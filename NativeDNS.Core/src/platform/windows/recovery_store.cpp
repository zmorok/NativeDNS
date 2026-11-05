#include "recovery_store.hpp"
#include <nativedns/config.hpp>
#include <nativedns/platform.hpp>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <algorithm>
#include <utility>

namespace nd::platform::detail {
namespace {
constexpr size_t journal_limit = 2 * 1024 * 1024;
constexpr DWORD read_share = FILE_SHARE_READ | FILE_SHARE_DELETE;
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
[[noreturn]] void fail(const char* operation, const std::filesystem::path& path,
                       DWORD error = GetLastError()) {
    throw Error("DNS_PREPARATION_IO", std::string(operation) + ": " + path_to_utf8(path) +
                                    " Windows error=" + std::to_string(error));
}
struct Security {
    PSECURITY_DESCRIPTOR value = nullptr;
    explicit Security(const wchar_t* specification) {
        if (specification && !ConvertStringSecurityDescriptorToSecurityDescriptorW(
                specification, SDDL_REVISION_1, &value, nullptr))
            throw Error("DNS_PREPARATION_SECURITY", "Cannot construct recovery security descriptor");
    }
    ~Security() { if (value) LocalFree(value); }
    Security(const Security&) = delete;
    Security& operator=(const Security&) = delete;
};
void verify_security(HANDLE handle, const std::filesystem::path& path, PSECURITY_DESCRIPTOR expected) {
    if (!expected) return;
    PSECURITY_DESCRIPTOR actual = nullptr;
    PSID owner = nullptr; PACL acl = nullptr;
    const auto error = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                       &owner, nullptr, &acl, nullptr, &actual);
    struct Release { PVOID value; ~Release() { if (value) LocalFree(value); } } release{actual};
    PSID expected_owner = nullptr; BOOL defaulted = FALSE, present = FALSE;
    PACL expected_acl = nullptr;
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    if (error != ERROR_SUCCESS || !GetSecurityDescriptorOwner(expected, &expected_owner, &defaulted) ||
        !GetSecurityDescriptorDacl(expected, &present, &expected_acl, &defaulted) ||
        !GetSecurityDescriptorControl(actual, &control, &revision) || !(control & SE_DACL_PROTECTED) ||
        !owner || !EqualSid(owner, expected_owner) || !acl || acl->AclSize != expected_acl->AclSize ||
        !std::equal(reinterpret_cast<const char*>(acl), reinterpret_cast<const char*>(acl) + acl->AclSize,
                    reinterpret_cast<const char*>(expected_acl)))
        throw Error("DNS_PREPARATION_SECURITY", "Recovery data must be owned by Administrators and writable only by Administrators/SYSTEM: " + path_to_utf8(path));
}
bool file_exists(const std::filesystem::path& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
            throw Error("DNS_PREPARATION_SECURITY", "Recovery refuses a reparse point: " + path_to_utf8(path));
        return true;
    }
    const auto error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return false;
    fail("Cannot inspect file", path, error);
}
std::string read_handle(HANDLE handle, const std::filesystem::path& path, size_t limit) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) fail("Cannot inspect open file", path);
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) || info.nNumberOfLinks != 1)
        throw Error("DNS_PREPARATION_SECURITY", "Recovery requires a regular file with one link: " + path_to_utf8(path));
    const auto size = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    if (size > limit) throw Error("DNS_PREPARATION_LIMIT", "File exceeds recovery limit: " + path_to_utf8(path));
    LARGE_INTEGER start{};
    if (!SetFilePointerEx(handle, start, nullptr, FILE_BEGIN)) fail("Cannot seek file", path);
    std::string bytes(static_cast<size_t>(size), '\0');
    DWORD count = 0;
    if (size && (!ReadFile(handle, bytes.data(), static_cast<DWORD>(size), &count, nullptr) || count != size))
        fail("Cannot read file", path);
    return bytes;
}
std::string read_file(const std::filesystem::path& path, size_t limit, PSECURITY_DESCRIPTOR security = nullptr) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, read_share, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) fail("Cannot open file", path);
    verify_security(file.value, path, security);
    return read_handle(file.value, path, limit);
}
void remove_file(const std::filesystem::path& path, PSECURITY_DESCRIPTOR security = nullptr) {
    if (!file_exists(path)) return;
    if (security) (void)read_file(path, journal_limit, security);
    if (!DeleteFileW(path.c_str())) fail("Cannot remove recovery file", path);
}
void create_file(const std::filesystem::path& path, const std::string& contents, PSECURITY_DESCRIPTOR descriptor) {
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, descriptor ? &security : nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) fail("Cannot create recovery file", path);
    verify_security(file.value, path, descriptor);
    DWORD written = 0;
    if ((!contents.empty() && (!WriteFile(file.value, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) ||
                               written != contents.size())) || !FlushFileBuffers(file.value))
        fail("Cannot persist recovery file", path);
}
void atomic_save(const std::filesystem::path& path, const std::string& contents, PSECURITY_DESCRIPTOR security) {
    auto temp = path; temp += L".new";
    remove_file(temp, security); // Only our fixed staging name inside the private directory.
    create_file(temp, contents, security);
    if (file_exists(path) && security) (void)read_file(path, journal_limit, security);
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        fail("Cannot publish recovery journal", path);
}
void secure_directory(const std::filesystem::path& path) {
    Security descriptor(L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor.value, FALSE};
    if (!CreateDirectoryW(path.c_str(), &security) && GetLastError() != ERROR_ALREADY_EXISTS)
        fail("Cannot create protected recovery directory", path);
    // A directory pre-created by another user must never supply elevated recovery data.
    Handle directory(CreateFileW(path.c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (directory.value == INVALID_HANDLE_VALUE) fail("Cannot inspect recovery directory security", path);
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(directory.value, &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw Error("DNS_PREPARATION_SECURITY", "Invalid recovery directory: " + path_to_utf8(path));
    verify_security(directory.value, path, descriptor.value);
}
} // namespace
struct RecoveryFile::Impl {
    std::filesystem::path journal;
    Security security;
    Handle lock;
    Impl(const std::filesystem::path& directory, const std::string& name, RecoveryScope scope)
        : security(scope == RecoveryScope::machine ? L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" : nullptr) {
        if (scope == RecoveryScope::machine) secure_directory(directory);
        if (name.empty() || name.size() > 40 || !std::all_of(name.begin(), name.end(), [](char c) {
                return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
            })) throw Error("DNS_PREPARATION_JOURNAL", "Invalid recovery file name");
        journal = directory / (widen(name) + L".journal");
        const auto lock_path = directory / (widen(name) + L".lock");
        if (file_exists(lock_path)) (void)read_file(lock_path, 0, security.value);
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), security.value, FALSE};
        lock.value = CreateFileW(lock_path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                                 security.value ? &attributes : nullptr, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (lock.value == INVALID_HANDLE_VALUE) fail("Cannot acquire recovery lock", lock_path);
        verify_security(lock.value, lock_path, security.value);
        (void)read_handle(lock.value, lock_path, 0);
    }
};
RecoveryFile::RecoveryFile(const std::filesystem::path& directory, const std::string& name, RecoveryScope scope)
    : impl_(std::make_unique<Impl>(directory, name, scope)) {}
RecoveryFile::~RecoveryFile() = default;
std::optional<std::string> RecoveryFile::load() {
    if (!file_exists(impl_->journal)) return std::nullopt;
    return read_file(impl_->journal, journal_limit, impl_->security.value);
}
void RecoveryFile::save(const std::string& bytes) {
    if (bytes.size() > journal_limit) throw Error("DNS_PREPARATION_LIMIT", "Recovery journal exceeds 2 MiB");
    atomic_save(impl_->journal, bytes, impl_->security.value);
}
void RecoveryFile::clear() {
    remove_file(impl_->journal, impl_->security.value);
    auto stage = impl_->journal; stage += L".new";
    remove_file(stage, impl_->security.value);
}
void ensure_recovery_directory(const std::filesystem::path& directory) { secure_directory(directory); }
std::filesystem::path network_recovery_directory() {
    PWSTR data = nullptr;
    const auto status = SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &data);
    if (FAILED(status)) throw Error("DNS_PREPARATION_SECURITY", "Cannot locate machine recovery directory");
    const auto directory = std::filesystem::path(data) / L"NativeDNS.NetworkRecovery";
    CoTaskMemFree(data);
    ensure_recovery_directory(directory);
    return directory;
}
} // namespace nd::platform::detail
