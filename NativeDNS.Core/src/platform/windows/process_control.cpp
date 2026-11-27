#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <memory>
#include <vector>

namespace nd::platform {
namespace {
struct CloseHandleDeleter {
    void operator()(void* handle) const {
        CloseHandle(handle);
    }
};
using Handle = std::unique_ptr<void, CloseHandleDeleter>;

struct NtUnicodeString {
    USHORT length = 0;
    USHORT max_length = 0;
    PWSTR buffer = nullptr;
};

enum class ArgumentMatch { matched, not_matched, access_denied, unavailable };

ArgumentMatch check_required_argument(HANDLE process, const std::string& required_argument) {
    if (required_argument.empty())
        return ArgumentMatch::matched;
    using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static const auto query_fn = []() -> NtQueryInformationProcessFn {
        if (const auto ntdll = GetModuleHandleW(L"ntdll.dll"))
            return reinterpret_cast<NtQueryInformationProcessFn>(
                GetProcAddress(ntdll, "NtQueryInformationProcess"));
        return nullptr;
    }();
    if (!query_fn)
        return ArgumentMatch::unavailable;
    constexpr ULONG process_command_line_information = 60;
    constexpr LONG status_info_length_mismatch = static_cast<LONG>(0xC0000004L);
    constexpr LONG status_buffer_too_small = static_cast<LONG>(0xC0000023L);
    constexpr LONG status_access_denied = static_cast<LONG>(0xC0000022L);
    ULONG bytes = 4096;
    std::vector<BYTE> storage(bytes);
    ULONG needed = 0;
    LONG status = query_fn(
        process, process_command_line_information, storage.data(), bytes, &needed);
    if ((status == status_info_length_mismatch || status == status_buffer_too_small) &&
        needed > bytes && needed <= 256 * 1024) {
        storage.resize(needed);
        status = query_fn(
            process, process_command_line_information, storage.data(), needed, &needed);
    }
    if (status == status_access_denied)
        return ArgumentMatch::access_denied;
    if (status < 0)
        return ArgumentMatch::unavailable;
    const auto* text = reinterpret_cast<const NtUnicodeString*>(storage.data());
    if (!text->buffer || !text->length)
        return ArgumentMatch::not_matched;
    std::wstring cmdline(text->buffer, text->length / sizeof(wchar_t));
    int argc = 0;
    auto** argv = CommandLineToArgvW(cmdline.c_str(), &argc);
    if (!argv)
        return ArgumentMatch::unavailable;
    const std::wstring needle = widen(required_argument);
    bool found = false;
    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], needle.c_str()) == 0) {
            found = true;
            break;
        }
    }
    LocalFree(argv);
    return found ? ArgumentMatch::matched : ArgumentMatch::not_matched;
}

[[noreturn]] void fail(const char* operation) {
    const auto code = GetLastError();
    throw Error(code == ERROR_ACCESS_DENIED ? "PROCESS_PERMISSION" : "PROCESS_CONTROL",
                std::string(operation) + ": Win32=" + std::to_string(code));
}
uint64_t birth(HANDLE process) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user))
        fail("GetProcessTimes");
    return (uint64_t{created.dwHighDateTime} << 32) | created.dwLowDateTime;
}
bool matches(HANDLE process, const std::filesystem::path& executable) {
    std::wstring image(32768, L'\0');
    DWORD length = static_cast<DWORD>(image.size());
    if (!QueryFullProcessImageNameW(process, 0, image.data(), &length))
        fail("QueryFullProcessImageName");
    image.resize(length);
    const auto expected = std::filesystem::weakly_canonical(executable).wstring();
    return CompareStringOrdinal(image.c_str(), -1, expected.c_str(), -1, TRUE) == CSTR_EQUAL;
}
} // namespace

std::vector<ProcessIdentity> matching_processes(const std::filesystem::path& executable,
                                                const std::string& required_argument) {
    const HANDLE raw = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (raw == INVALID_HANDLE_VALUE)
        fail("CreateToolhelp32Snapshot");
    Handle snapshot(raw);
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::vector<ProcessIdentity> result;
    if (!Process32FirstW(snapshot.get(), &entry))
        fail("Process32First");
    do {
        if (entry.th32ProcessID == GetCurrentProcessId() ||
            _wcsicmp(entry.szExeFile, executable.filename().c_str()) != 0)
            continue;
        Handle process(OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, entry.th32ProcessID));
        if (!process) {
            if (GetLastError() == ERROR_INVALID_PARAMETER)
                continue; // Exited between snapshot and open.
            fail("OpenProcess(query)");
        }
        if (WaitForSingleObject(process.get(), 0) == WAIT_OBJECT_0)
            continue;
        if (!matches(process.get(), executable))
            continue;
        const auto arg_match = check_required_argument(process.get(), required_argument);
        if (arg_match == ArgumentMatch::not_matched)
            continue;
        result.push_back({entry.th32ProcessID, birth(process.get())});
    } while (Process32NextW(snapshot.get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES)
        fail("Process32Next");
    return result;
}

void force_stop_process(const std::filesystem::path& executable,
                        ProcessIdentity identity,
                        const std::string& required_argument) {
    if (!identity.pid || identity.pid == GetCurrentProcessId())
        throw Error("PROCESS_IDENTITY", "Refusing to terminate the current/invalid process");
    Handle process(OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE, FALSE, identity.pid));
    if (!process) {
        if (GetLastError() == ERROR_INVALID_PARAMETER)
            return;
        fail("OpenProcess(terminate)");
    }
    if (WaitForSingleObject(process.get(), 0) == WAIT_OBJECT_0)
        return;
    if (birth(process.get()) != identity.started || !matches(process.get(), executable))
        throw Error("PROCESS_IDENTITY",
                    "Executable or process birth token changed; refusing termination");
    const auto arg_match = check_required_argument(process.get(), required_argument);
    if (arg_match == ArgumentMatch::access_denied)
        throw Error("PROCESS_PERMISSION", "Cannot inspect target command line without elevation");
    if (arg_match == ArgumentMatch::not_matched)
        throw Error("PROCESS_IDENTITY",
                    "Target process command line does not match required role; refusing termination");
    // Verification and termination use the same kernel handle, even if the PID is reused.
    if (!TerminateProcess(process.get(), 12)) {
        const auto error = GetLastError();
        if (WaitForSingleObject(process.get(), 0) == WAIT_OBJECT_0)
            return;
        SetLastError(error);
        fail("TerminateProcess");
    }
    if (WaitForSingleObject(process.get(), 5000) != WAIT_OBJECT_0)
        throw Error("PROCESS_CONTROL", "Process termination did not complete within 5 seconds");
}
} // namespace nd::platform
