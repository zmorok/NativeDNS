#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <windows.h>
#include <tlhelp32.h>
#include <memory>

namespace nd::platform {
namespace {
struct CloseHandleDeleter {
    void operator()(void* handle) const {
        CloseHandle(handle);
    }
};
using Handle = std::unique_ptr<void, CloseHandleDeleter>;

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

std::vector<ProcessIdentity> matching_processes(const std::filesystem::path& executable) {
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
        if (matches(process.get(), executable))
            result.push_back({entry.th32ProcessID, birth(process.get())});
    } while (Process32NextW(snapshot.get(), &entry));
    if (GetLastError() != ERROR_NO_MORE_FILES)
        fail("Process32Next");
    return result;
}

void force_stop_process(const std::filesystem::path& executable, ProcessIdentity identity) {
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
