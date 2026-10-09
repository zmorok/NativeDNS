#include <nativedns/network.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <windows.h>
#include <tlhelp32.h>
#include <cwctype>
#include <algorithm>

namespace nd::platform {
namespace {
struct ServiceHandle {
    SC_HANDLE value;
    ~ServiceHandle() {
        if (value)
            CloseServiceHandle(value);
    }
};
std::wstring normalized(std::wstring value) {
    if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
        value = value.substr(1, value.size() - 2);
    if (value.starts_with(L"\\??\\"))
        value.erase(0, 4);
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::towlower(c));
    });
    return value;
}
} // namespace
std::vector<InterceptionConflict> interception_conflicts() {
    std::vector<InterceptionConflict> result;
    const HANDLE processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processes != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(processes, &entry))
            do {
                const auto name = normalized(entry.szExeFile);
                if (name == L"nativednscorehost.exe" &&
                    entry.th32ProcessID != GetCurrentProcessId())
                    result.push_back({"INTERCEPT_CONFLICT",
                                      "Another NativeDNSCoreHost process is present",
                                      true});
            } while (Process32NextW(processes, &entry));
        CloseHandle(processes);
    }
    ServiceHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!manager.value) {
        result.push_back(
            {"CONFLICT_DETECTION_UNAVAILABLE", "Cannot inspect driver services", false});
        return result;
    }
    for (const auto* name : {L"WinDivert", L"WinDivert1.4", L"WinDivert2.2"}) {
        ServiceHandle service{
            OpenServiceW(manager.value, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)};
        if (!service.value)
            continue;
        SERVICE_STATUS_PROCESS status{};
        DWORD size = 0;
        if (!QueryServiceStatusEx(service.value,
                                  SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<BYTE*>(&status),
                                  sizeof(status),
                                  &size) ||
            status.dwCurrentState != SERVICE_RUNNING)
            continue;
        DWORD required = 0;
        (void)QueryServiceConfigW(service.value, nullptr, 0, &required);
        std::vector<BYTE> storage(required);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
        const bool queried =
            required && QueryServiceConfigW(service.value, config, required, &required);
        const auto expected =
            normalized((executable_path().parent_path() / L"WinDivert64.sys").wstring());
        if (!queried || !config->lpBinaryPathName ||
            normalized(config->lpBinaryPathName) != expected)
            result.push_back(
                {"INTERCEPT_DRIVER_PRESENT",
                 "Foreign or unverified WinDivert driver service is loaded: " + narrow(name),
                 false});
    }
    return result;
}
} // namespace nd::platform
