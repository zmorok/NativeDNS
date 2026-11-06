#include <nativedns/network.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <windows.h>
#include <tlhelp32.h>
#include <cwctype>
#include <algorithm>
#include <fwpmu.h>
#include <objbase.h>
#include <map>
#include <memory>

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

std::string component(const std::wstring& text) {
    const auto name = normalized(text);
    for (const auto& [pattern, label] :
         std::initializer_list<std::pair<const wchar_t*, const char*>>{
             {L"yogadns", "YogaDNS"},
             {L"adguard", "AdGuard"},
             {L"nextdns", "NextDNS"},
             {L"cloudflare", "Cloudflare WARP"},
             {L"warp-svc", "Cloudflare WARP"},
             {L"technitium", "Technitium DNS"},
             {L"dnscrypt", "DNSCrypt proxy"},
             {L"controld", "Control D"}})
        if (name.find(pattern) != std::wstring::npos)
            return label;
    return {};
}
std::string safe_name(const wchar_t* text) {
    if (!text)
        return {};
    std::wstring value(text, wcsnlen_s(text, 512));
    for (auto& c : value)
        if (c < 32)
            c = L' ';
    return narrow(value);
}
std::string guid_text(const GUID& guid) {
    wchar_t text[40]{};
    StringFromGUID2(guid, text, 40);
    return narrow(text);
}
void inspect_wfp(std::vector<InterceptionConflict>& result) {
    struct Engine {
        HANDLE value = nullptr;
        ~Engine() {
            if (value)
                FwpmEngineClose0(value);
        }
    } engine;
    const auto opened =
        FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine.value);
    if (opened != ERROR_SUCCESS) {
        result.push_back({"WFP_INSPECTION_UNAVAILABLE",
                          "Read-only WFP enumeration failed: " + std::to_string(opened),
                          false});
        return;
    }
    std::map<std::string, std::string> providers;
    // Bounded enumeration. Registered providers/callouts alone do not prove active interference.
    const auto enumerate = [&]<class T>(auto create, auto next, auto destroy, auto inspect) {
        HANDLE cursor = nullptr;
        DWORD error = create(engine.value, nullptr, &cursor);
        if (error != ERROR_SUCCESS) {
            result.push_back({"WFP_INSPECTION_PARTIAL",
                              "Cannot create WFP enumeration: " + std::to_string(error),
                              false});
            return;
        }
        const auto close_cursor = [&](void* value) { destroy(engine.value, value); };
        std::unique_ptr<void, decltype(close_cursor)> cursor_owner(cursor, close_cursor);
        bool finished = false;
        for (unsigned page = 0; page < 64; ++page) {
            T** entries = nullptr;
            UINT32 count = 0;
            error = next(engine.value, cursor, 64, &entries, &count);
            const auto free_entries = [](T** value) {
                if (value)
                    FwpmFreeMemory0(reinterpret_cast<void**>(&value));
            };
            std::unique_ptr<T*, decltype(free_entries)> entry_owner(entries, free_entries);
            if (error != ERROR_SUCCESS) {
                result.push_back({"WFP_INSPECTION_PARTIAL",
                                  "WFP enumeration error: " + std::to_string(error),
                                  false});
                finished = true;
                break;
            }
            for (UINT32 i = 0; i < count; ++i)
                inspect(*entries[i]);
            if (count < 64) {
                finished = true;
                break;
            }
        }
        if (!finished)
            result.push_back(
                {"WFP_INSPECTION_LIMIT", "WFP enumeration capped at 4096 objects per kind", false});
    };
    enumerate.template operator()<FWPM_PROVIDER0>(
        FwpmProviderCreateEnumHandle0,
        FwpmProviderEnum0,
        FwpmProviderDestroyEnumHandle0,
        [&](const FWPM_PROVIDER0& item) {
            const auto label = component(item.displayData.name ? item.displayData.name : L"");
            if (label.empty())
                return;
            providers[guid_text(item.providerKey)] = label;
            result.push_back({"WFP_PROVIDER_REGISTERED",
                              label + " provider=" + guid_text(item.providerKey) +
                                  " name=" + safe_name(item.displayData.name) +
                                  "; registration alone does not establish an active interceptor",
                              false});
        });
    enumerate.template operator()<FWPM_CALLOUT0>(
        FwpmCalloutCreateEnumHandle0,
        FwpmCalloutEnum0,
        FwpmCalloutDestroyEnumHandle0,
        [&](const FWPM_CALLOUT0& item) {
            auto label = component(item.displayData.name ? item.displayData.name : L"");
            if (label.empty() && item.providerKey)
                label = providers[guid_text(*item.providerKey)];
            if (label.empty())
                return;
            result.push_back({"WFP_CALLOUT_REGISTERED",
                              label + " callout=" + guid_text(item.calloutKey) +
                                  " layer=" + guid_text(item.applicableLayer) +
                                  " name=" + safe_name(item.displayData.name),
                              false});
        });
    enumerate.template operator()<FWPM_FILTER0>(
        FwpmFilterCreateEnumHandle0,
        FwpmFilterEnum0,
        FwpmFilterDestroyEnumHandle0,
        [&](const FWPM_FILTER0& item) {
            if (item.flags & FWPM_FILTER_FLAG_DISABLED)
                return;
            auto label = component(item.displayData.name ? item.displayData.name : L"");
            if (label.empty() && item.providerKey)
                label = providers[guid_text(*item.providerKey)];
            if (label.empty())
                return;
            result.push_back({"WFP_POTENTIAL_INTERCEPTOR",
                              label + " filter_id=" + std::to_string(item.filterId) +
                                  " layer=" + guid_text(item.layerKey) +
                                  " action=" + std::to_string(item.action.type) +
                                  " name=" + safe_name(item.displayData.name) +
                                  "; potential interference, not a confirmed conflict",
                              true});
        });
    result.push_back({"WFP_INSPECTION_SCOPE",
                      "Read-only WFP snapshot; matching known component names only; bounded, not a "
                      "complete WFP ordering or DNS traffic analysis",
                      false});
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
                const auto label = component(name);
                if (!label.empty())
                    result.push_back({"POTENTIAL_DNS_INTERCEPTOR",
                                      "Potential competing DNS interceptor detected: " + label +
                                          " process=" + narrow(name) +
                                          " pid=" + std::to_string(entry.th32ProcessID) +
                                          "; process presence does not confirm interference",
                                      true});
                if ((name == L"nativednscorehost.exe" || name == L"nativedns.corehost.exe") &&
                    entry.th32ProcessID != GetCurrentProcessId())
                    result.push_back({"INTERCEPT_CONFLICT",
                                      "Another NativeDNSCoreHost process is present",
                                      true});
            } while (Process32NextW(processes, &entry));
        CloseHandle(processes);
    }
    ServiceHandle manager{
        OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE)};
    if (!manager.value) {
        result.push_back(
            {"CONFLICT_DETECTION_UNAVAILABLE", "Cannot inspect driver services", false});
        inspect_wfp(result);
        return result;
    }
    DWORD required = 0, count = 0, resume = 0;
    (void)EnumServicesStatusExW(manager.value,
                                SC_ENUM_PROCESS_INFO,
                                SERVICE_WIN32 | SERVICE_DRIVER,
                                SERVICE_ACTIVE,
                                nullptr,
                                0,
                                &required,
                                &count,
                                &resume,
                                nullptr);
    if (required && required <= 4 * 1024 * 1024) {
        std::vector<BYTE> data(required);
        resume = 0;
        if (EnumServicesStatusExW(manager.value,
                                  SC_ENUM_PROCESS_INFO,
                                  SERVICE_WIN32 | SERVICE_DRIVER,
                                  SERVICE_ACTIVE,
                                  data.data(),
                                  required,
                                  &required,
                                  &count,
                                  &resume,
                                  nullptr)) {
            const auto entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(data.data());
            for (DWORD i = 0; i < count; ++i) {
                const auto& entry = entries[i];
                const auto label =
                    component(std::wstring(entry.lpServiceName) + L" " + entry.lpDisplayName);
                if (!label.empty() && entry.ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING)
                    result.push_back(
                        {"POTENTIAL_DNS_INTERCEPTOR",
                         "Potential competing DNS interceptor detected: " + label +
                             " running_service=" + safe_name(entry.lpServiceName) +
                             " type=" + std::to_string(entry.ServiceStatusProcess.dwServiceType) +
                             "; active component, interference is not confirmed",
                         true});
            }
        } else
            result.push_back(
                {"CONFLICT_DETECTION_PARTIAL", "Cannot enumerate active services", false});
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
        DWORD config_bytes = 0;
        (void)QueryServiceConfigW(service.value, nullptr, 0, &config_bytes);
        std::vector<BYTE> storage(config_bytes);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
        const bool queried =
            config_bytes && QueryServiceConfigW(service.value, config, config_bytes, &config_bytes);
        const auto expected =
            normalized((windivert_directory() / L"WinDivert64.sys").wstring());
        if (!queried || !config->lpBinaryPathName ||
            normalized(config->lpBinaryPathName) != expected)
            result.push_back(
                {"INTERCEPT_DRIVER_PRESENT",
                 "Foreign or unverified WinDivert driver service is loaded: " + narrow(name),
                 false});
    }
    inspect_wfp(result);
    if (result.size() > 256) {
        result.resize(256);
        result.push_back({"CONFLICT_DETECTION_LIMIT", "Findings capped at 256 entries", false});
    }
    return result;
}
} // namespace nd::platform
