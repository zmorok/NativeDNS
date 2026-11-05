#include <nativedns/network.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <nativedns/network_preflight.hpp>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netlistmgr.h>
#include <ocidl.h>
#include <wrl/client.h>

namespace nd::platform {
namespace {
struct RegistryKey {
    HKEY value = nullptr;
    ~RegistryKey() { if (value) RegCloseKey(value); }
};
void inspect_policy(std::vector<PreflightFinding>& result,
                    const wchar_t* path,
                    const wchar_t* name) {
    DWORD value = 0, bytes = sizeof(value);
    const auto status = RegGetValueW(HKEY_LOCAL_MACHINE, path, name, RRF_RT_REG_DWORD,
                                     nullptr, &value, &bytes);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
        return;
    if (status != ERROR_SUCCESS) {
        result.push_back({Level::errors_only, "DNS_PREFLIGHT_POLICY",
                          "Cannot inspect machine DNS policy: " + narrow(name) +
                              " error=" + std::to_string(status)});
        return;
    }
    result.push_back({Level::normal, "DNS_PREFLIGHT_POLICY",
                      "machine_key=\"" + narrow(path) + "\" value=" + narrow(name) +
                          " data=" + std::to_string(value) +
                          "; a configured policy may affect resolver encryption"});
}
} // namespace
std::filesystem::path system_hosts_path() {
    wchar_t directory[32768]{};
    DWORD bytes = sizeof(directory);
    const auto status = RegGetValueW(HKEY_LOCAL_MACHINE,
                                      L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                                      L"DataBasePath", RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                                      nullptr, directory, &bytes);
    if (status == ERROR_SUCCESS && directory[0])
        return std::filesystem::path(directory) / L"hosts";
    if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND)
        throw Error("DNS_PREFLIGHT_HOSTS", "Cannot read hosts directory: " + std::to_string(status));
    const auto count = GetSystemDirectoryW(directory, static_cast<UINT>(std::size(directory)));
    if (!count || count >= std::size(directory))
        throw Error("DNS_PREFLIGHT_HOSTS", "Cannot locate system hosts directory");
    return std::filesystem::path(directory) / L"drivers" / L"etc" / L"hosts";
}
std::vector<PreflightFinding> dns_environment_findings(const NetworkSnapshot& network) {
    std::vector<PreflightFinding> result;
    // Resolve at runtime so older Windows 10 builds can still launch NativeDNS.
    const auto module = LoadLibraryExW(L"iphlpapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    struct Release { HMODULE value; ~Release() { if (value) FreeLibrary(value); } } release{module};
    const auto get = module ? reinterpret_cast<decltype(&GetInterfaceDnsSettings)>(
                                  GetProcAddress(module, "GetInterfaceDnsSettings")) : nullptr;
    const auto free = module ? reinterpret_cast<decltype(&FreeInterfaceDnsSettings)>(
                                   GetProcAddress(module, "FreeInterfaceDnsSettings")) : nullptr;
    if (!get || !free)
        result.push_back({Level::normal, "DNS_PREFLIGHT_OS_UNAVAILABLE",
                          "This Windows build does not expose interface DNS encryption settings"});
    if (get && free) {
        for (const auto& info : network.interfaces) {
            if (!info.up || info.loopback || info.addresses.empty())
                continue;
            GUID id{};
            if (FAILED(CLSIDFromString(widen(info.id).c_str(), &id)))
                continue;
            DNS_INTERFACE_SETTINGS3 settings{};
            settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
            auto* base = reinterpret_cast<DNS_INTERFACE_SETTINGS*>(&settings);
            const auto status = get(id, base);
            if (status != NO_ERROR) {
                result.push_back({Level::normal, "DNS_PREFLIGHT_OS_UNAVAILABLE",
                                  "interface=\"" + info.name + "\" error=" + std::to_string(status) +
                                      "; encryption settings could not be inspected"});
                continue;
            }
            struct FreeSettings {
                decltype(&FreeInterfaceDnsSettings) release;
                DNS_INTERFACE_SETTINGS* value;
                ~FreeSettings() { release(value); }
            } cleanup{free, base};
            const auto inspect = [&](ULONG count, const DNS_SERVER_PROPERTY* properties,
                                     const char* source) {
                for (ULONG i = 0; properties && i < count && i < 4096; ++i) {
                    const auto& property = properties[i];
                    if (property.Type != DnsServerDohProperty || !property.Property.DohSettings)
                        continue;
                    const auto& doh = *property.Property.DohSettings;
                    if (!(doh.Flags & (DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO |
                                      DNS_DOH_SERVER_SETTINGS_ENABLE |
                                      DNS_DOH_SERVER_SETTINGS_ENABLE_DDR)))
                        continue;
                    result.push_back({Level::errors_only, "DNS_OS_ENCRYPTED",
                                      "interface=\"" + info.name + "\" source=" + source +
                                          " server_index=" + std::to_string(property.ServerIndex) +
                                          " flags=" + std::to_string(doh.Flags) +
                                          "; Windows DNS encryption can bypass port 53 interception. "
                                          "Use unencrypted system DNS while NativeDNS routes queries; "
                                          "NativeDNS upstream DoH/DoT remains configurable."});
                }
            };
            inspect(settings.cServerProperties, settings.ServerProperties, "adapter");
            inspect(settings.cProfileServerProperties, settings.ProfileServerProperties, "profile");
            result.push_back({Level::normal, "DNS_PREFLIGHT_OS",
                              "interface=\"" + info.name + "\" flags=" + std::to_string(settings.Flags) +
                                  " server_properties=" + std::to_string(settings.cServerProperties) +
                                  " profile_properties=" + std::to_string(settings.cProfileServerProperties)});
        }
    }
    inspect_policy(result, L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters", L"EnableAutoDoh");
    inspect_policy(result, L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"DoHPolicy");
    for (const auto* path : {
             L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig",
             L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig"}) {
        RegistryKey key;
        const auto status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key.value);
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
            continue;
        DWORD count = 0;
        const auto query = status == ERROR_SUCCESS
                               ? RegQueryInfoKeyW(key.value, nullptr, nullptr, nullptr, &count,
                                                  nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)
                               : status;
        if (query != ERROR_SUCCESS)
            result.push_back({Level::errors_only, "DNS_PREFLIGHT_NRPT",
                              "Cannot inspect NRPT rules: error=" + std::to_string(query)});
        else if (count)
            result.push_back({Level::normal, "DNS_PREFLIGHT_NRPT",
                              "key=\"" + narrow(path) + "\" rules=" + std::to_string(count) +
                                  "; system name-resolution policies can select another resolver"});
    }
    return result;
}
void flush_dns_cache() {
    const auto module = LoadLibraryExW(L"dnsapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module)
        throw Error("DNS_CACHE_FLUSH", "Cannot load Windows DNS cache API");
    const auto flush =
        reinterpret_cast<BOOL(WINAPI*)()>(GetProcAddress(module, "DnsFlushResolverCache"));
    const bool success = flush && flush();
    const auto error = GetLastError();
    FreeLibrary(module);
    if (!success)
        throw Error("DNS_CACHE_FLUSH", "Windows DNS cache flush failed: " + std::to_string(error));
}
std::vector<std::string> captive_portal_adapters() {
    using Microsoft::WRL::ComPtr;
    const auto initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    struct Apartment {
        bool active;
        ~Apartment() {
            if (active)
                CoUninitialize();
        }
    } apartment{SUCCEEDED(initialized)};
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE)
        return {};
    ComPtr<INetworkListManager> manager;
    if (FAILED(CoCreateInstance(
            CLSID_NetworkListManager, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&manager))))
        return {};
    ComPtr<IEnumNetworks> networks;
    if (FAILED(manager->GetNetworks(NLM_ENUM_NETWORK_CONNECTED, &networks)))
        return {};
    std::vector<std::string> result;
    for (unsigned count = 0; count < 4096; ++count) {
        ComPtr<INetwork> network;
        if (networks->Next(1, &network, nullptr) != S_OK)
            break;
        ComPtr<IPropertyBag> properties;
        if (FAILED(network.As(&properties)))
            continue;
        bool captive = false;
        for (const auto* key : {L"NA_InternetConnectivityV4", L"NA_InternetConnectivityV6"}) {
            VARIANT value{};
            if (SUCCEEDED(properties->Read(key, &value, nullptr))) {
                const auto flags = value.vt == VT_UI4  ? value.ulVal
                                   : value.vt == VT_I4 ? static_cast<ULONG>(value.lVal)
                                                       : 0;
                captive = captive || (flags & NLM_INTERNET_CONNECTIVITY_WEBHIJACK) != 0;
            }
            VariantClear(&value);
        }
        if (!captive)
            continue;
        ComPtr<IEnumNetworkConnections> connections;
        if (FAILED(network->GetNetworkConnections(&connections)))
            continue;
        for (unsigned connection_count = 0; connection_count < 4096; ++connection_count) {
            ComPtr<INetworkConnection> connection;
            if (connections->Next(1, &connection, nullptr) != S_OK)
                break;
            GUID adapter{};
            wchar_t text[40]{};
            if (SUCCEEDED(connection->GetAdapterId(&adapter)) && StringFromGUID2(adapter, text, 40))
                result.push_back(narrow(text));
        }
    }
    return result;
}
} // namespace nd::platform
