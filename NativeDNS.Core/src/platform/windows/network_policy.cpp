#include <nativedns/network.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <windows.h>
#include <netlistmgr.h>
#include <ocidl.h>
#include <wrl/client.h>

namespace nd::platform {
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
