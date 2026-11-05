#pragma once
#include <nativedns/network_preparation.hpp>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

namespace nd::platform::detail {
class InterfaceDnsApi {
public:
    virtual ~InterfaceDnsApi() = default;
    virtual DWORD get(GUID id, DNS_INTERFACE_SETTINGS* settings) = 0;
    virtual void free(DNS_INTERFACE_SETTINGS* settings) = 0;
    virtual DWORD set(GUID id, const DNS_INTERFACE_SETTINGS* settings) = 0;
};
std::shared_ptr<InterfaceDnsApi> make_system_dns_api();
using LoadNetworkJournal = std::function<std::optional<std::string>()>;
using SaveNetworkJournal = std::function<void(const std::optional<std::string>&)>;
std::unique_ptr<NetworkPreparationBackend> make_windows_network_backend(
    std::shared_ptr<InterfaceDnsApi> api, LoadNetworkJournal load, SaveNetworkJournal save);
} // namespace nd::platform::detail
