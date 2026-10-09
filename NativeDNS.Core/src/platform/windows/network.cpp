#include <nativedns/network.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <algorithm>

namespace nd::platform {
void bind_upstream_interface(std::intptr_t raw, const NetworkRoute& route) {
    if (route.interface_id.empty())
        return;
    const auto network = NetworkMonitor::shared().snapshot();
    const auto* info = find_interface(*network, route.interface_id);
    if (!network->error.empty() || !info || !info->up || info->index4 != route.index4 ||
        info->index6 != route.index6)
        throw Error("INTERFACE_DOWN", "Required upstream interface is unavailable");
    const SOCKET socket = static_cast<SOCKET>(raw);
    WSAPROTOCOL_INFOW protocol{};
    int size = sizeof(protocol);
    if (getsockopt(
            socket, SOL_SOCKET, SO_PROTOCOL_INFOW, reinterpret_cast<char*>(&protocol), &size) ==
        SOCKET_ERROR)
        throw Error("INTERFACE_BIND", "Cannot inspect upstream socket family");
    const bool ipv6 = protocol.iAddressFamily == AF_INET6;
    const auto index = ipv6 ? route.index6 : route.index4;
    if (!index)
        throw Error("INTERFACE_BIND", "Required interface does not support socket address family");
    const DWORD option = ipv6 ? index : htonl(index);
    if (setsockopt(socket,
                   ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
                   ipv6 ? IPV6_UNICAST_IF : IP_UNICAST_IF,
                   reinterpret_cast<const char*>(&option),
                   sizeof(option)) == SOCKET_ERROR)
        throw Error("INTERFACE_BIND",
                    "Cannot bind upstream interface: " + std::to_string(WSAGetLastError()));
}
namespace {
std::string numeric_address(const sockaddr* address, uint32_t interface6) {
    if (!address)
        return {};
    if (address->sa_family == AF_INET)
        return format_ip(&reinterpret_cast<const sockaddr_in*>(address)->sin_addr, false);
    if (address->sa_family != AF_INET6)
        return {};
    const auto& v6 = *reinterpret_cast<const sockaddr_in6*>(address);
    auto text = format_ip(&v6.sin6_addr, true);
    auto scope = v6.sin6_scope_id;
    if (!scope && IN6_IS_ADDR_LINKLOCAL(&v6.sin6_addr))
        scope = interface6;
    if (scope)
        text += '%' + std::to_string(scope);
    return text;
}
void append(std::vector<std::string>& values, std::string value) {
    if (!value.empty() && std::find(values.begin(), values.end(), value) == values.end())
        values.push_back(std::move(value));
}
} // namespace
std::vector<InterfaceInfo> enumerate_interfaces() {
    ULONG size = 16384;
    std::vector<unsigned char> storage(size);
    IP_ADAPTER_ADDRESSES* adapters = nullptr;
    ULONG result = ERROR_BUFFER_OVERFLOW;
    for (unsigned attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
        if (size > 1024 * 1024)
            throw Error("INTERFACE_ENUMERATION", "Adapter snapshot exceeds limit");
        storage.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
        result =
            GetAdaptersAddresses(AF_UNSPEC,
                                 GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                     GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_GATEWAYS,
                                 nullptr,
                                 adapters,
                                 &size);
    }
    if (result == ERROR_NO_DATA)
        return {};
    if (result != NO_ERROR)
        throw Error("INTERFACE_ENUMERATION",
                    "Cannot enumerate adapters: " + std::to_string(result));
    std::vector<InterfaceInfo> interfaces;
    const auto captive = captive_portal_adapters();
    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        InterfaceInfo info;
        info.id = adapter->AdapterName ? adapter->AdapterName : "";
        info.captive_portal = std::any_of(captive.begin(), captive.end(), [&](const auto& id) {
            return _stricmp(id.c_str(), info.id.c_str()) == 0;
        });
        info.name = adapter->FriendlyName ? narrow(adapter->FriendlyName) : "";
        info.description = adapter->Description ? narrow(adapter->Description) : "";
        info.dns_suffix = adapter->DnsSuffix ? narrow(adapter->DnsSuffix) : "";
        info.luid = adapter->Luid.Value;
        info.index4 = adapter->IfIndex;
        info.index6 = adapter->Ipv6IfIndex;
        info.metric4 = adapter->Ipv4Metric;
        info.metric6 = adapter->Ipv6Metric;
        info.mtu = adapter->Mtu;
        info.up = adapter->OperStatus == IfOperStatusUp;
        info.loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
        for (auto* item = adapter->FirstUnicastAddress; item; item = item->Next)
            append(info.addresses, numeric_address(item->Address.lpSockaddr, info.index6));
        for (auto* item = adapter->FirstDnsServerAddress; item; item = item->Next)
            append(info.dns_servers, numeric_address(item->Address.lpSockaddr, info.index6));
        for (auto* item = adapter->FirstGatewayAddress; item; item = item->Next)
            append(info.gateways, numeric_address(item->Address.lpSockaddr, info.index6));
        std::sort(info.addresses.begin(), info.addresses.end());
        interfaces.push_back(std::move(info));
    }
    return interfaces;
}
} // namespace nd::platform
