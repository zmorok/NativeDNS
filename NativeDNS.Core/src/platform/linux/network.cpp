#include <nativedns/network.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <map>
#include <algorithm>

namespace nd::platform {
void bind_upstream_interface(std::intptr_t raw, const NetworkRoute& route) {
    if (route.interface_id.empty())
        return;
    const auto network = NetworkMonitor::shared().snapshot();
    const auto* info = find_interface(*network, route.interface_id);
    if (!network->error.empty() || !info || !info->up || info->index4 != route.index4)
        throw Error("INTERFACE_DOWN", "Required upstream interface is unavailable");
    if (setsockopt(static_cast<int>(raw),
                   SOL_SOCKET,
                   SO_BINDTODEVICE,
                   route.interface_name.c_str(),
                   static_cast<socklen_t>(route.interface_name.size() + 1)) != 0)
        throw Error("INTERFACE_BIND", "Cannot bind upstream socket to required device");
}
std::vector<InterfaceInfo> enumerate_interfaces() {
    ifaddrs* addresses = nullptr;
    if (getifaddrs(&addresses) != 0)
        throw Error("INTERFACE_ENUMERATION", "Cannot enumerate POSIX interfaces");
    const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> owner(addresses, freeifaddrs);
    std::map<std::string, InterfaceInfo> interfaces;
    for (auto* item = addresses; item; item = item->ifa_next) {
        auto& info = interfaces[item->ifa_name];
        info.id = info.name = item->ifa_name;
        info.index4 = info.index6 = if_nametoindex(item->ifa_name);
        info.up = (item->ifa_flags & IFF_UP) && (item->ifa_flags & IFF_RUNNING);
        if (!item->ifa_addr)
            continue;
        std::string address;
        if (item->ifa_addr->sa_family == AF_INET)
            address = format_ip(&reinterpret_cast<sockaddr_in*>(item->ifa_addr)->sin_addr, false);
        else if (item->ifa_addr->sa_family == AF_INET6) {
            const auto* v6 = reinterpret_cast<sockaddr_in6*>(item->ifa_addr);
            address = format_ip(&v6->sin6_addr, true);
            if (v6->sin6_scope_id)
                address += '%' + std::to_string(v6->sin6_scope_id);
        }
        if (!address.empty())
            info.addresses.push_back(std::move(address));
    }
    std::vector<InterfaceInfo> result;
    for (auto& [id, info] : interfaces) {
        (void)id;
        std::sort(info.addresses.begin(), info.addresses.end());
        result.push_back(std::move(info));
    }
    return result;
}
} // namespace nd::platform
