#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <nativedns/model.hpp>

namespace nd {
struct InterfaceInfo {
    std::string id, name, description, dns_suffix;
    uint64_t luid = 0;
    uint32_t index4 = 0, index6 = 0, metric4 = 0, metric6 = 0, mtu = 0;
    bool up = false;
    std::vector<std::string> addresses, dns_servers, gateways;
    bool operator==(const InterfaceInfo&) const = default;
};
struct NetworkSnapshot {
    uint64_t generation = 0;
    std::vector<InterfaceInfo> interfaces;
    std::string error;
};
using NetworkSnapshotPtr = std::shared_ptr<const NetworkSnapshot>;
struct NumericEndpoint {
    std::string address;
    uint32_t scope6 = 0;
    bool ipv6 = false;
};
NumericEndpoint parse_numeric_endpoint(const std::string& text);
const InterfaceInfo* find_interface(const NetworkSnapshot& snapshot,
                                    const std::string& id,
                                    const std::string& match = "id");
std::string network_route_key(const NetworkRoute& route);
Server with_network_context(Server server);
class NetworkMonitor final {
public:
    using Source = std::function<std::vector<InterfaceInfo>()>;
    explicit NetworkMonitor(Source source = {}, bool watch = true);
    ~NetworkMonitor();
    NetworkSnapshotPtr snapshot() const;
    void refresh();
    static NetworkMonitor& shared();

private:
    Source source_;
    std::mutex refresh_mutex_, wait_mutex_;
    std::condition_variable_any changed_;
    std::atomic<NetworkSnapshotPtr> snapshot_;
    std::jthread watcher_;
};
namespace platform {
std::vector<InterfaceInfo> enumerate_interfaces();
void bind_upstream_interface(std::intptr_t socket, const NetworkRoute& route);
} // namespace platform
} // namespace nd
