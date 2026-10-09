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
}
} // namespace nd
