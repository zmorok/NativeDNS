#include <nativedns/network.hpp>
#include <algorithm>
#include <chrono>
#include <exception>

namespace nd {
NetworkMonitor::NetworkMonitor(Source source, bool watch)
    : source_(source ? std::move(source) : platform::enumerate_interfaces) {
    snapshot_.store(std::make_shared<NetworkSnapshot>());
    refresh();
    if (watch)
        watcher_ = std::jthread([this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                std::unique_lock lock(wait_mutex_);
                changed_.wait_for(lock, stop, std::chrono::seconds(1), [] { return false; });
                lock.unlock();
                if (!stop.stop_requested())
                    refresh();
            }
        });
}
NetworkMonitor::~NetworkMonitor() {
    watcher_.request_stop();
    changed_.notify_all();
    if (watcher_.joinable())
        watcher_.join();
}
NetworkSnapshotPtr NetworkMonitor::snapshot() const {
    return snapshot_.load();
}
void NetworkMonitor::refresh() {
    std::lock_guard lock(refresh_mutex_);
    const auto previous = snapshot();
    auto next = std::make_shared<NetworkSnapshot>();
    try {
        next->interfaces = source_();
        std::sort(next->interfaces.begin(),
                  next->interfaces.end(),
                  [](const auto& a, const auto& b) { return a.id < b.id; });
    } catch (const std::exception& error) {
        next->interfaces = previous->interfaces;
        next->error = error.what();
    }
    if (next->interfaces == previous->interfaces && next->error == previous->error)
        return;
    next->generation = previous->generation + 1;
    snapshot_.store(std::move(next));
}
NetworkMonitor& NetworkMonitor::shared() {
    static NetworkMonitor monitor;
    return monitor;
}
} // namespace nd
