#include <nativedns/network.hpp>
#include <algorithm>
#include <chrono>
#include <exception>
#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <charconv>

namespace nd {
NumericEndpoint parse_numeric_endpoint(const std::string& text) {
    NumericEndpoint result;
    const auto marker = text.find('%');
    result.address = text.substr(0, marker);
    std::array<uint8_t, 16> bytes{};
    if (!platform::parse_ip(result.address, bytes, result.ipv6))
        throw Error("ENDPOINT", "DNS endpoint requires a numeric IPv4/IPv6 address");
    if (marker != std::string::npos) {
        const auto value = text.substr(marker + 1);
        const auto parsed =
            std::from_chars(value.data(), value.data() + value.size(), result.scope6);
        if (!result.ipv6 || parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
            !result.scope6)
            throw Error("ENDPOINT", "IPv6 scope must be a positive numeric interface index");
    }
    return result;
}
const InterfaceInfo*
find_interface(const NetworkSnapshot& snapshot, const std::string& id, const std::string& match) {
    const auto canonical = [](std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
        });
        if (value.starts_with("guid:"))
            value.erase(0, 5);
        return value;
    };
    const auto needle = canonical(id);
    if (match != "id" && match != "guid" && match != "index" && match != "name" &&
        match != "suffix")
        throw Error("NOT_IMPLEMENTED", "Unsupported interface selector type: " + match);
    const InterfaceInfo* found = nullptr;
    for (const auto& info : snapshot.interfaces) {
        bool matches = false;
        if (match == "name")
            matches = canonical(info.name) == needle || canonical(info.description) == needle;
        else if (match == "suffix")
            matches = canonical(info.dns_suffix) == needle;
        else
            matches = canonical(info.id) == needle || std::to_string(info.index4) == needle ||
                      std::to_string(info.index6) == needle;
        if (matches) {
            if (found)
                throw Error("INTERFACE_AMBIGUOUS", "Interface selector matches multiple adapters");
            found = &info;
        }
    }
    return found;
}
std::string network_route_key(const NetworkRoute& route) {
    return route.interface_id + '|' + std::to_string(route.index4) + '|' +
           std::to_string(route.index6) + '|' + std::to_string(route.scope6);
}
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
