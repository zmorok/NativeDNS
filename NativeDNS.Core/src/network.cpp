#include <nativedns/network.hpp>
#include <algorithm>
#include <chrono>
#include <exception>
#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <charconv>
#include <tuple>

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
           std::to_string(route.index6) + '|' + std::to_string(route.scope6) + '|' +
           std::to_string(route.generation);
}
Server with_network_context(Server server) {
    if (!server.route.generation)
        server.route.generation = NetworkMonitor::shared().snapshot()->generation;
    return server;
}
std::vector<std::string>
select_bootstrap_dns_servers(const std::vector<InterfaceInfo>& interfaces) {
    struct Candidate {
        std::string address, interface_id;
        bool no_gateway;
        uint32_t metric;
        size_t order;
    };
    std::vector<Candidate> candidates;
    for (const auto& info : interfaces) {
        if (!info.up || info.loopback)
            continue;
        for (size_t order = 0; order < info.dns_servers.size(); ++order) {
            const auto& address = info.dns_servers[order];
            try {
                const auto endpoint = parse_numeric_endpoint(address);
                std::array<uint8_t, 16> bytes{};
                bool ipv6 = false;
                if (!platform::parse_ip(endpoint.address, bytes, ipv6))
                    continue;
                if (!ipv6) {
                    if (!bytes[12] || bytes[12] == 127 || bytes[12] >= 224)
                        continue;
                } else {
                    const bool zero_prefix = std::all_of(
                        bytes.begin(), bytes.begin() + 15, [](auto b) { return b == 0; });
                    if ((zero_prefix && bytes[15] <= 1) || bytes[0] == 0xff)
                        continue;
                    // Windows advertises these obsolete placeholder resolvers on adapters
                    // without configured IPv6 DNS, including loopback and virtual adapters.
                    const bool placeholder =
                        bytes[0] == 0xfe && bytes[1] == 0xc0 &&
                        std::all_of(
                            bytes.begin() + 2, bytes.begin() + 6, [](auto b) { return b == 0; }) &&
                        bytes[6] == 0xff && bytes[7] == 0xff &&
                        std::all_of(
                            bytes.begin() + 8, bytes.begin() + 15, [](auto b) { return b == 0; }) &&
                        bytes[15] >= 1 && bytes[15] <= 3;
                    if (placeholder ||
                        (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 && !endpoint.scope6))
                        continue;
                }
                candidates.push_back({address,
                                      info.id,
                                      info.gateways.empty(),
                                      ipv6 ? info.metric6 : info.metric4,
                                      order});
            } catch (const Error&) {
                // OS adapter data is not a user-specified endpoint: ignore invalid entries.
            }
        }
    }
    std::stable_sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
        return std::tie(a.no_gateway, a.metric, a.interface_id, a.order) <
               std::tie(b.no_gateway, b.metric, b.interface_id, b.order);
    });
    std::vector<std::string> result;
    for (const auto& candidate : candidates)
        if (std::find(result.begin(), result.end(), candidate.address) == result.end())
            result.push_back(candidate.address);
    return result;
}
NetworkMonitor::NetworkMonitor(Source source, bool watch)
    : source_(source ? std::move(source) : platform::enumerate_interfaces) {
    snapshot_.store(std::make_shared<NetworkSnapshot>());
    refresh();
    if (watch)
        watcher_ = std::jthread([this](std::stop_token stop) {
            auto last = platform::monotonic_millis();
            while (!stop.stop_requested()) {
                std::unique_lock lock(wait_mutex_);
                changed_.wait_for(lock, stop, std::chrono::seconds(1), [] { return false; });
                lock.unlock();
                if (!stop.stop_requested()) {
                    const auto now = platform::monotonic_millis();
                    refresh(now - last > 5000);
                    last = now;
                }
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
void NetworkMonitor::refresh(bool invalidate) {
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
    if (!invalidate && next->interfaces == previous->interfaces && next->error == previous->error)
        return;
    next->generation = previous->generation + 1;
    snapshot_.store(std::move(next));
}
NetworkMonitor& NetworkMonitor::shared() {
    static NetworkMonitor monitor;
    return monitor;
}
} // namespace nd
