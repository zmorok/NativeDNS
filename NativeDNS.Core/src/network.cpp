#include <nativedns/network.hpp>
#include <algorithm>
#include <chrono>
#include <exception>
#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <charconv>
#include <map>
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
std::string describe_network_change(const NetworkSnapshot& previous, const NetworkSnapshot& current) {
    auto sanitize_name = [](std::string value) {
        for (char& ch : value) {
            if (ch == '"')
                ch = '\'';
            else if (static_cast<unsigned char>(ch) < 32)
                ch = ' ';
        }
        return value;
    };
    auto format_up = [&](const InterfaceInfo& info) {
        auto label = sanitize_name(info.name.empty() ? info.id : info.name);
        label += " (up";
        if (!info.addresses.empty())
            label += ", " + sanitize_name(info.addresses.front());
        if (!info.dns_servers.empty())
            label += ", dns=" + sanitize_name(info.dns_servers.front());
        if (info.captive_portal)
            label += ", captive_portal";
        label += ')';
        return label;
    };
    std::map<std::string, const InterfaceInfo*> prev_by_id, curr_by_id;
    for (const auto& info : previous.interfaces)
        prev_by_id.emplace(info.id, &info);
    for (const auto& info : current.interfaces)
        curr_by_id.emplace(info.id, &info);
    std::vector<std::string> changes;
    for (const auto& [id, curr] : curr_by_id) {
        const auto found = prev_by_id.find(id);
        if (found == prev_by_id.end()) {
            if (curr->up)
                changes.push_back(format_up(*curr));
            continue;
        }
        const auto* prev = found->second;
        if (prev->up != curr->up) {
            changes.push_back(curr->up ? format_up(*curr)
                                       : sanitize_name(curr->name.empty() ? curr->id : curr->name) +
                                             " (down)");
        } else if (curr->up &&
                   (prev->addresses != curr->addresses || prev->dns_servers != curr->dns_servers ||
                    prev->gateways != curr->gateways ||
                    prev->captive_portal != curr->captive_portal)) {
            changes.push_back(format_up(*curr));
        }
    }
    for (const auto& [id, prev] : prev_by_id) {
        if (curr_by_id.find(id) == curr_by_id.end() && prev->up) {
            changes.push_back(sanitize_name(prev->name.empty() ? prev->id : prev->name) +
                              " (removed)");
        }
    }
    if (changes.empty()) {
        if (previous.interfaces == current.interfaces && previous.error == current.error) {
            if (current.power_resumed && current.resume_sleep_ms > 0)
                return "resume (power, sleep=" + std::to_string(current.resume_sleep_ms) + "ms)";
            if (current.resume_sleep_ms > 0)
                return "resume (sleep=" + std::to_string(current.resume_sleep_ms) + "ms)";
            if (current.power_resumed)
                return "resume (power)";
            return "resume";
        }
        return "none";
    }
    std::string summary;
    const size_t limit = std::min<size_t>(changes.size(), 4);
    for (size_t i = 0; i < limit; ++i) {
        if (i > 0)
            summary += ", ";
        summary += changes[i];
    }
    if (changes.size() > 4)
        summary += ", +" + std::to_string(changes.size() - 4) + " more";
    return summary;
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
uint64_t detected_suspend_millis(platform::MonotonicClocks previous,
                                 platform::MonotonicClocks current) noexcept {
    if (current.boottime_ms <= previous.boottime_ms)
        return 0;
    const uint64_t boot_delta = current.boottime_ms - previous.boottime_ms;
    const uint64_t active_delta =
        current.active_ms > previous.active_ms ? current.active_ms - previous.active_ms : 0;
    return boot_delta > active_delta ? boot_delta - active_delta : 0;
}
NetworkMonitor::NetworkMonitor(Source source, bool watch, ClockSource clocks)
    : source_(source ? std::move(source) : platform::enumerate_interfaces),
      clocks_(clocks ? std::move(clocks) : platform::monotonic_clocks) {
    snapshot_.store(std::make_shared<NetworkSnapshot>());
    last_clocks_ = clocks_();
    refresh();
    if (watch) {
        suspend_subscription_ = std::make_unique<platform::SuspendResumeSubscription>([this] {
            resume_pending_.store(true, std::memory_order_release);
            changed_.notify_all();
        });
        watcher_ = std::jthread([this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                std::unique_lock lock(wait_mutex_);
                changed_.wait_for(lock, stop, std::chrono::seconds(1), [this] {
                    return resume_pending_.load(std::memory_order_acquire);
                });
                lock.unlock();
                if (!stop.stop_requested())
                    poll_once();
            }
        });
    }
}
NetworkMonitor::~NetworkMonitor() {
    suspend_subscription_.reset();
    watcher_.request_stop();
    changed_.notify_all();
    if (watcher_.joinable())
        watcher_.join();
}
void NetworkMonitor::poll_once() {
    constexpr uint64_t resume_threshold_ms = 3000;
    const auto now = clocks_();
    uint64_t suspend_ms = 0;
    {
        std::lock_guard lock(wait_mutex_);
        suspend_ms = detected_suspend_millis(last_clocks_, now);
        last_clocks_ = now;
    }
    const bool power_resumed = resume_pending_.exchange(false, std::memory_order_acq_rel);
    const bool resumed = power_resumed || suspend_ms >= resume_threshold_ms;
    refresh(resumed, resumed ? suspend_ms : 0, power_resumed);
}
NetworkSnapshotPtr NetworkMonitor::snapshot() const {
    return snapshot_.load();
}
namespace {
bool active_routing_equal(const InterfaceInfo& a, const InterfaceInfo& b) {
    return a.id == b.id && a.name == b.name && a.dns_suffix == b.dns_suffix && a.luid == b.luid &&
           a.index4 == b.index4 && a.index6 == b.index6 && a.up == b.up &&
           a.loopback == b.loopback && a.captive_portal == b.captive_portal &&
           a.addresses == b.addresses && a.dns_servers == b.dns_servers &&
           a.gateways == b.gateways;
}
bool routing_equivalent(const std::vector<InterfaceInfo>& previous,
                        const std::vector<InterfaceInfo>& current) {
    size_t i = 0, j = 0;
    while (i < previous.size() || j < current.size()) {
        while (i < previous.size() && !previous[i].up)
            ++i;
        while (j < current.size() && !current[j].up)
            ++j;
        if (i == previous.size() || j == current.size())
            return i == previous.size() && j == current.size();
        if (!active_routing_equal(previous[i], current[j]))
            return false;
        ++i;
        ++j;
    }
    return select_bootstrap_dns_servers(previous) == select_bootstrap_dns_servers(current);
}
} // namespace
void NetworkMonitor::refresh(bool invalidate, uint64_t resume_sleep_ms, bool power_resumed) {
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
    const bool initial = previous->generation == 0;
    const bool routing_changed = initial || invalidate || next->error != previous->error ||
                                 !routing_equivalent(previous->interfaces, next->interfaces);
    if (!routing_changed) {
        if (next->interfaces == previous->interfaces)
            return;
        next->generation = previous->generation;
        snapshot_.store(std::move(next));
        return;
    }
    if (invalidate) {
        next->resume_sleep_ms = resume_sleep_ms;
        next->power_resumed = power_resumed;
    }
    next->generation = previous->generation + 1;
    snapshot_.store(std::move(next));
}
NetworkMonitor& NetworkMonitor::shared() {
    static NetworkMonitor monitor;
    return monitor;
}
} // namespace nd
