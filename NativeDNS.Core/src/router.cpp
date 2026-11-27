#include <nativedns/router.hpp>
#include <nativedns/detail/cancellation.hpp>
#include <nativedns/platform.hpp>
#include <algorithm>
#include <charconv>
#include <cmath>
#include <functional>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
namespace nd {
namespace {
std::string protocol_log_suffix(Protocol protocol) {
    switch (protocol) {
        case Protocol::udp:
            return " (UDP) (DNS over UDP)";
        case Protocol::tcp:
            return " (TCP) (DNS over TCP)";
        case Protocol::doh:
            return " (DoH) (DNS over HTTPS)";
        case Protocol::dot:
            return " (DoT) (DNS over TLS)";
        case Protocol::doh3:
            return " (DoH3) (DNS over HTTPS/3)";
        case Protocol::doq:
            return " (DoQ) (DNS over QUIC)";
        case Protocol::dnscrypt:
            return " (DNSCrypt)";
        case Protocol::anonymized_dnscrypt:
            return " (Anonymized DNSCrypt)";
    }
    return {};
}
uint64_t epoch_now_ms() noexcept {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count());
}
std::string sanitize_wire_field(std::string text) {
    for (char& ch : text) {
        if (ch == '\t' || ch == '\r' || ch == '\n')
            ch = ' ';
    }
    if (text.size() > 256)
        text.resize(256);
    return text;
}
const Server* find_server(const Config& config, uint32_t id) {
    const auto it = std::find_if(
        config.servers.begin(), config.servers.end(), [id](const Server& s) { return s.id == id; });
    return it == config.servers.end() ? nullptr : &*it;
}
const ServerPool* find_pool(const Config& config, uint32_t id) {
    const auto it = std::find_if(config.pools.begin(),
                                 config.pools.end(),
                                 [id](const ServerPool& p) { return p.id == id; });
    return it == config.pools.end() ? nullptr : &*it;
}
uint32_t parse_u32_field(std::string_view sv) {
    uint32_t v = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), v);
    return ec == std::errc{} && ptr == sv.data() + sv.size() ? v : 0;
}
uint64_t parse_u64_field(std::string_view sv) {
    uint64_t v = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), v);
    return ec == std::errc{} && ptr == sv.data() + sv.size() ? v : 0;
}
} // namespace
std::string format_pool_statuses(const std::vector<PoolStatusSnapshot>& statuses) {
    std::ostringstream out;
    for (const auto& pool : statuses) {
        out << "POOL\t" << pool.pool_id << '\t' << pool.active_server_id << '\n';
        for (const auto& member : pool.members) {
            const char* health = member.health == PoolMemberHealth::healthy ? "healthy"
                                 : member.health == PoolMemberHealth::failed ? "failed"
                                                                             : "untested";
            out << "MEMBER\t" << pool.pool_id << '\t' << member.server_id << '\t' << health << '\t'
                << static_cast<uint64_t>(std::llround(std::max(0.0, member.rtt_ms))) << '\t'
                << member.checked_epoch_ms << '\t' << sanitize_wire_field(member.last_error)
                << '\n';
        }
    }
    return out.str();
}
std::vector<PoolStatusSnapshot> parse_pool_statuses(const std::string& payload) {
    std::vector<PoolStatusSnapshot> result;
    std::unordered_map<uint32_t, size_t> index_by_pool;
    std::istringstream in(payload);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        std::vector<std::string_view> parts;
        size_t pos = 0;
        while (true) {
            const auto tab = line.find('\t', pos);
            if (tab == std::string::npos) {
                parts.emplace_back(line.data() + pos, line.size() - pos);
                break;
            }
            parts.emplace_back(line.data() + pos, tab - pos);
            pos = tab + 1;
        }
        if (parts.size() >= 3 && parts[0] == "POOL") {
            const uint32_t pid = parse_u32_field(parts[1]);
            if (!pid)
                continue;
            const auto [it, inserted] = index_by_pool.emplace(pid, result.size());
            if (inserted)
                result.push_back({pid, parse_u32_field(parts[2]), {}});
            else
                result[it->second].active_server_id = parse_u32_field(parts[2]);
        } else if (parts.size() >= 6 && parts[0] == "MEMBER") {
            const uint32_t pid = parse_u32_field(parts[1]);
            const uint32_t sid = parse_u32_field(parts[2]);
            if (!pid || !sid)
                continue;
            const auto [it, inserted] = index_by_pool.emplace(pid, result.size());
            if (inserted)
                result.push_back({pid, 0, {}});
            PoolMemberStatus member;
            member.server_id = sid;
            if (parts[3] == "healthy")
                member.health = PoolMemberHealth::healthy;
            else if (parts[3] == "failed")
                member.health = PoolMemberHealth::failed;
            else
                member.health = PoolMemberHealth::untested;
            member.rtt_ms = static_cast<double>(parse_u64_field(parts[4]));
            member.checked_epoch_ms = parse_u64_field(parts[5]);
            if (parts.size() >= 7)
                member.last_error = std::string(parts[6]);
            result[it->second].members.push_back(std::move(member));
        }
    }
    return result;
}
std::string route_log_message(const Question& question,
                              const Rule& rule,
                              const Server* server,
                              std::optional<double> elapsed_ms,
                              const ServerPool* pool) {
    std::ostringstream output;
    output << question.name << " [" << dns_type_name(question.type) << "] - "
           << action_name(rule.action) << " : ";
    if (server) {
        const auto identity = (rule.server_id || rule.pool_id) && !server->name.empty()
                                  ? server->name
                                  : (!server->ip.empty() ? server->ip : server->name);
        output << "server=" << identity << protocol_log_suffix(server->protocol) << ", ";
    }
    output << "rule=" << rule.name;
    if (elapsed_ms)
        output << ", time=" << std::fixed << std::setprecision(2) << *elapsed_ms << " ms";
    if (server)
        output << ", endpoint="
               << (!server->ip.empty()         ? server->ip
                   : !server->hostname.empty() ? server->hostname
                                               : server->url)
               << " port=" << server->port << " interface="
               << (server->route.interface_id.empty() ? "automatic" : server->route.interface_id)
               << " generation=" << server->route.generation;
    const uint32_t reported_server_id =
        ((rule.server_id || rule.pool_id) && server && server->id) ? server->id : rule.server_id;
    output << ", server_id=" << reported_server_id;
    if (rule.pool_id) {
        output << " pool_id=" << rule.pool_id;
        if (pool && !pool->name.empty())
            output << " pool=\"" << pool->name << '"';
    } else if (rule.server_id && server && server->id && server->id != rule.server_id)
        output << " rule_server_id=" << rule.server_id;
    return output.str();
}
Router::Router(Config config, Logger& logger) : logger_(logger) {
    reload(std::move(config));
}
Router::~Router() {
    stop_pool_monitor();
}
Router::SnapshotPtr Router::snapshot() const {
    return snapshot_.load();
}
void Router::reload(Config config) const {
    validate(config);
    auto next = std::make_shared<Snapshot>(std::move(config));
    // Preserve last known health for unchanged pool members so GUI does not flicker on unrelated reloads.
    if (const auto previous = snapshot_.load()) {
        std::lock_guard prev_lock(previous->pool_mutex);
        std::lock_guard next_lock(next->pool_mutex);
        for (const auto& pool : next->config.pools) {
            const auto prev_pool_it = previous->pool_states.find(pool.id);
            const auto* prev_pool_cfg = find_pool(previous->config, pool.id);
            if (prev_pool_it == previous->pool_states.end() || !prev_pool_cfg)
                continue;
            auto& next_state = next->pool_states[pool.id];
            bool all_preserved = true;
            for (const auto sid : pool.server_ids) {
                const auto* prev_srv = find_server(previous->config, sid);
                const auto* next_srv = find_server(next->config, sid);
                const auto prev_m = prev_pool_it->second.members.find(sid);
                if (prev_srv && next_srv && prev_m != prev_pool_it->second.members.end() &&
                    prev_srv->protocol == next_srv->protocol && prev_srv->ip == next_srv->ip &&
                    prev_srv->hostname == next_srv->hostname && prev_srv->url == next_srv->url &&
                    prev_srv->port == next_srv->port && prev_srv->enabled == next_srv->enabled) {
                    next_state.members[sid] = prev_m->second;
                } else {
                    all_preserved = false;
                }
            }
            if (all_preserved && prev_pool_cfg->test_hostname == pool.test_hostname &&
                prev_pool_cfg->type == pool.type &&
                prev_pool_cfg->recheck_seconds == pool.recheck_seconds) {
                next_state.next_probe = prev_pool_it->second.next_probe;
            }
            uint32_t best_id = 0;
            double best_rtt = std::numeric_limits<double>::infinity();
            for (const auto sid : pool.server_ids) {
                const auto* srv = find_server(next->config, sid);
                if (!srv || !srv->enabled)
                    continue;
                const auto& m = next_state.members[sid];
                if (m.health == PoolMemberHealth::healthy && m.rtt_ms < best_rtt) {
                    best_rtt = m.rtt_ms;
                    best_id = sid;
                }
            }
            next_state.active_server_id = best_id;
        }
    }
    platform::set_captive_portal_polling_enabled(next->options.captive_portal_detection);
    snapshot_.store(std::move(next));
    {
        std::lock_guard mlock(monitor_mutex_);
    }
    monitor_cv_.notify_all();
}
void Router::cancel_pending() const {
    cancellation_.load()->request_stop();
    {
        std::lock_guard lock(transport_mutex_);
        transports_.fill(nullptr);
    }
    {
        std::lock_guard mlock(monitor_mutex_);
    }
    monitor_cv_.notify_all();
}
void Router::resume() const {
    if (cancellation_.load()->stop_requested()) {
        cancellation_.store(std::make_shared<std::stop_source>());
        reload(snapshot()->config);
    }
}
void Router::start_pool_monitor() const {
    std::lock_guard lock(monitor_mutex_);
    if (monitor_running_)
        return;
    monitor_running_ = true;
    monitor_thread_ = std::jthread([this] { pool_monitor_loop(); });
}
void Router::stop_pool_monitor() const {
    std::jthread worker;
    {
        std::lock_guard lock(monitor_mutex_);
        if (!monitor_running_)
            return;
        monitor_running_ = false;
        worker = std::move(monitor_thread_);
    }
    monitor_cv_.notify_all();
    if (worker.joinable())
        worker.join();
}
void Router::probe_pool(const Snapshot& snapshot, const ServerPool& pool) const {
    if (pool.server_ids.empty()) {
        std::lock_guard lock(snapshot.pool_mutex);
        auto& state = snapshot.pool_states[pool.id];
        state.active_server_id = 0;
        state.next_probe =
            std::chrono::steady_clock::now() + std::chrono::seconds(pool.recheck_seconds);
        return;
    }
    std::vector<Server> targets;
    targets.reserve(pool.server_ids.size());
    for (const auto sid : pool.server_ids) {
        if (const auto* srv = find_server(snapshot.config, sid); srv && srv->enabled)
            targets.push_back(*srv);
    }
    if (targets.empty()) {
        std::lock_guard lock(snapshot.pool_mutex);
        auto& state = snapshot.pool_states[pool.id];
        state.active_server_id = 0;
        state.next_probe =
            std::chrono::steady_clock::now() + std::chrono::seconds(pool.recheck_seconds);
        return;
    }

    const auto probe_query = make_query(pool.test_hostname);
    const auto probe_question = parse_question(probe_query);
    struct ProbeResult {
        uint32_t server_id = 0;
        PoolMemberHealth health = PoolMemberHealth::failed;
        double rtt_ms = 0.0;
        std::string error;
        uint64_t checked_epoch_ms = 0;
    };
    std::vector<ProbeResult> results(targets.size());
    std::atomic_size_t cursor{0};
    const size_t workers_count = std::min<size_t>(
        targets.size(), std::clamp<size_t>(snapshot.config.test_concurrency, 1, 8));
    auto run_worker = [&] {
        for (;;) {
            if (cancellation_.load()->stop_requested())
                return;
            const size_t idx = cursor.fetch_add(1, std::memory_order_relaxed);
            if (idx >= targets.size())
                return;
            const auto& srv = targets[idx];
            auto& out = results[idx];
            out.server_id = srv.id;
            const auto started = std::chrono::steady_clock::now();
            try {
                auto prepared = with_network_context(srv);
                const auto reply = exchange(probe_query, prepared);
                const auto elapsed = std::chrono::duration<double, std::milli>(
                                         std::chrono::steady_clock::now() - started)
                                         .count();
                const auto parsed = parse_response(reply, probe_question);
                out.rtt_ms = elapsed;
                out.checked_epoch_ms = epoch_now_ms();
                if (parsed.rcode == 0) {
                    out.health = PoolMemberHealth::healthy;
                } else {
                    out.health = PoolMemberHealth::failed;
                    out.error = "DNS RCODE " + std::to_string(parsed.rcode) + " (" +
                                dns_rcode_name(parsed.rcode) + ")";
                }
            } catch (const Error& error) {
                if (error.code == "CANCELLED")
                    return;
                out.health = PoolMemberHealth::failed;
                out.error = error.code + ": " + error.what();
                out.checked_epoch_ms = epoch_now_ms();
            } catch (const std::exception& error) {
                out.health = PoolMemberHealth::failed;
                out.error = error.what();
                out.checked_epoch_ms = epoch_now_ms();
            }
        }
    };
    if (workers_count <= 1) {
        run_worker();
    } else {
        std::vector<std::jthread> workers;
        workers.reserve(workers_count);
        for (size_t i = 0; i < workers_count; ++i)
            workers.emplace_back(run_worker);
    }

    if (cancellation_.load()->stop_requested())
        return;

    uint32_t previous_active = 0;
    uint32_t next_active = 0;
    double best_rtt = std::numeric_limits<double>::infinity();
    {
        std::lock_guard lock(snapshot.pool_mutex);
        auto& state = snapshot.pool_states[pool.id];
        previous_active = state.active_server_id;
        for (const auto& res : results) {
            if (!res.server_id || !res.checked_epoch_ms)
                continue;
            auto& m = state.members[res.server_id];
            m.health = res.health;
            m.rtt_ms = res.rtt_ms;
            m.last_error = res.error;
            m.checked_epoch_ms = res.checked_epoch_ms;
        }
        for (const auto sid : pool.server_ids) {
            const auto* srv = find_server(snapshot.config, sid);
            if (!srv || !srv->enabled)
                continue;
            const auto it = state.members.find(sid);
            if (it != state.members.end() && it->second.health == PoolMemberHealth::healthy &&
                it->second.rtt_ms < best_rtt) {
                best_rtt = it->second.rtt_ms;
                next_active = sid;
            }
        }
        state.active_server_id = next_active;
        state.next_probe =
            std::chrono::steady_clock::now() + std::chrono::seconds(pool.recheck_seconds);
    }
    if (next_active != previous_active && logger_.enabled(Level::verbose)) {
        const auto* chosen = next_active ? find_server(snapshot.config, next_active) : nullptr;
        logger_.write(
            Level::verbose,
            "POOL_MONITOR",
            "pool=\"" + pool.name + "\" pool_id=" + std::to_string(pool.id) + " active_server=" +
                (chosen ? chosen->name : "none") + " active_server_id=" +
                std::to_string(next_active) +
                (chosen ? " rtt_ms=" + std::to_string(static_cast<uint64_t>(std::llround(best_rtt)))
                        : ""));
    }
}
void Router::probe_redundancy_pools_now() const {
    const auto current = snapshot();
    if (!current)
        return;
    for (const auto& pool : current->config.pools) {
        if (pool.type == PoolType::redundancy)
            probe_pool(*current, pool);
    }
}
void Router::pool_monitor_loop() const {
    for (;;) {
        {
            std::lock_guard lock(monitor_mutex_);
            if (!monitor_running_)
                return;
        }
        const auto current = snapshot();
        auto wake_at = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        std::vector<ServerPool> due;
        if (current) {
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard lock(current->pool_mutex);
            for (const auto& pool : current->config.pools) {
                if (pool.type != PoolType::redundancy)
                    continue;
                const auto& state = current->pool_states[pool.id];
                if (state.next_probe == std::chrono::steady_clock::time_point{} ||
                    state.next_probe <= now) {
                    due.push_back(pool);
                } else if (state.next_probe < wake_at) {
                    wake_at = state.next_probe;
                }
            }
        }
        if (!due.empty()) {
            for (const auto& pool : due) {
                {
                    std::lock_guard lock(monitor_mutex_);
                    if (!monitor_running_)
                        return;
                }
                if (snapshot().get() != current.get())
                    break;
                probe_pool(*current, pool);
            }
            continue;
        }
        std::unique_lock lock(monitor_mutex_);
        if (!monitor_running_)
            return;
        monitor_cv_.wait_until(lock, wake_at, [this, &current] {
            return !monitor_running_ || snapshot().get() != current.get();
        });
    }
}
std::vector<PoolStatusSnapshot> Router::pool_statuses() const {
    const auto current = snapshot();
    if (!current)
        return {};
    std::vector<PoolStatusSnapshot> out;
    out.reserve(current->config.pools.size());
    std::lock_guard lock(current->pool_mutex);
    for (const auto& pool : current->config.pools) {
        PoolStatusSnapshot ps;
        ps.pool_id = pool.id;
        const auto st_it = current->pool_states.find(pool.id);
        if (st_it != current->pool_states.end())
            ps.active_server_id = st_it->second.active_server_id;
        ps.members.reserve(pool.server_ids.size());
        for (const auto sid : pool.server_ids) {
            PoolMemberStatus ms;
            ms.server_id = sid;
            if (st_it != current->pool_states.end()) {
                if (const auto m_it = st_it->second.members.find(sid);
                    m_it != st_it->second.members.end()) {
                    ms.health = m_it->second.health;
                    ms.rtt_ms = m_it->second.rtt_ms;
                    ms.last_error = m_it->second.last_error;
                    ms.checked_epoch_ms = m_it->second.checked_epoch_ms;
                }
            }
            ps.members.push_back(std::move(ms));
        }
        out.push_back(std::move(ps));
    }
    return out;
}
Packet Router::exchange(const Packet& request, const Server& server) const {
    detail::CancellationScope cancellation(detail::request_cancellation.stop_possible()
                                               ? detail::request_cancellation
                                               : cancellation_.load()->get_token());
    detail::check_cancelled();
    const auto index = static_cast<size_t>(server.protocol);
    if (index >= transports_.size())
        throw Error("PROTOCOL", "Invalid DNS transport");
    std::shared_ptr<IDnsTransport> transport;
    {
        std::lock_guard lock(transport_mutex_);
        detail::check_cancelled();
        if (!transports_[index])
            transports_[index] = make_transport(server.protocol);
        transport = transports_[index];
    }
    counters_.upstream_attempts.fetch_add(1, std::memory_order_relaxed);
    try {
        auto reply = transport->exchange(request, server);
        counters_.upstream_replies.fetch_add(1, std::memory_order_relaxed);
        return reply;
    } catch (...) {
        counters_.upstream_errors.fetch_add(1, std::memory_order_relaxed);
        throw;
    }
}
RoutingStatistics Router::statistics() const {
    RoutingStatistics v;
#define ND_LOAD(name) v.name = counters_.name.load(std::memory_order_relaxed)
    ND_LOAD(queries_completed);
    ND_LOAD(rules_evaluated);
    ND_LOAD(blocked);
    ND_LOAD(bypassed);
    ND_LOAD(parse_errors);
    ND_LOAD(route_errors);
    ND_LOAD(negative_replies);
    ND_LOAD(upstream_error_rcodes);
    ND_LOAD(upstream_attempts);
    ND_LOAD(upstream_replies);
    ND_LOAD(upstream_errors);
#undef ND_LOAD
    return v;
}
std::pair<Packet, const Server*> Router::exchange_pool(const Snapshot& snapshot,
                                                       const Packet& request,
                                                       const ServerPool& pool,
                                                       const NetworkRoute& route) const {
    std::vector<const Server*> candidates;
    candidates.reserve(pool.server_ids.size());
    for (const auto sid : pool.server_ids) {
        if (const auto* srv = find_server(snapshot.config, sid); srv && srv->enabled)
            candidates.push_back(srv);
    }
    if (candidates.empty())
        throw Error("POOL_EMPTY", "Server pool has no enabled servers: " + pool.name);

    const auto started = std::chrono::steady_clock::now();
    uint64_t budget_ms = 0;
    for (const auto* server : candidates)
        budget_ms = std::min<uint64_t>(120000, budget_ms + server->timeout_ms);
    budget_ms =
        std::max<uint64_t>(candidates.front()->timeout_ms, std::min<uint64_t>(30000, budget_ms));
    const auto deadline = started + std::chrono::milliseconds(budget_ms);

    if (pool.type == PoolType::redundancy) {
        std::lock_guard lock(snapshot.pool_mutex);
        const auto& state = snapshot.pool_states[pool.id];
        auto rank_of = [&](const Server* srv) -> std::pair<int, double> {
            const auto it = state.members.find(srv->id);
            if (it == state.members.end() || it->second.health == PoolMemberHealth::untested)
                return {1, 0.0};
            if (it->second.health == PoolMemberHealth::healthy)
                return {0, it->second.rtt_ms};
            return {2, it->second.rtt_ms};
        };
        std::stable_sort(candidates.begin(),
                         candidates.end(),
                         [&](const Server* left, const Server* right) {
                             const auto a = rank_of(left);
                             const auto b = rank_of(right);
                             if (a.first != b.first)
                                 return a.first < b.first;
                             if (a.first == 0)
                                 return a.second < b.second;
                             return false;
                         });
    } else {
        // Load Balancing: pick a random enabled server for each request, with
        // failover to remaining pool members on failure.
        for (size_t i = candidates.size(); i > 1; --i) {
            const size_t j = platform::secure_random_u32() % i;
            std::swap(candidates[i - 1], candidates[j]);
        }
    }

    auto recompute_active = [&](PoolRuntimeState& state) {
        uint32_t best_id = 0;
        double best_rtt = std::numeric_limits<double>::infinity();
        for (const auto sid : pool.server_ids) {
            const auto* srv = find_server(snapshot.config, sid);
            if (!srv || !srv->enabled)
                continue;
            const auto it = state.members.find(sid);
            if (it != state.members.end() && it->second.health == PoolMemberHealth::healthy &&
                it->second.rtt_ms < best_rtt) {
                best_rtt = it->second.rtt_ms;
                best_id = sid;
            }
        }
        state.active_server_id = best_id;
    };

    std::string last_code = "UPSTREAM_UNAVAILABLE", last_message = "No pool upstream attempt completed";
    std::optional<std::pair<Packet, const Server*>> fallback_rcode_reply;
    for (size_t index = 0; index < candidates.size(); ++index) {
        const auto* candidate = candidates[index];
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            break;
        auto attempt = *candidate;
        if (!route.interface_id.empty())
            attempt.route = route;
        attempt = with_network_context(std::move(attempt));
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        attempt.timeout_ms = static_cast<uint32_t>(
            std::min<int64_t>(attempt.timeout_ms, std::max<int64_t>(1, remaining)));
        const auto attempt_started = std::chrono::steady_clock::now();
        try {
            auto packet = exchange(request, attempt);
            const uint16_t base_rcode =
                packet.size() >= 4 ? static_cast<uint16_t>(packet[3] & 0x0f) : 0;
            if ((base_rcode == 2 || base_rcode == 5) && index + 1 < candidates.size()) {
                if (!fallback_rcode_reply)
                    fallback_rcode_reply.emplace(std::move(packet), candidate);
                {
                    std::lock_guard lock(snapshot.pool_mutex);
                    auto& state = snapshot.pool_states[pool.id];
                    auto& member = state.members[candidate->id];
                    member.health = PoolMemberHealth::failed;
                    member.last_error = "DNS RCODE " + std::to_string(base_rcode) + " (" +
                                        dns_rcode_name(base_rcode) + ")";
                    member.checked_epoch_ms = epoch_now_ms();
                    if (pool.type == PoolType::redundancy)
                        recompute_active(state);
                }
                if (logger_.enabled(Level::verbose))
                    logger_.write_limited(
                        Level::verbose,
                        "pool-rcode|" + std::to_string(pool.id) + '|' +
                            std::to_string(candidate->id) + '|' + std::to_string(base_rcode),
                        "UPSTREAM_FAILOVER",
                        "pool=\"" + pool.name + "\" server=" + candidate->name +
                            " failure=DNS_RCODE(" + dns_rcode_name(base_rcode) +
                            ") trying_next=1");
                continue;
            }
            const double elapsed = std::chrono::duration<double, std::milli>(
                                       std::chrono::steady_clock::now() - attempt_started)
                                       .count();
            {
                std::lock_guard lock(snapshot.pool_mutex);
                auto& state = snapshot.pool_states[pool.id];
                auto& member = state.members[candidate->id];
                const bool was_healthy = member.health == PoolMemberHealth::healthy;
                member.health = PoolMemberHealth::healthy;
                member.rtt_ms = was_healthy ? (member.rtt_ms * 0.8 + elapsed * 0.2) : elapsed;
                member.last_error.clear();
                member.checked_epoch_ms = epoch_now_ms();
                if (pool.type == PoolType::redundancy)
                    recompute_active(state);
            }
            return {std::move(packet), candidate};
        } catch (const Error& error) {
            if (error.code == "CANCELLED")
                throw;
            last_code = error.code;
            last_message = "pool=" + pool.name + " server=" + candidate->name +
                           " protocol=" + protocol_name(candidate->protocol) +
                           " context=" + network_route_key(attempt.route) +
                           " error=" + error.what();
            {
                std::lock_guard lock(snapshot.pool_mutex);
                auto& state = snapshot.pool_states[pool.id];
                auto& member = state.members[candidate->id];
                member.health = PoolMemberHealth::failed;
                member.last_error = error.code + ": " + error.what();
                member.checked_epoch_ms = epoch_now_ms();
                if (pool.type == PoolType::redundancy)
                    recompute_active(state);
            }
            if (logger_.enabled(Level::verbose))
                logger_.write_limited(Level::verbose,
                                      "pool-fail|" + std::to_string(pool.id) + '|' +
                                          std::to_string(candidate->id) + '|' + error.code,
                                      "UPSTREAM_FAILOVER",
                                      "pool=\"" + pool.name + "\" server=" + candidate->name +
                                          " failure=" + last_code);
        }
    }
    if (fallback_rcode_reply)
        return std::move(*fallback_rcode_reply);
    throw Error(last_code, "Server pool exhausted: " + last_message);
}
Router::ExchangeResult Router::exchange_cached(const Snapshot& snapshot,
                                               const Packet& request,
                                               const Question& question,
                                               const Server& primary,
                                               bool configured,
                                               const ServerPool* pool) const {
    if (request.size() < 2)
        throw Error("DNS_MALFORMED", "DNS request is too short");
    std::string key;
    key.reserve(request.size() + 96);
    if (pool) {
        key += "pool:";
        key += std::to_string(pool->id);
    } else {
        key += configured ? "configured:" : "original:";
        key += std::to_string(configured ? primary.id : static_cast<uint32_t>(primary.protocol));
    }
    key += '|';
    key += network_route_key(primary.route) + '|';
    if (!configured && !pool)
        key += primary.ip + '|' + std::to_string(primary.port) + '|';
    key.append(2, '\0');
    key.append(reinterpret_cast<const char*>(request.data() + 2), request.size() - 2);
    const uint16_t transaction_id = static_cast<uint16_t>((request[0] << 8) | request[1]);
    std::shared_ptr<Pending> pending;
    bool leader = false;
    {
        std::unique_lock lock(snapshot.cache_mutex);
        const auto now = std::chrono::steady_clock::now();
        if (const auto found = snapshot.cache.find(key); found != snapshot.cache.end()) {
            if (found->second.expires <= now) {
                snapshot.cache_bytes -= found->second.packet.size() + found->first.size();
                snapshot.cache_lru.erase(found->second.lru_it);
                snapshot.cache.erase(found);
            } else {
                snapshot.cache_lru.splice(
                    snapshot.cache_lru.begin(), snapshot.cache_lru, found->second.lru_it);
                const auto elapsed = static_cast<uint32_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(now - found->second.stored)
                        .count());
                if (logger_.enabled(Level::debug))
                    logger_.write(Level::debug,
                                  "DNS_CACHE_HIT",
                                  pool ? ("pool=" + pool->name) : ("server=" + primary.name));
                return {age_dns_response(found->second.packet, transaction_id, elapsed),
                        found->second.parsed,
                        found->second.used_server_id,
                        ExchangeSource::cache};
            }
        }
        const auto found = snapshot.pending.find(key);
        if (found != snapshot.pending.end())
            pending = found->second;
        else {
            if (snapshot.pending.size() >= 256)
                throw Error("UPSTREAM_BUSY", "Too many distinct DNS queries in flight");
            pending = std::make_shared<Pending>();
            snapshot.pending.emplace(key, pending);
            leader = true;
        }
        if (!leader) {
            if (logger_.enabled(Level::debug))
                logger_.write(Level::debug,
                              "DNS_COALESCED",
                              pool ? ("pool=" + pool->name) : ("server=" + primary.name));
            uint64_t group_budget_ms = primary.timeout_ms;
            if (pool) {
                uint64_t sum_ms = 0;
                uint64_t first_timeout = 3000;
                bool saw_first = false;
                for (const auto sid : pool->server_ids) {
                    if (const auto* srv = find_server(snapshot.config, sid); srv && srv->enabled) {
                        if (!saw_first) {
                            first_timeout = srv->timeout_ms;
                            saw_first = true;
                        }
                        sum_ms = std::min<uint64_t>(120000, sum_ms + srv->timeout_ms);
                    }
                }
                group_budget_ms =
                    std::max<uint64_t>(first_timeout, std::min<uint64_t>(30000, sum_ms));
            }
            const auto wait_ms =
                std::min<uint64_t>(120000, std::max<uint64_t>(group_budget_ms + 1000, 2000));
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms);
            while (!pending->done)
                if (detail::wait_until_change(pending->changed, lock, deadline) ==
                    std::cv_status::timeout)
                    throw Error("TIMEOUT", "Coalesced DNS request deadline exceeded");
            if (!pending->error_code.empty())
                throw Error(pending->error_code, pending->error_message);
            return {age_dns_response(pending->packet, transaction_id, 0),
                    pending->parsed,
                    pending->used_server_id,
                    ExchangeSource::coalesced};
        }
    }
    try {
        std::pair<Packet, const Server*> exchanged;
        if (pool) {
            exchanged = exchange_pool(snapshot, request, *pool, primary.route);
        } else {
            exchanged = {exchange(request, primary), &primary};
        }
        exchanged.first =
            clamp_dns_ttl(exchanged.first, snapshot.options.ttl_min, snapshot.options.ttl_max);
        auto parsed = parse_response(exchanged.first, question);
        const uint32_t used_id = (configured || pool) ? exchanged.second->id : 0;
        {
            std::lock_guard lock(snapshot.cache_mutex);
            const auto now = std::chrono::steady_clock::now();
            if (parsed.cacheable) {
                constexpr size_t max_cache_bytes = 32 * 1024 * 1024;
                const auto entry_bytes = exchanged.first.size() + key.size();
                if (const auto existing = snapshot.cache.find(key);
                    existing != snapshot.cache.end()) {
                    snapshot.cache_bytes -= existing->second.packet.size() + existing->first.size();
                    snapshot.cache_lru.erase(existing->second.lru_it);
                    snapshot.cache.erase(existing);
                }
                for (unsigned pruned = 0; pruned < 4 && !snapshot.cache_lru.empty(); ++pruned) {
                    const auto tail = snapshot.cache.find(snapshot.cache_lru.back());
                    if (tail == snapshot.cache.end() || tail->second.expires > now)
                        break;
                    snapshot.cache_bytes -= tail->second.packet.size() + tail->first.size();
                    snapshot.cache.erase(tail);
                    snapshot.cache_lru.pop_back();
                }
                while (!snapshot.cache_lru.empty() &&
                       (snapshot.cache.size() >= 4096 ||
                        snapshot.cache_bytes + entry_bytes > max_cache_bytes)) {
                    const auto victim = snapshot.cache.find(snapshot.cache_lru.back());
                    if (victim != snapshot.cache.end()) {
                        snapshot.cache_bytes -= victim->second.packet.size() + victim->first.size();
                        snapshot.cache.erase(victim);
                    }
                    snapshot.cache_lru.pop_back();
                }
                const auto ttl = std::min<uint32_t>(parsed.cache_ttl, 86400);
                snapshot.cache_lru.push_front(key);
                snapshot.cache.emplace(
                    key,
                    CacheEntry{exchanged.first,
                               parsed,
                               now,
                               now + std::chrono::seconds(ttl),
                               used_id,
                               snapshot.cache_lru.begin()});
                snapshot.cache_bytes += entry_bytes;
            }
            pending->packet = exchanged.first;
            pending->parsed = parsed;
            pending->used_server_id = used_id;
            pending->done = true;
            snapshot.pending.erase(key);
        }
        pending->changed.notify_all();
        return {std::move(exchanged.first), std::move(parsed), used_id, ExchangeSource::upstream};
    } catch (const Error& error) {
        {
            std::lock_guard lock(snapshot.cache_mutex);
            pending->error_code = error.code;
            pending->error_message = error.what();
            pending->done = true;
            snapshot.pending.erase(key);
        }
        pending->changed.notify_all();
        throw;
    } catch (const std::exception& error) {
        {
            std::lock_guard lock(snapshot.cache_mutex);
            pending->error_code = "INTERNAL";
            pending->error_message = error.what();
            pending->done = true;
            snapshot.pending.erase(key);
        }
        pending->changed.notify_all();
        throw;
    } catch (...) {
        {
            std::lock_guard lock(snapshot.cache_mutex);
            pending->error_code = "INTERNAL";
            pending->error_message = "Unknown upstream routing exception";
            pending->done = true;
            snapshot.pending.erase(key);
        }
        pending->changed.notify_all();
        throw;
    }
}
RouteResult Router::route(const Packet& request, const Server& original) const {
    return route(request, original, snapshot());
}
RouteResult Router::route(const Packet& request,
                          const Server& original,
                          SnapshotPtr current,
                          std::optional<Question> pre_parsed,
                          std::optional<RuleDecision> pre_decision) const {
    detail::CancellationScope cancellation(cancellation_.load()->get_token());
    const auto& snapshot = *current;
    RouteResult result;
    struct Completed {
        Counters& counters;
        ~Completed() {
            counters.queries_completed.fetch_add(1, std::memory_order_relaxed);
        }
    } completed{counters_};
    Question question;
    LogContext context;
    bool valid_question = false;
    const Rule* matched_rule = nullptr;
    const Server* selected_server = nullptr;
    const ServerPool* selected_pool = nullptr;
    std::optional<Server> diagnostic_server;
    const auto log = [this, &context, &selected_server, &selected_pool](Level level,
                                                                        std::string code,
                                                                        std::string message,
                                                                        std::string extra_key = {}) {
        if (level == Level::errors_only) {
            auto key =
                code + '|' + context.rule + '|' +
                (selected_pool ? ("pool:" + std::to_string(selected_pool->id) + '|') : "") +
                (selected_server
                     ? std::to_string(selected_server->id) + '|' +
                           protocol_name(selected_server->protocol) + '|' + selected_server->ip +
                           '|' + selected_server->hostname + '|' + selected_server->url + '|' +
                           std::to_string(selected_server->port) + '|' +
                           network_route_key(selected_server->route)
                     : "no-upstream");
            if (!extra_key.empty())
                key += '|' + extra_key;
            logger_.write_limited(
                level, std::move(key), std::move(code), std::move(message), context);
        } else
            logger_.write(level, std::move(code), std::move(message), context);
    };
    auto exchange_started = std::chrono::steady_clock::time_point{};
    try {
        question = pre_parsed ? std::move(*pre_parsed) : parse_question(request);
        if (question.flags & 0x8000)
            throw Error("DNS_MALFORMED", "Cannot route a reply as a query");
        valid_question = true;
        context.address = question.name;
        context.dns_type = dns_type_name(question.type);
        const auto decision = (pre_decision && pre_decision->rule)
                                  ? std::move(*pre_decision)
                                  : evaluate_compiled_rule(snapshot.compiled_rules, question.name);
        const auto& rule = *decision.rule;
        counters_.rules_evaluated.fetch_add(1, std::memory_order_relaxed);
        if (rule.action == Action::block)
            counters_.blocked.fetch_add(1, std::memory_order_relaxed);
        if (rule.action == Action::bypass)
            counters_.bypassed.fetch_add(1, std::memory_order_relaxed);
        matched_rule = &rule;
        context.rule = rule.name;
        context.action = action_name(rule.action);
        result.rule_id = rule.id;
        result.server_id = rule.server_id;
        result.pool_id = rule.pool_id;
        result.action = rule.action;
        if (!decision.error_code.empty())
            throw Error(decision.error_code, decision.message);
        if (decision.captive_bypass || rule.action == Action::bypass) {
            if (decision.captive_bypass)
                log(Level::normal,
                    "CAPTIVE_PORTAL_BYPASS",
                    "Preserving OS resolver for captive portal discovery");
            if (logger_.enabled(Level::normal))
                log(Level::normal, "DNS_ROUTE", route_log_message(question, rule, &original));
            result.disposition = Disposition::forward_original;
            result.packet = request;
            return result;
        }
        if (rule.action == Action::block) {
            if (logger_.enabled(Level::normal)) {
                std::string block_detail = ", source=local_block";
                if (rule.block_mode == BlockMode::silent_drop)
                    block_detail += " silent_drop=1";
                else {
                    const uint16_t block_rcode = rule.block_mode == BlockMode::nxdomain ? 3
                                                 : rule.block_mode == BlockMode::refused ? 5
                                                                                         : 0;
                    block_detail += " rcode=" + std::to_string(block_rcode) +
                                    " rcode_name=" + dns_rcode_name(block_rcode);
                }
                log(Level::normal,
                    "DNS_ROUTE",
                    route_log_message(question, rule, nullptr) + block_detail);
            }
            if (rule.block_mode == BlockMode::silent_drop) {
                result.disposition = Disposition::silent_drop;
                return result;
            }
            result.packet = make_block_response(request, rule.block_mode);
            return result;
        }
        const Server* server = &original;
        if (rule.pool_id) {
            selected_pool = find_pool(snapshot.config, rule.pool_id);
            if (!selected_pool)
                throw Error("POOL_REFERENCE", "Missing selected server pool");
        } else if (rule.server_id) {
            server = find_server(snapshot.config, rule.server_id);
            if (!server)
                throw Error("SERVER_REFERENCE", "Missing selected server");
            if (!server->enabled)
                throw Error("SERVER_DISABLED", "Selected DNS server is disabled");
        }
        selected_server = server;
        diagnostic_server = *server;
        auto& routed_server = *diagnostic_server;
        selected_server = &routed_server;
        if (!decision.route.interface_id.empty()) {
            routed_server.route = decision.route;
            if (!rule.server_id && !rule.pool_id) {
                if (decision.interface_dns.empty())
                    throw Error("INTERFACE_DNS", "Selected interface has no DNS resolver");
                routed_server.ip = decision.interface_dns.front();
                routed_server.port = 53;
            }
        }
        routed_server = with_network_context(std::move(routed_server));
        if (logger_.enabled(Level::verbose))
            log(Level::verbose,
                "DNS_UPSTREAM",
                route_log_message(
                    question, rule, selected_pool ? nullptr : &routed_server, std::nullopt, selected_pool));
        exchange_started = std::chrono::steady_clock::now();
        ExchangeResult exchanged;
        if (selected_pool) {
            exchanged = exchange_cached(
                snapshot, request, question, routed_server, true, selected_pool);
        } else if (!decision.route.interface_id.empty() && !rule.server_id &&
                   decision.interface_dns.size() > 1) {
            const auto total_deadline =
                exchange_started + std::chrono::milliseconds(routed_server.timeout_ms);
            std::exception_ptr last_error;
            bool succeeded = false;
            for (size_t i = 0; i < decision.interface_dns.size(); ++i) {
                const auto now = std::chrono::steady_clock::now();
                if (now >= total_deadline)
                    break;
                const auto remaining_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(total_deadline - now)
                        .count();
                const auto left = decision.interface_dns.size() - i;
                auto candidate = routed_server;
                candidate.ip = decision.interface_dns[i];
                candidate.port = 53;
                candidate.timeout_ms = static_cast<uint32_t>(
                    std::max<int64_t>(1, remaining_ms / static_cast<int64_t>(left)));
                try {
                    exchanged = exchange_cached(snapshot, request, question, candidate, false);
                    routed_server = std::move(candidate);
                    succeeded = true;
                    break;
                } catch (const Error& error) {
                    if (error.code == "CANCELLED")
                        throw;
                    last_error = std::current_exception();
                }
            }
            if (!succeeded) {
                if (last_error)
                    std::rethrow_exception(last_error);
                throw Error("TIMEOUT", "Interface DNS resolvers timed out");
            }
        } else {
            exchanged =
                exchange_cached(snapshot, request, question, routed_server, rule.server_id != 0);
        }
        result.packet = std::move(exchanged.packet);
        result.server_id = exchanged.used_server_id;
        if (result.server_id) {
            if (const auto* used = find_server(snapshot.config, result.server_id)) {
                const auto route = routed_server.route;
                routed_server = *used;
                routed_server.route = route;
            }
        }
        const auto& parsed = exchanged.parsed;
        const auto elapsed = std::chrono::duration<double, std::milli>(
                                 std::chrono::steady_clock::now() - exchange_started)
                                 .count();
        const char* source = exchanged.source == ExchangeSource::cache       ? "cache"
                             : exchanged.source == ExchangeSource::coalesced ? "coalesced"
                                                                             : "upstream";
        const auto rcode_text = dns_rcode_name(parsed.rcode);
        const auto common_meta = [&] {
            std::string meta = " rcode_name=" + rcode_text + " source=" + source +
                               " answer_count=" + std::to_string(parsed.answer_count) +
                               " authority_soa=" + (parsed.has_authority_soa ? "1" : "0");
            if (parsed.has_authority_soa)
                meta += " soa_ttl=" + std::to_string(parsed.soa_ttl);
            meta += std::string(" ad=") + (parsed.authenticated_data ? "1" : "0") +
                    " tc=" + (parsed.truncated ? "1" : "0");
            return meta;
        };
        if (parsed.rcode == 0) {
            if (parsed.answer_count == 0)
                counters_.negative_replies.fetch_add(1, std::memory_order_relaxed);
            if (logger_.enabled(Level::normal)) {
                std::string details =
                    ", rcode=0 address_count=" + std::to_string(parsed.addresses.size());
                for (size_t i = 0; i < parsed.addresses.size() && i < 8; ++i)
                    details += " answer_ip=" + parsed.addresses[i];
                details += common_meta();
                if (parsed.answer_count == 0)
                    details += " nodata=1";
                log(Level::normal,
                    "DNS_ROUTE",
                    route_log_message(question, rule, selected_server, elapsed, selected_pool) +
                        details);
            }
            if (logger_.enabled(Level::debug))
                log(Level::debug,
                    "DNS_REPLY_DETAIL",
                    question.name + " bytes=" + std::to_string(result.packet.size()) +
                        " addresses=" + std::to_string(parsed.addresses.size()));
        } else if (parsed.rcode == 3) {
            // NXDOMAIN is a valid negative DNS response, not a routing or transport failure.
            counters_.negative_replies.fetch_add(1, std::memory_order_relaxed);
            if (logger_.enabled(Level::normal))
                log(Level::normal,
                    "DNS_ROUTE",
                    route_log_message(question, rule, selected_server, elapsed, selected_pool) +
                        ", rcode=3" + common_meta());
        } else {
            counters_.route_errors.fetch_add(1, std::memory_order_relaxed);
            counters_.upstream_error_rcodes.fetch_add(1, std::memory_order_relaxed);
            result.error_code = "DNS_RCODE";
            result.message =
                "Upstream returned RCODE " + std::to_string(parsed.rcode) + " (" + rcode_text + ")";
            log(Level::errors_only,
                result.error_code,
                route_log_message(question, rule, selected_server, elapsed, selected_pool) +
                    ", rcode=" + std::to_string(parsed.rcode) + common_meta() +
                    ", error=" + result.message,
                "rcode=" + std::to_string(parsed.rcode));
        }
    } catch (const Error& error) {
        if (!valid_question)
            counters_.parse_errors.fetch_add(1, std::memory_order_relaxed);
        counters_.route_errors.fetch_add(1, std::memory_order_relaxed);
        result.error_code = error.code;
        result.message = error.what();
        if (valid_question && matched_rule) {
            const auto elapsed =
                exchange_started == std::chrono::steady_clock::time_point{}
                    ? std::optional<double>{}
                    : std::optional<double>{std::chrono::duration<double, std::milli>(
                                                std::chrono::steady_clock::now() - exchange_started)
                                                .count()};
            log(Level::errors_only,
                error.code,
                route_log_message(
                    question, *matched_rule, selected_pool ? nullptr : selected_server, elapsed, selected_pool) +
                    ", error=" + error.what());
        } else
            log(Level::errors_only, error.code, question.name + " " + error.what());
        if (valid_question)
            result.packet = make_error_response(request, 2);
        else
            result.disposition = Disposition::silent_drop;
    } catch (const std::exception& error) {
        counters_.route_errors.fetch_add(1, std::memory_order_relaxed);
        result.error_code = "INTERNAL";
        result.message = error.what();
        if (valid_question && matched_rule) {
            const auto elapsed =
                exchange_started == std::chrono::steady_clock::time_point{}
                    ? std::optional<double>{}
                    : std::optional<double>{std::chrono::duration<double, std::milli>(
                                                std::chrono::steady_clock::now() - exchange_started)
                                                .count()};
            log(Level::errors_only,
                result.error_code,
                route_log_message(
                    question, *matched_rule, selected_pool ? nullptr : selected_server, elapsed, selected_pool) +
                    ", error=" + error.what());
        } else
            log(Level::errors_only, result.error_code, result.message);
        if (valid_question)
            result.packet = make_error_response(request, 2);
        else
            result.disposition = Disposition::silent_drop;
    }
    return result;
}
} // namespace nd
