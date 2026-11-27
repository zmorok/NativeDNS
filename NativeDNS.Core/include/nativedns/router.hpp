#pragma once
#include <nativedns/dns.hpp>
#include <array>
#include <list>
#include <mutex>
#include <optional>
#include <map>
#include <unordered_map>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <stop_token>
#include <thread>
namespace nd {
enum class Disposition { reply, forward_original, silent_drop };
enum class PoolMemberHealth { untested, healthy, failed };
struct PoolMemberStatus {
    uint32_t server_id = 0;
    PoolMemberHealth health = PoolMemberHealth::untested;
    double rtt_ms = 0.0;
    std::string last_error;
    uint64_t checked_epoch_ms = 0;
};
struct PoolStatusSnapshot {
    uint32_t pool_id = 0;
    uint32_t active_server_id = 0;
    std::vector<PoolMemberStatus> members;
};
std::string format_pool_statuses(const std::vector<PoolStatusSnapshot>& statuses);
std::vector<PoolStatusSnapshot> parse_pool_statuses(const std::string& payload);
struct RouteResult {
    Disposition disposition = Disposition::reply;
    Packet packet;
    uint32_t rule_id = 0, server_id = 0, pool_id = 0;
    Action action = Action::process;
    std::string error_code, message;
};
struct RoutingStatistics {
    uint64_t queries_completed = 0, rules_evaluated = 0, blocked = 0, bypassed = 0;
    uint64_t parse_errors = 0, route_errors = 0;
    uint64_t negative_replies = 0, upstream_error_rcodes = 0;
    uint64_t upstream_attempts = 0, upstream_replies = 0, upstream_errors = 0;
};
std::string route_log_message(const Question& question,
                              const Rule& rule,
                              const Server* server,
                              std::optional<double> elapsed_ms = std::nullopt,
                              const ServerPool* pool = nullptr);
// Each DNS query retains one validated configuration snapshot. Original destination belongs to
// the interception backend.
class Router {
private:
    struct PoolMemberState {
        PoolMemberHealth health = PoolMemberHealth::untested;
        double rtt_ms = 0.0;
        std::string last_error;
        uint64_t checked_epoch_ms = 0;
    };
    struct PoolRuntimeState {
        uint32_t active_server_id = 0;
        std::chrono::steady_clock::time_point next_probe{};
        std::unordered_map<uint32_t, PoolMemberState> members;
    };
    struct CacheEntry {
        Packet packet;
        DnsAnswer parsed;
        std::chrono::steady_clock::time_point stored, expires;
        uint32_t used_server_id = 0;
        std::list<std::string>::iterator lru_it;
    };
    struct Pending {
        bool done = false;
        Packet packet;
        DnsAnswer parsed;
        uint32_t used_server_id = 0;
        std::string error_code, error_message;
        std::condition_variable changed;
    };

public:
    struct Snapshot {
        explicit Snapshot(Config value)
            : config(std::move(value)), compiled_rules(compile_rules(config)),
              options(compiled_rules.options) {
            for (const auto& pool : config.pools) {
                auto& state = pool_states[pool.id];
                for (const auto sid : pool.server_ids)
                    state.members.try_emplace(sid);
            }
        }
        Snapshot(const Snapshot&) = delete;
        Snapshot& operator=(const Snapshot&) = delete;
        Config config;
        CompiledRules compiled_rules;
        RuntimeOptions options;

    private:
        friend class Router;
        mutable std::mutex pool_mutex;
        mutable std::unordered_map<uint32_t, PoolRuntimeState> pool_states;
        mutable std::mutex cache_mutex;
        mutable std::list<std::string> cache_lru;
        mutable std::unordered_map<std::string, CacheEntry> cache;
        mutable size_t cache_bytes = 0;
        mutable std::unordered_map<std::string, std::shared_ptr<Pending>> pending;
    };
    using SnapshotPtr = std::shared_ptr<const Snapshot>;
    explicit Router(Config config, Logger& logger);
    ~Router();
    SnapshotPtr snapshot() const;
    void reload(Config config) const;
    void cancel_pending() const;
    void resume() const;
    void start_pool_monitor() const;
    void stop_pool_monitor() const;
    void probe_redundancy_pools_now() const;
    std::vector<PoolStatusSnapshot> pool_statuses() const;
    RouteResult route(const Packet& request, const Server& original) const;
    RouteResult route(const Packet& request,
                      const Server& original,
                      SnapshotPtr snapshot,
                      std::optional<Question> pre_parsed = std::nullopt,
                      std::optional<RuleDecision> pre_decision = std::nullopt) const;
    Packet exchange(const Packet& request, const Server& server) const;
    RoutingStatistics statistics() const;

private:
    enum class ExchangeSource { upstream, cache, coalesced };
    struct ExchangeResult {
        Packet packet;
        DnsAnswer parsed;
        uint32_t used_server_id = 0;
        ExchangeSource source = ExchangeSource::upstream;
    };
    std::pair<Packet, const Server*> exchange_pool(const Snapshot& snapshot,
                                                   const Packet& request,
                                                   const ServerPool& pool,
                                                   const NetworkRoute& route) const;
    ExchangeResult exchange_cached(const Snapshot& snapshot,
                                   const Packet& request,
                                   const Question& question,
                                   const Server& primary,
                                   bool configured,
                                   const ServerPool* pool = nullptr) const;
    void probe_pool(const Snapshot& snapshot, const ServerPool& pool) const;
    void pool_monitor_loop() const;
    Logger& logger_;
    mutable std::atomic<SnapshotPtr> snapshot_;
    mutable std::atomic<std::shared_ptr<std::stop_source>> cancellation_{
        std::make_shared<std::stop_source>()};
    mutable std::mutex transport_mutex_;
    mutable std::array<std::shared_ptr<IDnsTransport>, 8> transports_;
    mutable std::mutex monitor_mutex_;
    mutable std::condition_variable monitor_cv_;
    mutable bool monitor_running_ = false;
    mutable std::jthread monitor_thread_;
    struct Counters {
        std::atomic_uint64_t queries_completed{0}, rules_evaluated{0}, blocked{0}, bypassed{0};
        std::atomic_uint64_t parse_errors{0}, route_errors{0};
        std::atomic_uint64_t negative_replies{0}, upstream_error_rcodes{0};
        std::atomic_uint64_t upstream_attempts{0}, upstream_replies{0}, upstream_errors{0};
    };
    mutable Counters counters_;
};
} // namespace nd
