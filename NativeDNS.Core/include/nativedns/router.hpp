#pragma once
#include <nativedns/dns.hpp>
#include <array>
#include <mutex>
#include <optional>
#include <map>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <stop_token>
namespace nd {
enum class Disposition { reply, forward_original, silent_drop };
struct RouteResult {
    Disposition disposition = Disposition::reply;
    Packet packet;
    uint32_t rule_id = 0, server_id = 0;
    Action action = Action::process;
    std::string error_code, message;
};
std::string route_log_message(const Question& question,
                              const Rule& rule,
                              const Server* server,
                              std::optional<double> elapsed_ms = std::nullopt);
// Each DNS query retains one validated configuration snapshot. Original destination belongs to
// the interception backend.
class Router {
private:
    struct Health {
        unsigned consecutive_failures = 0;
        std::chrono::steady_clock::time_point retry_after{};
        std::optional<double> latency_ms;
    };
    struct CacheEntry {
        Packet packet;
        std::chrono::steady_clock::time_point stored, expires;
        uint32_t used_server_id = 0;
    };
    struct Pending {
        bool done = false;
        Packet packet;
        uint32_t used_server_id = 0;
        std::string error_code, error_message;
        std::condition_variable changed;
    };

public:
    struct Snapshot {
        explicit Snapshot(Config value) : config(std::move(value)) {
        }
        Config config;

    private:
        friend class Router;
        mutable std::mutex health_mutex;
        mutable std::map<std::string, Health> health;
        mutable std::mutex cache_mutex;
        mutable std::map<std::string, CacheEntry> cache;
        mutable size_t cache_bytes = 0;
        mutable std::map<std::string, std::shared_ptr<Pending>> pending;
    };
    using SnapshotPtr = std::shared_ptr<const Snapshot>;
    explicit Router(Config config, Logger& logger);
    SnapshotPtr snapshot() const;
    void reload(Config config) const;
    void cancel_pending() const;
    void resume() const;
    RouteResult route(const Packet& request, const Server& original) const;
    RouteResult route(const Packet& request, const Server& original, SnapshotPtr snapshot) const;
    Packet exchange(const Packet& request, const Server& server) const;

private:
    std::pair<Packet, const Server*>
    exchange_group(const Snapshot& snapshot, const Packet& request, const Server& primary) const;
    std::pair<Packet, uint32_t> exchange_cached(const Snapshot& snapshot,
                                                const Packet& request,
                                                const Server& primary,
                                                bool configured) const;
    Logger& logger_;
    mutable std::atomic<SnapshotPtr> snapshot_;
    mutable std::atomic<std::shared_ptr<std::stop_source>> cancellation_{
        std::make_shared<std::stop_source>()};
    mutable std::mutex transport_mutex_;
    mutable std::array<std::shared_ptr<IDnsTransport>, 8> transports_;
};
} // namespace nd
