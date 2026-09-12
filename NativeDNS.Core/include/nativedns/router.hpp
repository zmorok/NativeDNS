#pragma once
#include <nativedns/dns.hpp>
#include <array>
#include <mutex>
#include <optional>
#include <map>
#include <condition_variable>
namespace nd {
enum class Disposition { reply, forward_original, silent_drop };
struct RouteResult {
    Disposition disposition = Disposition::reply;
    Packet packet;
    uint32_t rule_id = 0, server_id = 0;
    Action action = Action::process;
    std::string error_code, message;
};
std::string route_log_message(const Question& question, const Rule& rule, const Server* server,
                              std::optional<double> elapsed_ms = std::nullopt);
// Immutable validated configuration. Original destination belongs to the interception backend.
class Router {
public:
    explicit Router(Config config, Logger& logger);
    RouteResult route(const Packet& request, const Server& original) const;
    Packet exchange(const Packet& request, const Server& server) const;
private:
    struct Health {
        unsigned consecutive_failures=0;
        std::chrono::steady_clock::time_point retry_after{};
        std::optional<double> latency_ms;
    };
    struct CacheEntry { Packet packet;std::chrono::steady_clock::time_point stored,expires;uint32_t used_server_id=0; };
    struct Pending { bool done=false;Packet packet;uint32_t used_server_id=0;std::string error_code,error_message;std::condition_variable changed; };
    std::pair<Packet,const Server*> exchange_group(const Packet& request,const Server& primary) const;
    std::pair<Packet,uint32_t> exchange_cached(const Packet& request,const Server& primary,bool configured) const;
    Config config_;
    Logger& logger_;
    mutable std::array<std::once_flag,8> transport_once_;
    mutable std::array<std::unique_ptr<IDnsTransport>,8> transports_;
    mutable std::mutex health_mutex_;
    mutable std::map<uint32_t,Health> health_;
    mutable std::mutex cache_mutex_;
    mutable std::map<std::string,CacheEntry> cache_;
    mutable std::map<std::string,std::shared_ptr<Pending>> pending_;
};
}
