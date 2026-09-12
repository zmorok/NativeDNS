#pragma once
#include <nativedns/dns.hpp>
#include <array>
#include <mutex>
#include <optional>
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
    Config config_;
    Logger& logger_;
    mutable std::array<std::once_flag,8> transport_once_;
    mutable std::array<std::unique_ptr<IDnsTransport>,8> transports_;
};
}
