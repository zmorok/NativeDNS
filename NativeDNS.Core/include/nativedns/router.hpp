#pragma once
#include <nativedns/dns.hpp>
namespace nd {
enum class Disposition { reply, forward_original, silent_drop };
struct RouteResult {
    Disposition disposition = Disposition::reply;
    Packet packet;
    uint32_t rule_id = 0, server_id = 0;
    Action action = Action::process;
    std::string error_code, message;
};
// Immutable validated configuration. Original destination belongs to the interception backend.
class Router {
public:
    explicit Router(Config config, Logger& logger);
    RouteResult route(const Packet& request, const Server& original) const;
private:
    Config config_;
    Logger& logger_;
};
}
