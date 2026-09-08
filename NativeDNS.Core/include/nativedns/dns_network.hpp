#pragma once
#include <nativedns/dns.hpp>
#include <chrono>

namespace nd::detail {
using NetworkClock = std::chrono::steady_clock;

class NetworkUpstreamGuard final {
public:
    NetworkUpstreamGuard(bool tcp, uint16_t local_port);
    ~NetworkUpstreamGuard();
    NetworkUpstreamGuard(const NetworkUpstreamGuard&) = delete;
    NetworkUpstreamGuard& operator=(const NetworkUpstreamGuard&) = delete;
private:
    bool tcp_;
    uint16_t local_port_;
};
bool is_network_upstream(bool tcp, uint16_t local_port);

// Sends one opaque datagram or one two-byte length-prefixed stream frame.
// The payload itself is never interpreted as DNS here.
Packet exchange_network(const Packet& request, const Server& server, bool tcp,
                        NetworkClock::time_point deadline);
}
