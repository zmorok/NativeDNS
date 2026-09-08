#pragma once
#include <nativedns/router.hpp>
namespace nd {
enum class State { stopped, starting, running, stopping, error };
struct InterceptionStatus {
    State state = State::stopped;
    uint16_t port = 0;
    bool transparent = false;
    bool udp = false;
    bool tcp = false;
    std::string error_code, error_message;
};
class IInterceptionProvider {
public:
    virtual ~IInterceptionProvider() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual InterceptionStatus status() const = 0;
};

// Explicit loopback fallback. It is portable and does not modify system DNS.
class LocalProxy final : public IInterceptionProvider {
public:
    LocalProxy(std::shared_ptr<const Router> router, Server original, Logger& logger, uint16_t port = 0);
    ~LocalProxy();
    void start() override;
    void stop() override;
    InterceptionStatus status() const override;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Creates the native transparent interception backend for the current OS:
// WinDivert on Windows; nftables redirect backend on Linux.
std::unique_ptr<IInterceptionProvider> make_platform_interception(Config config, Logger& logger,
                                                                  uint16_t intercepted_dns_port = 53);

#ifdef _WIN32
class WinDivertInterception final : public IInterceptionProvider {
public:
    WinDivertInterception(Config config, Logger& logger, uint16_t intercepted_tcp_port = 53);
    ~WinDivertInterception();
    void start() override;
    void stop() override;
    InterceptionStatus status() const override;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

Packet make_intercepted_udp_response(const Packet& captured, const Packet& dns_response);
Packet make_reflected_tcp_packet(const Packet& captured, uint16_t proxy_port, bool toward_proxy,
                                 uint16_t intercepted_port = 53);
#endif
}
