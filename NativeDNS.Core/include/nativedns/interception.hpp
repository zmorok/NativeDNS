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
// Mechanism state and end-to-end verification are deliberately independent.
struct InterceptionTestResult {
    bool in_progress = false;
    bool sent = false, captured = false, parsed = false, injected = false, received = false;
    uint64_t timestamp_ms = 0;
    uint32_t interface_index = 0;
    std::string failure_stage = "NOT_RUN", message;
    bool success() const {
        return !in_progress && sent && captured && parsed && injected && received;
    }
};
struct InterceptionDiagnostics {
    bool supported = false, library_loaded = false, handle_open = false, receiver_active = false;
    int priority = 123;
    std::string health = "UNVERIFIED", filter;
    uint64_t packets_received = 0, udp_dns_captured = 0, tcp_dns_captured = 0;
    uint64_t dns_parse_errors = 0, rules_evaluated = 0, queries_processed = 0;
    uint64_t queries_bypassed = 0, queries_blocked = 0, upstream_bypassed = 0;
    uint64_t packets_injected = 0, send_errors = 0, receive_errors = 0;
    uint64_t worker_queue_overflows = 0, processing_errors = 0, last_capture_timestamp = 0;
    uint64_t negative_replies = 0, upstream_error_rcodes = 0;
    uint64_t active_workers = 0, queued_jobs = 0, queued_bytes = 0;
    uint64_t upstream_attempts = 0, upstream_replies = 0, upstream_errors = 0;
    InterceptionTestResult last_test;
};
std::string format_interception_test(const InterceptionTestResult& value);
std::string format_interception_diagnostics(const InterceptionDiagnostics& value);
class IInterceptionProvider {
public:
    virtual ~IInterceptionProvider() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void cancel_pending() = 0;
    virtual void reload(Config config) = 0;
    virtual InterceptionStatus status() const = 0;
    virtual InterceptionDiagnostics diagnostics() const {
        return {};
    }
    virtual InterceptionTestResult self_test() {
        throw Error("NOT_SUPPORTED",
                    "Active interception test is available for Windows UDP/IPv4 only");
    }
    virtual std::vector<PoolStatusSnapshot> pool_statuses() const {
        return {};
    }
};

// Explicit loopback fallback. It is portable and does not modify system DNS.
class LocalProxy final : public IInterceptionProvider {
public:
    LocalProxy(std::shared_ptr<const Router> router,
               Server original,
               Logger& logger,
               uint16_t port = 0);
    ~LocalProxy();
    void start() override;
    void stop() override;
    void cancel_pending() override;
    void reload(Config config) override;
    InterceptionStatus status() const override;
    std::vector<PoolStatusSnapshot> pool_statuses() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Creates the native transparent interception backend for the current OS:
// WinDivert on Windows; nftables redirect backend on Linux.
std::unique_ptr<IInterceptionProvider>
make_platform_interception(Config config, Logger& logger, uint16_t intercepted_dns_port = 53);

#ifdef _WIN32
class WinDivertInterception final : public IInterceptionProvider {
public:
    WinDivertInterception(Config config, Logger& logger, uint16_t intercepted_tcp_port = 53);
    ~WinDivertInterception();
    void start() override;
    void stop() override;
    void cancel_pending() override;
    void reload(Config config) override;
    InterceptionStatus status() const override;
    InterceptionDiagnostics diagnostics() const override;
    InterceptionTestResult self_test() override;
    std::vector<PoolStatusSnapshot> pool_statuses() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

Packet make_intercepted_udp_response(const Packet& captured, const Packet& dns_response);
Packet make_intercepted_tcp_reset(const Packet& captured);
Packet make_reflected_tcp_packet(const Packet& captured,
                                 uint16_t proxy_port,
                                 bool toward_proxy,
                                 uint16_t intercepted_port = 53);
// Returns true only when the captured UDP DNS query can be safely reinjected
// without entering the bounded routing worker queue.
bool should_reinject_udp_immediately(const Config& config, const Packet& captured);
bool is_transient_windivert_send_error(uint32_t win32_error);
std::string windivert_filter(bool intercept_others, uint16_t target, uint16_t proxy);
#endif
} // namespace nd
