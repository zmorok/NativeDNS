#pragma once
#include <nativedns/router.hpp>

namespace nd::detail {

// Receives TCP connections reflected by WinDivert. The reflected peer address
// is the original DNS destination, so Process/0 and Bypass retain that endpoint.
class TcpDnsProxy final {
public:
    TcpDnsProxy(const Router& router, Logger& logger, uint16_t intercepted_port = 53);
    ~TcpDnsProxy();
    uint16_t start();
    void stop();
    void expect_connection(std::string original_ip, uint16_t client_port);
    void forget_connection(const std::string& original_ip, uint16_t client_port);
    TcpDnsProxy(const TcpDnsProxy&) = delete;
    TcpDnsProxy& operator=(const TcpDnsProxy&) = delete;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace nd::detail
