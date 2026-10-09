#pragma once
#include <nativedns/dns.hpp>
#include <chrono>

namespace nd::detail {
struct BootstrapResult {
    std::string endpoint;
    uint32_t ttl = 0;
};
BootstrapResult resolve_bootstrap(const Server& server,
                                  const std::string& host,
                                  const std::vector<std::string>& resolvers,
                                  std::chrono::steady_clock::time_point deadline,
                                  IDnsTransport& transport);
} // namespace nd::detail
