#pragma once
#include <nativedns/dns.hpp>
#include <chrono>
#include <string_view>

namespace nd::detail {
struct BootstrapResult {
    std::string endpoint;
    uint32_t ttl = 0;
    std::vector<std::string> endpoints;
};
bool is_dns_message_content_type(std::string_view header);
BootstrapResult resolve_bootstrap(const Server& server,
                                  const std::string& host,
                                  const std::vector<std::string>& resolvers,
                                  std::chrono::steady_clock::time_point deadline,
                                  IDnsTransport& transport);
} // namespace nd::detail
