#pragma once
#include <nativedns/config.hpp>
#include <nativedns/logger.hpp>
#include <string_view>

namespace nd {
struct PreflightFinding {
    Level level = Level::normal;
    std::string code, message;
};
// SHA-256 of the canonical serialized config, not of XML whitespace/formatting.
std::string configuration_fingerprint(const Config& config);
// Inspect only: an external override must never be silently deleted.
std::vector<PreflightFinding> inspect_hosts_overrides(const Config& config,
                                                     const NetworkSnapshot& network,
                                                     std::string_view contents);
std::vector<PreflightFinding> inspect_network_environment(const Config& config,
                                                         const NetworkSnapshot& network);
namespace platform {
std::filesystem::path system_hosts_path();
std::vector<PreflightFinding> dns_environment_findings(const NetworkSnapshot& network);
} // namespace platform
} // namespace nd
