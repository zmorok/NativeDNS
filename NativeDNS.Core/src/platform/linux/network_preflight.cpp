#include <nativedns/network_preflight.hpp>
#include <nativedns/network_preparation.hpp>

namespace nd::platform {
std::unique_ptr<NetworkPreparation> make_network_preparation() { return {}; }
std::filesystem::path system_hosts_path() {
    return "/etc/hosts";
}
std::vector<PreflightFinding> dns_environment_findings(const NetworkSnapshot&) {
    return {{Level::normal, "DNS_PREFLIGHT_OS",
             "System resolver encryption and application Secure DNS require separate inspection"}};
}
} // namespace nd::platform
