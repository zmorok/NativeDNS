#include <nativedns/network_preflight.hpp>
#include <nativedns/platform.hpp>
#include <fstream>
#include <sstream>
#include <set>
#include <sodium.h>

namespace nd {
std::string routing_fingerprint(const Config& config) {
    auto routing = config;
    routing.logging = {};
    routing.test_target = "iana.org";
    routing.test_concurrency = 15;
    // Preserve all network settings and metadata, including unknown future ones.
    return configuration_fingerprint(routing);
}
std::string configuration_fingerprint(const Config& config) {
    const auto text = serialize_config(config);
    unsigned char digest[crypto_hash_sha256_BYTES]{};
    crypto_hash_sha256(digest, reinterpret_cast<const unsigned char*>(text.data()), text.size());
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : digest) {
        result += hex[byte >> 4];
        result += hex[byte & 15];
    }
    return result;
}
std::vector<PreflightFinding> inspect_hosts_overrides(const Config& config,
                                                     const NetworkSnapshot& network,
                                                     std::string_view contents) {
    if (contents.size() > 4 * 1024 * 1024)
        throw Error("DNS_PREFLIGHT_HOSTS", "Hosts file exceeds the 4 MiB inspection limit");
    if (contents.starts_with("\xEF\xBB\xBF"))
        contents.remove_prefix(3);
    if (contents.find('\0') != std::string_view::npos)
        throw Error("DNS_PREFLIGHT_HOSTS", "Hosts file contains NUL bytes; inspect its encoding");
    std::vector<PreflightFinding> result;
    auto snapshot = std::make_shared<NetworkSnapshot>(network);
    std::istringstream input{std::string(contents)};
    std::string line;
    size_t number = 0, names = 0;
    std::set<std::string> reported;
    while (std::getline(input, line)) {
        ++number;
        line.erase(line.find('#') == std::string::npos ? line.size() : line.find('#'));
        std::istringstream row(line);
        std::string address, host;
        if (!(row >> address))
            continue;
        if (!platform::is_numeric_ip(address)) continue;
        while (row >> host) {
            if (++names > 16384) {
                result.push_back({Level::errors_only, "DNS_PREFLIGHT_LIMIT",
                                  "Hosts inspection stopped after 16384 names"});
                return result;
            }
            std::string normalized;
            try {
                normalized = normalize_dns_name(host);
            } catch (const Error&) {
                continue;
            }
            const auto decision = evaluate_rule(config, normalized, snapshot);
            if (decision.rule->action == Action::bypass ||
                (decision.rule->action == Action::process && decision.rule->server_id == 0) ||
                !reported.insert(normalized).second)
                continue;
            result.push_back({Level::errors_only,
                              "DNS_HOSTS_OVERRIDE",
                              "name=" + normalized + " address=" + address +
                                  " line=" + std::to_string(number) +
                                  " rule_id=" + std::to_string(decision.rule->id) +
                                  " rule=\"" + decision.rule->name +
                                  "\"; System hosts resolution can answer before a DNS "
                                  "packet reaches NativeDNS. Review this hosts entry."});
            if (result.size() >= 128) {
                result.push_back({Level::errors_only, "DNS_PREFLIGHT_LIMIT",
                                  "Hosts inspection stopped after 128 matching names"});
                return result;
            }
        }
    }
    return result;
}
std::vector<PreflightFinding> inspect_network_environment(const Config& config,
                                                         const NetworkSnapshot& network) {
    auto result = platform::dns_environment_findings(network);
    if (!network.error.empty())
        result.push_back({Level::errors_only, "DNS_PREFLIGHT_NETWORK", network.error});
    for (const auto& info : network.interfaces) {
        if (!info.up || info.loopback || info.addresses.empty())
            continue;
        std::string details = "id=" + info.id + " name=\"" + info.name +
                              "\" index4=" + std::to_string(info.index4) +
                              " index6=" + std::to_string(info.index6);
        for (const auto& dns : info.dns_servers)
            details += " dns=" + dns;
        result.push_back({Level::normal, "DNS_PREFLIGHT_INTERFACE", std::move(details)});
    }
    try {
        const auto path = platform::system_hosts_path();
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            if (std::filesystem::exists(path))
                throw Error("DNS_PREFLIGHT_HOSTS", "Cannot read hosts file");
            result.push_back({Level::normal, "DNS_PREFLIGHT_HOSTS", "Hosts file is absent"});
        } else {
            // Bound allocation even for a file changing during inspection.
            std::string contents(4 * 1024 * 1024 + 1, '\0');
            input.read(contents.data(), static_cast<std::streamsize>(contents.size()));
            contents.resize(static_cast<size_t>(input.gcount()));
            if (input.bad())
                throw Error("DNS_PREFLIGHT_HOSTS", "Cannot finish reading hosts file");
            auto findings = inspect_hosts_overrides(config, network, contents);
            result.push_back({Level::normal, "DNS_PREFLIGHT_HOSTS",
                              "path=\"" + platform::path_to_utf8(path) + "\" overrides=" +
                                  std::to_string(findings.size())});
            result.insert(result.end(), findings.begin(), findings.end());
        }
    } catch (const std::exception& error) {
        result.push_back({Level::errors_only, "DNS_PREFLIGHT_HOSTS", error.what()});
    }
    result.push_back({Level::normal, "DNS_PREFLIGHT_SCOPE",
                      "NativeDNS intercepts UDP/TCP DNS on port 53. Browser/application Secure "
                      "DNS, VPN DNS and existing application caches can avoid this path. "
                      "An HTTPS DNS record type is still ordinary DNS, not proof of DoH. "
                      "Adapter DNS addresses are retained for Bypass and bootstrap."});
    return result;
}
} // namespace nd
