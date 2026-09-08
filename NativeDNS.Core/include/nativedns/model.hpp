#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace nd {
enum class Protocol { udp, tcp, doh, dot, doh3, doq, dnscrypt, anonymized_dnscrypt };
enum class Action { process, bypass, block };
enum class BlockMode { zero_address, nxdomain, refused, silent_drop };
enum class Level { errors_only, normal, verbose, debug };
struct Server {
    uint32_t id = 0;
    std::string name;
    bool enabled = true;
    Protocol protocol = Protocol::udp;
    std::string ip, hostname, url;
    uint16_t port = 0; // transport default
    bool dnssec_supported = false;
    uint32_t timeout_ms = 3000;
    std::vector<std::string> bootstrap, hashes;
    std::string public_key, provider_name, relay;
    std::map<std::string, std::string> metadata;
    bool operator==(const Server&) const = default;
};
struct Rule {
    uint32_t id = 0;
    std::string name;
    bool enabled = true, is_default = false;
    std::vector<std::string> patterns;
    Action action = Action::process;
    uint32_t server_id = 0; // original/system destination; NOT bypass action
    std::string interface_id;
    bool dnssec_validate = false, dnssec_reject_unsigned = false;
    BlockMode block_mode = BlockMode::zero_address;
    std::map<std::string, std::string> metadata;
    bool operator==(const Rule&) const = default;
};
struct LoggingSettings {
    Level screen = Level::normal, file = Level::normal;
    bool file_enabled = false;
    std::string directory = "logs";
    bool operator==(const LoggingSettings&) const = default;
};
struct Config {
    uint32_t schema_version = 1;
    std::vector<Server> servers;
    std::vector<Rule> rules;
    LoggingSettings logging;
    std::string test_target = "iana.org";
    uint32_t test_concurrency = 15;
    std::map<std::string, std::string> settings;
    bool operator==(const Config&) const = default;
};
inline Config default_config() {
    Config config;
    Rule rule;
    rule.id = 1;
    rule.name = "Default";
    rule.is_default = true;
    rule.patterns = {"*"};
    config.rules.push_back(rule);
    return config;
}
}
