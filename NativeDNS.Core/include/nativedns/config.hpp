#pragma once
#include <nativedns/model.hpp>
#include <filesystem>
#include <stdexcept>

namespace nd {
class Error : public std::runtime_error {
public:
    std::string code;
    Error(std::string error_code, std::string message)
        : std::runtime_error(std::move(message)), code(std::move(error_code)) {
    }
};
std::wstring widen(const std::string& text);
std::string narrow(const std::wstring& text);
std::string normalize_host(const std::string& text, bool pattern = false);
// Canonicalize the printable-ASCII DNS names supported by the wire/rules
// layer. Unlike a TLS/URL hostname, DNS labels may contain underscores and
// other service-label characters.
std::string normalize_dns_name(const std::string& text, bool pattern = false);
std::vector<std::string> split_patterns(const std::string& text);
bool host_matches(const std::string& normalized_host, const std::string& normalized_pattern);
void validate(const Config& config);
const Rule& match_rule(const Config& config, const std::string& hostname);
struct ImportResult {
    Config config;
    std::vector<std::string> warnings;
};
ImportResult import_yoga(const std::filesystem::path& path);
Config load_config(const std::filesystem::path& path);
Config parse_config(std::string text);
void save_config(const Config& config, const std::filesystem::path& path);
std::string serialize_config(const Config& config);
std::string protocol_name(Protocol protocol);
std::string action_name(Action action);
// Transactional mutations: validate candidate before replacing live snapshot.
class ConfigEditor {
public:
    explicit ConfigEditor(Config config);
    const Config& get() const {
        return config_;
    }
    void add_rule(Rule rule);
    void update_rule(Rule rule);
    void remove_rule(uint32_t id);
    void move_rule(uint32_t id, int direction);
    void clone_rule(uint32_t source_id, uint32_t new_id);
    void add_server(Server server);
    void update_server(Server server);
    void remove_server(uint32_t id);

private:
    void commit(Config next);
    Config config_;
};
} // namespace nd
