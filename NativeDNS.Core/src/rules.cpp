#include <nativedns/config.hpp>
#include <nativedns/dnscrypt.hpp>
#include <nativedns/platform.hpp>
#include <algorithm>
#include <functional>
#include <set>

namespace nd {
namespace {
std::vector<uint32_t> decode_utf8(const std::string& text) {
    std::vector<uint32_t> out;
    for (size_t i = 0; i < text.size();) {
        const uint8_t c = static_cast<uint8_t>(text[i]);
        uint32_t cp = 0;
        size_t extra = 0;
        if (c < 0x80) {
            cp = c;
            extra = 0;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F;
            extra = 1;
            if (cp < 2)
                throw Error("UTF8", "Overlong UTF-8");
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F;
            extra = 2;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07;
            extra = 3;
        } else
            throw Error("UTF8", "Invalid UTF-8 leading byte");
        if (i + extra >= text.size())
            throw Error("UTF8", "Truncated UTF-8");
        for (size_t j = 1; j <= extra; ++j) {
            const uint8_t b = static_cast<uint8_t>(text[i + j]);
            if ((b & 0xC0) != 0x80)
                throw Error("UTF8", "Invalid UTF-8 continuation byte");
            cp = (cp << 6) | (b & 0x3F);
        }
        if ((extra == 2 && cp < 0x800) || (extra == 3 && cp < 0x10000) || cp > 0x10FFFF ||
            (cp >= 0xD800 && cp <= 0xDFFF))
            throw Error("UTF8", "Invalid UTF-8 code point");
        out.push_back(cp);
        i += extra + 1;
    }
    return out;
}
void append_utf8(std::string& out, uint32_t cp) {
    if (cp <= 0x7F)
        out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}
std::string normalize_ascii_name(const std::string& text, bool pattern, bool hostname) {
    auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        throw Error("HOST", "Empty DNS name");
    std::string value = text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
    if (value.back() == '.')
        value.pop_back();
    if (value.empty())
        throw Error("HOST", "Empty DNS name");
    std::string result;
    size_t start = 0;
    while (start < value.size()) {
        const auto end = value.find('.', start);
        auto label =
            value.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (label.empty())
            throw Error("HOST", "Empty DNS label");
        if (label.size() > 63)
            throw Error("HOST", "DNS label exceeds 63 bytes");
        for (char& character : label) {
            const auto byte = static_cast<unsigned char>(character);
            if (character >= 'A' && character <= 'Z')
                character = static_cast<char>(character + ('a' - 'A'));
            const bool wildcard = pattern && (character == '*' || character == '?');
            const bool ldh = (character >= 'a' && character <= 'z') ||
                             (character >= '0' && character <= '9') || character == '-';
            if (hostname && !ldh && !wildcard)
                throw Error("HOST", "Hostname must use canonical ASCII A-label syntax");
            if (!hostname && (byte <= 32 || byte >= 127 || character == '.' ||
                              (!pattern && (character == '*' || character == '?'))))
                throw Error("HOST", "Unsupported DNS label character");
        }
        if (hostname && (label.front() == '-' || label.back() == '-'))
            throw Error("HOST", "Hyphen at DNS label boundary");
        if (!result.empty())
            result += '.';
        result += label;
        if (end == std::string::npos)
            break;
        start = end + 1;
        if (start == value.size())
            throw Error("HOST", "Multiple trailing dots");
    }
    if (result.size() > 253)
        throw Error("HOST", "DNS name exceeds 253 bytes");
    return result;
}
} // namespace
std::wstring widen(const std::string& text) {
    if (text.size() > 4 * 1024 * 1024)
        throw Error("INPUT_LIMIT", "Text exceeds limit");
    const auto cps = decode_utf8(text);
    std::wstring out;
    for (auto cp : cps) {
        if constexpr (sizeof(wchar_t) == 2) {
            if (cp <= 0xFFFF)
                out.push_back(static_cast<wchar_t>(cp));
            else {
                cp -= 0x10000;
                out.push_back(static_cast<wchar_t>(0xD800 + (cp >> 10)));
                out.push_back(static_cast<wchar_t>(0xDC00 + (cp & 0x3FF)));
            }
        } else
            out.push_back(static_cast<wchar_t>(cp));
    }
    return out;
}
std::string narrow(const std::wstring& text) {
    if (text.size() > 4 * 1024 * 1024)
        throw Error("INPUT_LIMIT", "Text exceeds limit");
    std::string out;
    for (size_t i = 0; i < text.size(); ++i) {
        uint32_t cp = static_cast<uint32_t>(text[i]);
        if constexpr (sizeof(wchar_t) == 2) {
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (i + 1 >= text.size())
                    throw Error("UTF8", "Invalid UTF-16");
                const uint32_t lo = static_cast<uint32_t>(text[++i]);
                if (lo < 0xDC00 || lo > 0xDFFF)
                    throw Error("UTF8", "Invalid UTF-16");
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF)
                throw Error("UTF8", "Invalid UTF-16");
        }
        append_utf8(out, cp);
    }
    return out;
}
std::string normalize_host(const std::string& text, bool pattern) {
    return normalize_ascii_name(text, pattern, true);
}
std::string normalize_dns_name(const std::string& text, bool pattern) {
    return normalize_ascii_name(text, pattern, false);
}
std::vector<std::string> split_patterns(const std::string& text) {
    std::vector<std::string> result;
    size_t begin = 0;
    while (begin < text.size()) {
        auto end = text.find_first_of(";\r\n", begin);
        const auto value =
            text.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
        if (value.find_first_not_of(" \t") != std::string::npos)
            result.push_back(normalize_dns_name(value, true));
        if (end == std::string::npos)
            break;
        begin = end + 1;
    }
    return result;
}
bool host_matches(const std::string& host, const std::string& pattern) {
    size_t h = 0, p = 0, star = std::string::npos, retry = 0;
    while (h < host.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || pattern[p] == host[h])) {
            ++h;
            ++p;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            retry = h;
        } else if (star != std::string::npos) {
            p = star + 1;
            h = ++retry;
        } else
            return false;
    }
    while (p < pattern.size() && pattern[p] == '*')
        ++p;
    return p == pattern.size();
}
std::string protocol_name(Protocol value) {
    switch (value) {
        case Protocol::udp:
            return "udp";
        case Protocol::tcp:
            return "tcp";
        case Protocol::doh:
            return "doh";
        case Protocol::dot:
            return "dot";
        case Protocol::doh3:
            return "doh3";
        case Protocol::doq:
            return "doq";
        case Protocol::dnscrypt:
            return "dnscrypt";
        case Protocol::anonymized_dnscrypt:
            return "anonymized_dnscrypt";
    }
    throw Error("PROTOCOL", "Unknown protocol");
}
std::string action_name(Action value) {
    switch (value) {
        case Action::process:
            return "process";
        case Action::bypass:
            return "bypass";
        case Action::block:
            return "block";
    }
    throw Error("ACTION", "Unknown action");
}
void validate(const Config& config) {
    if (config.schema_version != 1)
        throw Error("SCHEMA", "Unsupported schema version");
    if (config.servers.size() > 4096 || config.rules.empty() || config.rules.size() > 4096)
        throw Error("CONFIG_LIMIT", "Configuration count limit or missing Default");
    if (!config.test_concurrency || config.test_concurrency > 64)
        throw Error("CONFIG", "Test concurrency must be 1..64");
    (void)normalize_host(config.test_target);
    if (config.logging.screen > Level::debug || config.logging.file > Level::debug)
        throw Error("CONFIG", "Invalid log level");
    std::set<uint32_t> ids;
    for (const auto& server : config.servers) {
        if (!server.id || !ids.insert(server.id).second || server.name.empty())
            throw Error("SERVER_ID", "Missing/duplicate server ID or name");
        (void)protocol_name(server.protocol);
        if (!server.timeout_ms || server.timeout_ms > 120000)
            throw Error("CONFIG", "Timeout must be 1..120000 ms");
        if (!server.ip.empty()) {
            if (!platform::is_numeric_ip(server.ip))
                throw Error("ENDPOINT", "Server IP must be a numeric IPv4/IPv6 address");
        }
        if ((server.protocol == Protocol::udp || server.protocol == Protocol::tcp) &&
            server.ip.empty())
            throw Error("ENDPOINT", "Plain server requires IP");
        if (server.protocol == Protocol::dnscrypt ||
            server.protocol == Protocol::anonymized_dnscrypt) {
            validate_dnscrypt_server(server);
        }
        if (server.allow_direct_certificate_fallback &&
            server.protocol != Protocol::anonymized_dnscrypt)
            throw Error("CONFIG",
                        "Direct certificate fallback applies only to Anonymized DNSCrypt");
        if (server.protocol == Protocol::dot || server.protocol == Protocol::doq)
            (void)normalize_host(server.hostname);
        if (server.protocol == Protocol::doh || server.protocol == Protocol::doh3) {
            if (!server.url.starts_with("https://") ||
                server.url.find_first_of("\r\n\t ") != std::string::npos ||
                server.url.find('@') != std::string::npos)
                throw Error("ENDPOINT", "DoH requires HTTPS URL without credentials or whitespace");
            auto authority = server.url.substr(8,
                                               server.url.find('/', 8) == std::string::npos
                                                   ? std::string::npos
                                                   : server.url.find('/', 8) - 8);
            if (authority.empty())
                throw Error("ENDPOINT", "Empty DoH host");
        }
        std::set<uint32_t> fallbacks;
        for (const auto fallback : server.fallback_ids)
            if (!fallback || fallback == server.id || !fallbacks.insert(fallback).second)
                throw Error(
                    "SERVER_FALLBACK",
                    "Fallback IDs must be nonzero, unique, and different from the primary server");
    }
    std::map<uint32_t, const Server*> servers;
    for (const auto& server : config.servers)
        servers.emplace(server.id, &server);
    for (const auto& server : config.servers)
        for (const auto fallback : server.fallback_ids)
            if (!servers.contains(fallback))
                throw Error("SERVER_FALLBACK", "Fallback references a missing server");
    std::set<uint32_t> visiting, visited;
    std::function<void(uint32_t)> visit = [&](uint32_t id) {
        if (visited.contains(id))
            return;
        if (!visiting.insert(id).second)
            throw Error("SERVER_FALLBACK", "Fallback graph contains a cycle");
        for (const auto fallback : servers.at(id)->fallback_ids)
            visit(fallback);
        visiting.erase(id);
        visited.insert(id);
    };
    for (const auto& server : config.servers)
        visit(server.id);
    std::set<uint32_t> rule_ids;
    for (size_t i = 0; i < config.rules.size(); ++i) {
        const auto& rule = config.rules[i];
        if (!rule.id || !rule_ids.insert(rule.id).second || rule.name.empty())
            throw Error("RULE_ID", "Missing/duplicate rule ID or name");
        (void)action_name(rule.action);
        if (rule.block_mode > BlockMode::silent_drop)
            throw Error("CONFIG", "Invalid block mode");
        if (rule.is_default != (i == config.rules.size() - 1))
            throw Error("DEFAULT", "Exactly one Default must be last");
        if (rule.is_default && (!rule.enabled || rule.patterns != std::vector<std::string>{"*"}))
            throw Error("DEFAULT", "Default must be enabled and match all");
        if (rule.patterns.empty() || rule.patterns.size() > 4096)
            throw Error("PATTERN", "Missing or excessive patterns");
        for (const auto& pattern : rule.patterns)
            (void)normalize_dns_name(pattern, true);
        if (rule.action == Action::process && rule.server_id && !ids.contains(rule.server_id))
            throw Error("SERVER_REFERENCE", "Rule references missing server");
        if (rule.action != Action::process && rule.server_id)
            throw Error("SERVER_REFERENCE", "Non-Process rule cannot select server");
    }
}
const Rule& match_rule(const Config& config, const std::string& hostname) {
    const auto host = normalize_dns_name(hostname);
    for (const auto& rule : config.rules) {
        if (!rule.enabled)
            continue;
        for (const auto& pattern : rule.patterns)
            if (host_matches(host, normalize_dns_name(pattern, true)))
                return rule;
    }
    throw Error("DEFAULT", "No matching rule: invalid configuration");
}
ConfigEditor::ConfigEditor(Config config) : config_(std::move(config)) {
    validate(config_);
}
void ConfigEditor::commit(Config next) {
    validate(next);
    config_ = std::move(next);
}
void ConfigEditor::add_rule(Rule rule) {
    auto next = config_;
    next.rules.insert(next.rules.end() - 1, std::move(rule));
    commit(std::move(next));
}
void ConfigEditor::update_rule(Rule rule) {
    auto next = config_;
    auto it = std::find_if(
        next.rules.begin(), next.rules.end(), [&](const Rule& r) { return r.id == rule.id; });
    if (it == next.rules.end() || it->is_default != rule.is_default)
        throw Error("RULE_ID", "Rule not found or Default identity changed");
    *it = std::move(rule);
    commit(std::move(next));
}
void ConfigEditor::remove_rule(uint32_t id) {
    auto next = config_;
    auto it = std::find_if(
        next.rules.begin(), next.rules.end(), [&](const Rule& r) { return r.id == id; });
    if (it == next.rules.end() || it->is_default)
        throw Error("DEFAULT", "Cannot remove missing/Default rule");
    next.rules.erase(it);
    commit(std::move(next));
}
void ConfigEditor::move_rule(uint32_t id, int direction) {
    auto next = config_;
    auto it = std::find_if(
        next.rules.begin(), next.rules.end(), [&](const Rule& r) { return r.id == id; });
    if (direction != -1 && direction != 1)
        throw Error("ORDER", "Direction must be -1 or 1");
    if (it == next.rules.end() || it->is_default || (direction < 0 && it == next.rules.begin()) ||
        (direction > 0 && (it + 1)->is_default))
        throw Error("ORDER", "Cannot move rule beyond ordered boundary");
    std::iter_swap(it, it + direction);
    commit(std::move(next));
}
void ConfigEditor::clone_rule(uint32_t source_id, uint32_t new_id) {
    auto it = std::find_if(config_.rules.begin(), config_.rules.end(), [&](const Rule& r) {
        return r.id == source_id;
    });
    if (it == config_.rules.end())
        throw Error("RULE_ID", "Rule not found");
    Rule rule = *it;
    rule.id = new_id;
    rule.is_default = false;
    rule.name += " (copy)";
    add_rule(std::move(rule));
}
void ConfigEditor::add_server(Server server) {
    auto next = config_;
    next.servers.push_back(std::move(server));
    commit(std::move(next));
}
void ConfigEditor::update_server(Server server) {
    auto next = config_;
    auto it = std::find_if(next.servers.begin(), next.servers.end(), [&](const Server& s) {
        return s.id == server.id;
    });
    if (it == next.servers.end())
        throw Error("SERVER_ID", "Server not found");
    *it = std::move(server);
    commit(std::move(next));
}
void ConfigEditor::remove_server(uint32_t id) {
    auto next = config_;
    if (!std::erase_if(next.servers, [&](const Server& s) { return s.id == id; }))
        throw Error("SERVER_ID", "Server not found");
    commit(std::move(next));
}
} // namespace nd
