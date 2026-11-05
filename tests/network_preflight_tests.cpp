#include <nativedns/network_preflight.hpp>
#include <nativedns/platform.hpp>
#include <algorithm>
#include <iostream>
#ifdef NATIVEDNS_TEST_LEGACY_CODEPAGE
#include <windows.h>
#endif

namespace {
void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
}
int main(int argc, char** native_argv) {
    try {
#ifdef NATIVEDNS_TEST_LEGACY_CODEPAGE
        std::cout << "Test ANSI code page=" << GetACP() << '\n';
        if (GetACP() != 1251)
            return 77; // Locale manifests require Windows 11 / Server 2022.
#endif
        const auto args = nd::platform::command_line_arguments(argc, native_argv);
        if (args.size() == 2) {
            check(args[1] == "Кириллица 日本語 😀 path\\", "Unicode command line was corrupted");
            return 0;
        }
        auto config = nd::default_config();
        config.rules.back().action = nd::Action::bypass;
        nd::Rule custom;
        custom.id = 10;
        custom.name = "Проверка правил";
        custom.patterns = {"chatgpt.com", "*.chatgpt.com", "blocked.example"};
        custom.action = nd::Action::block;
        config.rules.insert(config.rules.begin(), custom);
        nd::NetworkSnapshot network;
        const auto inspect = [&](std::string_view text) {
            return nd::inspect_hosts_overrides(config, network, text);
        };
        const auto findings = inspect("\xEF\xBB\xBF# 127.0.0.1 chatgpt.com\r\n"
                                      "127.0.0.1 other.example CHATGPT.COM. # ignored.chatgpt.com\r\n"
                                      "::1 app.chatgpt.com blocked.example\n"
                                      "192.0.2.10 chatgpt.com\n"
                                      "not-an-ip invalid.chatgpt.com\n");
        check(findings.size() == 3, "Hosts aliases, comments, BOM, IPv6 or deduplication failed");
        check(findings[0].code == "DNS_HOSTS_OVERRIDE" &&
                  findings[0].level == nd::Level::errors_only &&
                  findings[0].message.find("name=chatgpt.com") != std::string::npos &&
                  findings[0].message.find("line=2") != std::string::npos,
              "Hosts conflict must identify the matched rule and line");
        config.rules.front().enabled = false;
        check(inspect("127.0.0.1 chatgpt.com").empty(), "Disabled rule caused a conflict");
        config.rules.front().enabled = true;
        config.rules.front().action = nd::Action::process;
        check(inspect("127.0.0.1 chatgpt.com").empty(), "Original-resolver Process was incorrectly reported as a hosts conflict");
        config.rules.front().action = nd::Action::block;
        check(inspect("127.0.0.1:53 chatgpt.com").empty(), "Invalid hosts address with a port was reported as an OS override");
        config.rules.front().interface_id = "absent";
        config.settings["ignore_rule_if_interface_down"] = "1";
        check(inspect("127.0.0.1 chatgpt.com").empty(), "Skipped interface rule caused a conflict");
        bool rejected = false;
        try { (void)inspect(std::string("127.0.0.1\0chatgpt.com", 21)); }
        catch (const nd::Error&) { rejected = true; }
        check(rejected, "Unsupported hosts encoding must be reported");
        rejected = false;
        try { (void)inspect(std::string(4 * 1024 * 1024 + 1, ' ')); }
        catch (const nd::Error&) { rejected = true; }
        check(rejected, "Hosts inspection must be bounded");
        const auto fingerprint = nd::configuration_fingerprint(config);
        check(fingerprint.size() == 64 &&
                  fingerprint == nd::configuration_fingerprint(nd::parse_config(nd::serialize_config(config))),
              "Config fingerprint must survive XML round trip");
        config.rules.front().patterns = {"different.example"};
        check(fingerprint != nd::configuration_fingerprint(config), "Config change has the same fingerprint");
        const auto text = "Кириллица 日本語 😀/NativeDNS.xml";
        const auto path = nd::platform::path_from_utf8(text);
        check(nd::platform::path_to_utf8(path) == text, "Unicode filesystem path was corrupted");
        std::cout << "network preflight passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
