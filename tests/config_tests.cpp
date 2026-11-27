#include <nativedns/config.hpp>
#include <nativedns/platform.hpp>
#include <fstream>
#include <iostream>
#include <functional>
#include <set>

void check(bool result, const char* message) {
    if (!result)
        throw std::runtime_error(message);
}
void fails(const std::function<void()>& fn) {
    try {
        fn();
    } catch (const nd::Error&) {
        return;
    }
    throw std::runtime_error("Expected structured failure");
}
void put(const std::filesystem::path& path, const std::string& text) {
    std::ofstream stream(path, std::ios::binary);
    stream << text;
}
int main() {
    try {
        {
            auto options_config = nd::default_config();
            options_config.settings["yoga.settings.clearDnsCache"] = "1";
            options_config.settings["ttlMin"] = "10";
            options_config.settings["yoga.settings.ttlMax"] = "60";
            options_config.settings["interceptOthers"] = "1";
            check(nd::runtime_options(options_config).windivert_priority == 123,
                  "Default WinDivert priority changed");
            for (const auto* value : {"-30000", "0", "123", "30000"}) {
                options_config.settings["windivertPriority"] = value;
                check(nd::runtime_options(options_config).windivert_priority == std::stoi(value),
                      "Priority not applied");
                check(nd::runtime_options(nd::parse_config(nd::serialize_config(options_config)))
                              .windivert_priority == std::stoi(value),
                      "Priority XML round trip");
            }
            for (const auto* value : {"-30001", "30001", "123x", "", "9999999999999999999"}) {
                options_config.settings["windivertPriority"] = value;
                bool invalid = false;
                try {
                    (void)nd::runtime_options(options_config);
                } catch (const nd::Error&) {
                    invalid = true;
                }
                check(invalid, "Invalid WinDivert priority accepted");
            }
            options_config.settings.erase("windivertPriority");
            const auto options = nd::runtime_options(options_config);
            check(options.clear_dns_cache && options.intercept_others && options.ttl_min == 10 &&
                      options.ttl_max == 60,
                  "Native and imported runtime options are executable");
            options_config.settings["clearDnsCache"] = "0";
            check(!nd::runtime_options(options_config).clear_dns_cache,
                  "Native option overrides imported value");
            for (const auto* bad : {"-1", "61", "2147483648", "10junk"}) {
                options_config.settings["ttlMin"] = bad;
                bool rejected = false;
                try {
                    nd::validate(options_config);
                } catch (const nd::Error& error) {
                    rejected = error.code == "CONFIG_SETTING";
                }
                check(rejected, "Invalid or inverted TTL interval rejected");
            }
        }
        const auto imported = nd::import_yoga(FIXTURE_PATH);
        const auto& config = imported.config;
        check(config.servers.size() == 6 && config.rules.size() == 16, "Fixture counts");
        std::set<uint32_t> ids;
        for (const auto& server : config.servers)
            ids.insert(server.id);
        check(ids == std::set<uint32_t>{1001, 1002, 1003, 1005, 1006, 1007}, "Server IDs");
        check(config.rules.back().is_default && config.rules.back().action == nd::Action::process &&
                  !config.rules.back().server_id,
              "Default sentinel mapping");
        const std::pair<const char*, const char*> cases[] = {
            {"chatgpt.com", "AI - OpenAI"},
            {"API.OPENAI.COM.", "AI - OpenAI"},
            {"gemini.google.com", "AI - Google"},
            {"claude.ai", "AI - Anthropic"},
            {"grok.com", "AI - xAI and X"},
            {"discord.com", "Communication - Discord"},
            {"twitch.tv", "Media - Twitch"},
            {"geforcenow.com", "GeForce NOW"},
            {"iana.org", "Default"}};
        for (const auto& [host, rule] : cases) {
            const std::string hostname = host;
            const auto& matched = nd::match_rule(config, hostname);
            check(matched.name == rule, "Fixture route name");
            check(matched.server_id == (matched.is_default ? 0u : 1002u), "Fixture route target");
        }
        check(config.servers[2].ip == "195.133.25.16" &&
                  config.servers[2].url == "https://dns.comss.one/dns-query",
              "DoH identity vs endpoint");
        check(!imported.warnings.empty(), "Unsupported settings surfaced");
        check(nd::normalize_host("XN--E1AFMKFD.XN--P1AI.") == "xn--e1afmkfd.xn--p1ai",
              "canonical IDN A-label");
        fails([&] { (void)nd::normalize_host("ПРИМЕР.РФ"); });
        check(nd::normalize_dns_name("_LDAP._TCP.Example.com") == "_ldap._tcp.example.com",
              "DNS service labels");
        check(nd::host_matches("a.b.example.com", "*.example.com"), "Wildcard subdomains");
        check(!nd::host_matches("example.com", "*.example.com"), "Wildcard excludes apex");
        check(!nd::host_matches("notexample.com", "*.example.com"), "Wildcard label boundary");
        check(nd::host_matches("x.local", "*.local") && nd::host_matches("abc.com", "a?c.*"),
              "Glob semantics");
        for (const auto& bad :
             {"", "bad..name", "a..", "-abc.org", "abc-.org", "a b.org", "a/b", "*.com"})
            fails([&] { (void)nd::normalize_host(bad); });
        check(nd::split_patterns(" A.COM;\r\n*.B.COM; ").size() == 2, "Pattern delimiters");
        for (const auto* service : {"_ldap._tcp.example.com",
                                    "_dmarc.example.com",
                                    "_acme-challenge.example.com",
                                    "selector._domainkey.example.com"}) {
            auto service_config = nd::default_config();
            service_config.rules.insert(
                service_config.rules.begin(),
                nd::Rule{42, "service", true, false, {service}, nd::Action::block});
            nd::validate(service_config);
            check(nd::match_rule(service_config, service).id == 42, "DNS service rule match");
        }
        nd::ConfigEditor editor(config);
        fails([&] { editor.remove_rule(16); });
        fails([&] { editor.move_rule(16, -1); });
        fails([&] { editor.remove_server(1002); });
        check(editor.get() == config, "Mutation rollback");
        editor.clone_rule(1, 100);
        check(editor.get().rules.size() == 17, "Clone");
        editor.remove_rule(100);
        auto disabled = config.rules[0];
        disabled.enabled = false;
        editor.update_rule(disabled);
        check(nd::match_rule(editor.get(), "chatgpt.com").is_default, "Disabled skip");
        nd::Rule block;
        block.id = 100;
        block.name = "Block";
        block.patterns = {"*.com"};
        block.action = nd::Action::block;
        editor.add_rule(block);
        check(nd::match_rule(editor.get(), "discord.com").name == "Communication - Discord",
              "First match precedence");
        for (int i = 0; i < 15; ++i)
            editor.move_rule(100, -1);
        check(nd::match_rule(editor.get(), "discord.com").action == nd::Action::block,
              "Reorder precedence");
        block.action = nd::Action::bypass;
        editor.update_rule(block);
        check(nd::match_rule(editor.get(), "discord.com").action == nd::Action::bypass,
              "Bypass retained");
        nd::Server plain;
        plain.id = 2000;
        plain.name = "Local";
        plain.ip = "127.0.0.1";
        editor.add_server(plain);
        plain.enabled = false;
        editor.update_server(plain);
        editor.remove_server(2000);
        auto cyclic = config;
        nd::Server first;
        first.id = 2000;
        first.name = "first";
        first.ip = "127.0.0.1";
        first.fallback_ids = {2001};
        nd::Server second = first;
        second.id = 2001;
        second.name = "second";
        second.fallback_ids = {2000};
        cyclic.servers.push_back(first);
        cyclic.servers.push_back(second);
        fails([&] { nd::validate(cyclic); });
        const auto directory = std::filesystem::current_path() /
                               ("config-test-" + std::to_string(nd::platform::process_id()));
        std::filesystem::create_directories(directory);
        const auto path = directory / "native.xml";
        nd::save_config(config, path);
        check(nd::load_config(path) == config, "Semantic round trip including metadata");
        check(nd::parse_config(nd::serialize_config(config)) == config,
              "In-memory config parser round trip");
        auto grouped = config;
        grouped.servers.front().fallback_ids = {1002};
        nd::save_config(grouped, path);
        check(nd::load_config(path) == grouped, "Legacy fallback attribute round trip");

        // Server Pools round trip, editor mutations, and validation.
        {
            auto pooled = config;
            nd::ServerPool red;
            red.id = 1;
            red.name = "RU DNS AI";
            red.type = nd::PoolType::redundancy;
            red.server_ids = {1001, 1002};
            red.test_hostname = "example.org";
            red.recheck_seconds = 45;
            nd::ServerPool lb;
            lb.id = 2;
            lb.name = "Random Pool";
            lb.type = nd::PoolType::load_balancing;
            lb.server_ids = {1002, 1003};
            nd::ConfigEditor pool_editor(pooled);
            pool_editor.add_pool(red);
            pool_editor.add_pool(lb);
            pooled = pool_editor.get();
            pooled.rules.front().server_id = 0;
            pooled.rules.front().pool_id = 1;
            nd::save_config(pooled, path);
            check(nd::load_config(path) == pooled, "Server pools XML round trip");

            auto both = pooled;
            both.rules.front().server_id = 1001;
            both.rules.front().pool_id = 1;
            fails([&] { nd::validate(both); });

            auto bad_recheck = pooled;
            bad_recheck.pools.front().recheck_seconds = 3;
            fails([&] { nd::validate(bad_recheck); });

            auto bad_member = pooled;
            bad_member.pools.front().server_ids.push_back(9999);
            fails([&] { nd::validate(bad_member); });

            nd::ConfigEditor ref_editor(pooled);
            fails([&] { ref_editor.remove_pool(1); }); // Referenced by rule 0
            ref_editor.remove_pool(2);                 // Unreferenced pool removes cleanly
            check(ref_editor.get().pools.size() == 1, "Unreferenced pool removed");
            ref_editor.remove_server(1001); // Also cleans up pool member reference
            check(ref_editor.get().pools.front().server_ids == std::vector<uint32_t>{1002},
                  "Removing server removes it from pool membership");
        }
        nd::save_config(config, path);
        auto changed = config;
        changed.logging.directory = "журнал & <test>";
        changed.logging.file_enabled = true;
        nd::save_config(changed, path);
        check(nd::load_config(path) == changed, "Updated round trip");
        check(nd::load_config(path.string() + ".bak") == config, "Last valid backup");
        auto bad = config;
        bad.rules.back().enabled = false;
        fails([&] { nd::save_config(bad, path); });
        check(nd::load_config(path) == changed, "Invalid write leaves previous file");
        put(path, "<NativeDNS>");
        fails([&] { (void)nd::load_config(path); });
        fails([&] { nd::save_config(config, path); });
        check(nd::load_config(path.string() + ".bak") == config,
              "Corrupt file does not destroy backup");
        const auto archived = nd::save_config_replacing_corrupt(changed, path);
        check(!archived.empty() && std::filesystem::exists(archived),
              "Corrupt recovery archives unreadable config");
        check(nd::load_config(path) == changed,
              "Corrupt recovery publishes replacement config");
        check(nd::load_config(path.string() + ".bak") == config,
              "Corrupt recovery preserves previous .bak untouched");
        std::filesystem::remove(archived);
        put(path,
            "<!DOCTYPE x [<!ENTITY a SYSTEM "
            "'file:///C:/Windows/win.ini'>]><NativeDNS>&a;</NativeDNS>");
        fails([&] { (void)nd::load_config(path); });
        put(path, "<NativeDNS schemaVersion=\"2\"/>");
        fails([&] { (void)nd::load_config(path); });
        put(path,
            "<YogaDnsProfile file_format=\"1\"><Rule name=\"Default\" hostnames=\"*\" "
            "action=\"process_server\" action_id=\"999\"/></YogaDnsProfile>");
        fails([&] { (void)nd::import_yoga(path); });
        put(path,
            "<YogaDnsProfile file_format=\"1\"><Rule name=\"one\" hostnames=\"*.com\" "
            "action=\"block\"/><Rule name=\"two\" hostnames=\"*.org\" "
            "action=\"bypass\"/></YogaDnsProfile>");
        auto actions = nd::import_yoga(path);
        check(actions.config.rules[0].action == nd::Action::block &&
                  actions.config.rules[1].action == nd::Action::bypass &&
                  actions.config.rules.back().is_default,
              "Additional action import");
        put(path,
            "<YogaDnsProfile file_format=\"1\">"
            "<DnsServer id=\"10\" name=\"ipv6-doh\" protocol=\"doh\" ip=\"2001:db8::1\" "
            "doh_host_name=\"2001:db8::1\" doh_path=\"dns-query\"/>"
            "<DnsServer id=\"11\" name=\"empty-path-doh\" protocol=\"doh\" ip=\"1.1.1.1\" "
            "doh_host_name=\"cloudflare-dns.com\" doh_path=\"\"/>"
            "<Rule name=\"Default\" hostnames=\"*\" action=\"process_server\" action_id=\"10\"/>"
            "<Rule name=\"specific\" hostnames=\"*.example.com\" action=\"block\"/>"
            "</YogaDnsProfile>");
        auto normalized = nd::import_yoga(path);
        check(normalized.config.servers.size() == 2 &&
                  normalized.config.servers[0].url == "https://[2001:db8::1]/dns-query" &&
                  normalized.config.servers[1].url == "https://cloudflare-dns.com/dns-query",
              "YogaDNS DoH IPv6 literal and doh_path normalization");
        check(normalized.config.rules.size() == 2 &&
                  normalized.config.rules[0].name == "specific" &&
                  normalized.config.rules[1].is_default,
              "YogaDNS non-last Default rule moved to end");
        check(!normalized.warnings.empty(), "YogaDNS normalization emits warnings");
        // Delete only individually named test-owned files; no recursive deletion.
        std::filesystem::remove(path);
        std::filesystem::remove(path.string() + ".bak");
        std::filesystem::remove(directory);
        std::cout << "config/rules/fixture tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
