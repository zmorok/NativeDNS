#include <nativedns/config.hpp>
#include <nativedns/platform.hpp>
#include <fstream>
#include <iostream>
#include <functional>
#include <set>

void check(bool result, const char* message) { if (!result) throw std::runtime_error(message); }
void fails(const std::function<void()>& fn) {
    try { fn(); } catch (const nd::Error&) { return; }
    throw std::runtime_error("Expected structured failure");
}
void put(const std::filesystem::path& path, const std::string& text) { std::ofstream stream(path, std::ios::binary); stream << text; }
int main() {
    try {
        const auto imported = nd::import_yoga(FIXTURE_PATH);
        const auto& config = imported.config;
        check(config.servers.size() == 6 && config.rules.size() == 16, "Fixture counts");
        std::set<uint32_t> ids; for (const auto& server : config.servers) ids.insert(server.id);
        check(ids == std::set<uint32_t>{1001,1002,1003,1005,1006,1007}, "Server IDs");
        check(config.rules.back().is_default && config.rules.back().action == nd::Action::process && !config.rules.back().server_id, "Default sentinel mapping");
        const std::pair<const char*, const char*> cases[] = {
            {"chatgpt.com", "AI - OpenAI"}, {"API.OPENAI.COM.", "AI - OpenAI"}, {"gemini.google.com", "AI - Google"},
            {"claude.ai", "AI - Anthropic"}, {"grok.com", "AI - xAI and X"}, {"discord.com", "Communication - Discord"},
            {"twitch.tv", "Media - Twitch"}, {"geforcenow.com", "GeForce NOW"}, {"iana.org", "Default"}
        };
        for (const auto& [host, rule] : cases) {
            const std::string hostname = host;
            const auto& matched = nd::match_rule(config, hostname);
            check(matched.name == rule, "Fixture route name");
            check(matched.server_id == (matched.is_default ? 0u : 1002u), "Fixture route target");
        }
        check(config.servers[2].ip == "195.133.25.16" && config.servers[2].url == "https://dns.comss.one/dns-query", "DoH identity vs endpoint");
        check(!imported.warnings.empty(), "Unsupported settings surfaced");
        check(nd::normalize_host("XN--E1AFMKFD.XN--P1AI.") == "xn--e1afmkfd.xn--p1ai", "canonical IDN A-label");
        fails([&] { (void)nd::normalize_host("ПРИМЕР.РФ"); });
        check(nd::normalize_dns_name("_LDAP._TCP.Example.com") == "_ldap._tcp.example.com", "DNS service labels");
        check(nd::host_matches("a.b.example.com", "*.example.com"), "Wildcard subdomains");
        check(!nd::host_matches("example.com", "*.example.com"), "Wildcard excludes apex");
        check(!nd::host_matches("notexample.com", "*.example.com"), "Wildcard label boundary");
        check(nd::host_matches("x.local", "*.local") && nd::host_matches("abc.com", "a?c.*"), "Glob semantics");
        for (const auto& bad : {"", "bad..name", "a..", "-abc.org", "abc-.org", "a b.org", "a/b", "*.com"})
            fails([&] { (void)nd::normalize_host(bad); });
        check(nd::split_patterns(" A.COM;\r\n*.B.COM; ").size() == 2, "Pattern delimiters");
        for(const auto* service:{"_ldap._tcp.example.com","_dmarc.example.com","_acme-challenge.example.com","selector._domainkey.example.com"}) {
            auto service_config=nd::default_config();service_config.rules.insert(service_config.rules.begin(),nd::Rule{42,"service",true,false,{service},nd::Action::block});
            nd::validate(service_config);check(nd::match_rule(service_config,service).id==42,"DNS service rule match");
        }
        nd::ConfigEditor editor(config);
        fails([&] { editor.remove_rule(16); }); fails([&] { editor.move_rule(16, -1); });
        fails([&] { editor.remove_server(1002); }); check(editor.get() == config, "Mutation rollback");
        editor.clone_rule(1, 100); check(editor.get().rules.size() == 17, "Clone"); editor.remove_rule(100);
        auto disabled = config.rules[0]; disabled.enabled = false; editor.update_rule(disabled);
        check(nd::match_rule(editor.get(), "chatgpt.com").is_default, "Disabled skip");
        nd::Rule block; block.id = 100; block.name = "Block"; block.patterns = {"*.com"}; block.action = nd::Action::block;
        editor.add_rule(block);
        check(nd::match_rule(editor.get(), "discord.com").name == "Communication - Discord", "First match precedence");
        for (int i = 0; i < 15; ++i) editor.move_rule(100, -1);
        check(nd::match_rule(editor.get(), "discord.com").action == nd::Action::block, "Reorder precedence");
        block.action = nd::Action::bypass; editor.update_rule(block);
        check(nd::match_rule(editor.get(), "discord.com").action == nd::Action::bypass, "Bypass retained");
        nd::Server plain; plain.id = 2000; plain.name = "Local"; plain.ip = "127.0.0.1";
        editor.add_server(plain); plain.enabled = false; editor.update_server(plain); editor.remove_server(2000);
        auto cyclic=config;nd::Server first;first.id=2000;first.name="first";first.ip="127.0.0.1";first.fallback_ids={2001};nd::Server second=first;second.id=2001;second.name="second";second.fallback_ids={2000};cyclic.servers.push_back(first);cyclic.servers.push_back(second);
        fails([&]{nd::validate(cyclic);});
        const auto directory = std::filesystem::current_path() / ("config-test-" + std::to_string(nd::platform::process_id()));
        std::filesystem::create_directories(directory);
        const auto path = directory / "native.xml";
        nd::save_config(config, path); check(nd::load_config(path) == config, "Semantic round trip including metadata");
        auto grouped=config;grouped.servers.front().fallback_ids={1002};nd::save_config(grouped,path);check(nd::load_config(path)==grouped,"Fallback group round trip");
        nd::save_config(config,path);
        auto changed = config; changed.logging.directory = "журнал & <test>"; changed.logging.file_enabled = true;
        nd::save_config(changed, path); check(nd::load_config(path) == changed, "Updated round trip");
        check(nd::load_config(path.string() + ".bak") == config, "Last valid backup");
        auto bad = config; bad.rules.back().enabled = false;
        fails([&] { nd::save_config(bad, path); }); check(nd::load_config(path) == changed, "Invalid write leaves previous file");
        put(path, "<NativeDNS>"); fails([&] { (void)nd::load_config(path); });
        fails([&] { nd::save_config(config, path); });
        check(nd::load_config(path.string() + ".bak") == config, "Corrupt file does not destroy backup");
        put(path, "<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///C:/Windows/win.ini'>]><NativeDNS>&a;</NativeDNS>");
        fails([&] { (void)nd::load_config(path); });
        put(path, "<NativeDNS schemaVersion=\"2\"/>"); fails([&] { (void)nd::load_config(path); });
        put(path, "<YogaDnsProfile file_format=\"1\"><Rule name=\"Default\" hostnames=\"*\" action=\"process_server\" action_id=\"999\"/></YogaDnsProfile>");
        fails([&] { (void)nd::import_yoga(path); });
        put(path, "<YogaDnsProfile file_format=\"1\"><Rule name=\"one\" hostnames=\"*.com\" action=\"block\"/><Rule name=\"two\" hostnames=\"*.org\" action=\"bypass\"/></YogaDnsProfile>");
        auto actions = nd::import_yoga(path); check(actions.config.rules[0].action == nd::Action::block && actions.config.rules[1].action == nd::Action::bypass && actions.config.rules.back().is_default, "Additional action import");
        // Delete only individually named test-owned files; no recursive deletion.
        std::filesystem::remove(path); std::filesystem::remove(path.string() + ".bak"); std::filesystem::remove(directory);
        std::cout << "config/rules/fixture tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
