#include <nativedns/dns.hpp>
#include <nativedns/host.hpp>
#include <nativedns/platform.hpp>
#include <curl/curl.h>
#include <iostream>
void check(bool value, const char* message) {
    if (!value)
        throw std::runtime_error(message);
}
int main(int argc, char**) {
    try {
        const auto prepare = [](nd::Server value) {
            auto config = nd::default_config();
            value.id = 1;
            config.servers.push_back(std::move(value));
            nd::prepare_secure_endpoints(config);
            return config.servers.front();
        };
#ifdef _WIN32
        check((curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_HTTP2) != 0,
              "Bundled Windows libcurl must support HTTP/2");
#endif
        nd::Server server;
        server.id = 1;
        server.name = "secure test";
        server.protocol = nd::Protocol::doh;
        server.url = "http://example.com/dns-query";
        check(nd::test_server(server).error_code == "ENDPOINT", "Reject plaintext DoH");
        server.url = "https://user:pass@example.com/dns-query";
        check(nd::test_server(server).error_code == "ENDPOINT", "Reject URL credentials");
        server.url = "https://example.com/dns-query#fragment";
        check(nd::test_server(server).error_code == "ENDPOINT", "Reject URL fragment");
        server.url = "https://example.com/dns-query";
        server.hashes = {"unrecognized-pin"};
        check(nd::test_server(server).error_code == "TLS_PIN", "Never ignore invalid pin");
        server.hashes.clear();
        server.ip = "not-an-ip";
        check(nd::test_server(server).error_code == "ENDPOINT", "Reject invalid address override");
        server.ip.clear();
        server.enabled = false;
        check(nd::test_server(server).error_code == "SERVER_DISABLED", "Disabled secure server");
        server.enabled = true;
        server.url = "https://localhost/dns-query";
        check(nd::test_server(server).error_code == "BOOTSTRAP",
              "Implicit runtime bootstrap must be rejected");
        auto bootstrap_config = nd::default_config();
        server.id = 1;
        bootstrap_config.servers.push_back(server);
        nd::prepare_secure_endpoints(bootstrap_config);
        check(!bootstrap_config.servers.front().ip.empty(),
              "Secure endpoint was not resolved before interception");
        {
            auto bound = server;
            bound.ip = "127.0.0.1";
            bound.port = 443;
            bound.route.interface_id = "NativeDNS-nonexistent-interface";
            bound.timeout_ms = 500;
            check(nd::test_server(bound).error_code == "INTERFACE_DOWN",
                  "TLS socket callback preserves interface failure instead of generic curl error");
        }
        {
            auto offline = nd::default_config();
            offline.logging.file_enabled = false;
            auto unavailable = server;
            unavailable.url = "https://unreachable-upstream.invalid/dns-query";
            unavailable.ip.clear();
            unavailable.bootstrap.clear();
            offline.servers.push_back(unavailable);
            offline.rules.back().action = nd::Action::block;
            const auto started = std::chrono::steady_clock::now();
            nd::CoreHost host(
                offline, {}, 0, "NativeDNS.Test.OfflineStartup", nd::InterceptionMode::transparent);
            check(std::chrono::steady_clock::now() - started < std::chrono::seconds(1),
                  "CoreHost construction does not wait for unavailable DNS upstream");
            nd::Logger log;
            nd::Router router(offline, log);
            check(!router.route(nd::make_query("example.com"), {}).packet.empty(),
                  "Unavailable secure server does not prevent independent Block rule");
            auto serialized = nd::serialize_config(offline);
            offline.servers.front().use_system_bootstrap = true;
            check(nd::serialize_config(offline) == serialized,
                  "Runtime system bootstrap policy is not persisted");
        }
        if (argc > 1) {
#ifdef _WIN32
            nd::platform::flush_dns_cache();
#endif
            auto config = nd::import_yoga(FIXTURE_PATH).config;
            nd::prepare_secure_endpoints(config);
            for (uint32_t id : {1001u, 1002u, 1003u}) {
                for (const auto& candidate : config.servers)
                    if (candidate.id == id) {
                        const auto result = nd::test_server(candidate);
                        std::cout << id << " " << result.success << " " << result.rtt_ms << " "
                                  << result.error_code << " " << result.message << '\n';
                        check(result.success, "Real fixture DoH/DoT failed");
                    }
            }
            for (const auto& candidate : config.servers)
                if (candidate.id == 1001) {
                    auto transport = nd::make_transport(nd::Protocol::dot);
                    for (const auto* hostname : {"iana.org", "example.com"}) {
                        const auto query = nd::make_query(hostname);
                        check(!nd::parse_response(transport->exchange(query, candidate),
                                                  nd::parse_question(query))
                                   .addresses.empty(),
                              "Persistent DoT exchange failed");
                    }
                }
            server.enabled = true;
            server.url = "https://expired.badssl.com/";
            server.timeout_ms = 5000;
            server = prepare(server);
            const auto expired = nd::test_server(server);
            std::cout << "expired certificate: " << expired.error_code << " " << expired.message
                      << '\n';
            bool live_failed = expired.error_code != "TLS_CERTIFICATE";
            if (live_failed)
                std::cerr << "Expired certificate check failed: " << expired.error_code << '\n';
            server.url = "https://wrong.host.badssl.com/";
            server.ip.clear();
            server = prepare(server);
            const auto wrong = nd::test_server(server);
            std::cout << "wrong certificate name: " << wrong.error_code << '\n';
            if (wrong.error_code != "TLS_CERTIFICATE") {
                live_failed = true;
                std::cerr << "Wrong hostname check failed: " << wrong.error_code << '\n';
            }
            server.url = "https://xbox-dns.ru/dns-query";
            server.ip.clear();
            server = prepare(server);
            server.hashes = {"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="};
            const auto pin = nd::test_server(server);
            std::cout << "wrong pin: " << pin.error_code << '\n';
            if (pin.error_code != "TLS_PIN") {
                live_failed = true;
                std::cerr << "Wrong pin check failed: " << pin.error_code << '\n';
            }
            server.hashes.clear();
            server.ip.clear();
            server.bootstrap = {"1.1.1.1"};
            const auto bootstrapped = nd::test_server(server);
            std::cout << "explicit bootstrap: " << bootstrapped.success << ' '
                      << bootstrapped.error_code << '\n';
            if (!bootstrapped.success)
                live_failed = true;
            check(!live_failed,
                  "One or more live TLS/bootstrap checks failed; see individual results");
        }
        std::cout << "secure transport checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
