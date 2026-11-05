#include <nativedns/dns.hpp>
#include <nativedns/host.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/network.hpp>
#include <curl/curl.h>
#include <iostream>
#include <future>
void check(bool value, const char* message) {
    if (!value)
        throw std::runtime_error(message);
}
int local_tls_checks(char** argv) {
    auto server = [](const char* port) {
        nd::Server result;
        result.protocol = nd::Protocol::doh;
        result.url = "https://localhost:" + std::string(port) + "/dns-query";
        result.ip = "127.0.0.1";
        result.timeout_ms = 3000;
        return result;
    };
    const auto valid = server(argv[2]);
    const auto positive = nd::test_server(valid);
    if (!positive.success || positive.addresses != std::vector<std::string>{"192.0.2.53"})
        throw std::runtime_error("Local trusted DoH control failed: " + positive.error_code + " " +
                                 positive.message);
    std::cout << "PASS trusted certificate and real DoH answer\n";
    const auto expect = [](const nd::Server& candidate, const char* code, const char* name) {
        const auto result = nd::test_server(candidate);
        if (result.success || result.error_code != code)
            throw std::runtime_error(std::string(name) + ": expected " + code + ", got " +
                                     result.error_code + " " + result.message);
        std::cout << "PASS " << name << ": " << result.error_code << '\n';
    };
    expect(server(argv[3]), "TLS_CERTIFICATE", "expired certificate");
    expect(server(argv[4]), "TLS_CERTIFICATE", "wrong certificate hostname");
    auto pinned = valid;
    pinned.hashes = {"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="};
    expect(pinned, "TLS_PIN", "wrong certificate pin");
    expect(server(argv[5]), "TLS_HTTP", "reset is a transport failure, not a certificate result");
    return 0;
}
int main(int argc, char** argv) {
    try {
        if (argc == 6 && std::string(argv[1]) == "--local-tls")
            return local_tls_checks(argv);
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
        if (argc > 1 && std::string(argv[1]) == "--system-bootstrap") {
            const auto resolvers = nd::platform::system_dns_servers();
            check(!resolvers.empty(), "Current network has no usable automatic bootstrap resolver");
            for (const auto& resolver : resolvers)
                std::cout << "system bootstrap resolver: " << resolver << '\n';
            bool failed = false;
            auto shared_transport = nd::make_transport(nd::Protocol::doh);
            for (unsigned generation = 0; generation < 3; ++generation) {
                nd::NetworkMonitor::shared().refresh(true);
                for (const auto* url : {"https://cloudflare-dns.com/dns-query",
                                        "https://dns.bezmezhau.com/dns-query"}) {
                    nd::Server automatic;
                    automatic.protocol = nd::Protocol::doh;
                    automatic.url = url;
                    automatic.timeout_ms = 3000;
                    automatic.use_system_bootstrap = true;
                    const auto result = nd::test_server(nd::with_network_context(automatic));
                    std::cout << "automatic bootstrap generation="
                              << nd::NetworkMonitor::shared().snapshot()->generation << " " << url
                              << " success=" << result.success << " " << result.rtt_ms << " ms "
                              << result.error_code << " " << result.message << '\n';
                    failed = failed || !result.success;
                    std::vector<std::future<void>> concurrent;
                    for (unsigned request = 0; request < 4; ++request)
                        concurrent.push_back(std::async(std::launch::async, [&, automatic] {
                            const auto query = nd::make_query("example.com");
                            const auto answer =
                                nd::parse_response(shared_transport->exchange(query, automatic),
                                                   nd::parse_question(query));
                            check(!answer.rcode && !answer.addresses.empty(),
                                  "Concurrent automatic bootstrap returns a real DNS answer");
                        }));
                    for (auto& request : concurrent)
                        request.get();
                    std::cout << "PASS concurrent bootstrap after network invalidation\n";
                }
            }
            nd::Server fallback;
            fallback.protocol = nd::Protocol::doh;
            fallback.url = "https://cloudflare-dns.com/dns-query";
            fallback.timeout_ms = 3000;
            fallback.bootstrap = {"192.0.2.1"};
            fallback.bootstrap.insert(fallback.bootstrap.end(), resolvers.begin(), resolvers.end());
            const auto result = nd::test_server(fallback);
            std::cout << "explicit bootstrap list with fallback: success=" << result.success << " "
                      << result.rtt_ms << " ms " << result.error_code << " " << result.message
                      << '\n';
            check(!failed && result.success, "Live automatic bootstrap/fallback failed");
        } else if (argc > 1) {
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
            server.url = "https://xbox-dns.ru/dns-query";
            server.timeout_ms = 5000;
            server.hashes.clear();
            server.ip.clear();
            server.bootstrap = {"1.1.1.1"};
            const auto bootstrapped = nd::test_server(server);
            std::cout << "explicit bootstrap: " << bootstrapped.success << ' '
                      << bootstrapped.error_code << '\n';
            check(bootstrapped.success, "Live explicit bootstrap failed; see the resolver result");
        }
        std::cout << "secure transport checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
