#include <nativedns/dns.hpp>
#include <curl/curl.h>
#include <iostream>
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int main(int argc, char**) {
    try {
#ifdef _WIN32
        check((curl_version_info(CURLVERSION_NOW)->features&CURL_VERSION_HTTP2)!=0,"Bundled Windows libcurl must support HTTP/2");
#endif
        nd::Server server; server.id = 1; server.name = "secure test"; server.protocol = nd::Protocol::doh;
        server.url = "http://example.com/dns-query";
        check(nd::test_server(server).error_code == "ENDPOINT", "Reject plaintext DoH");
        server.url = "https://user:pass@example.com/dns-query";
        check(nd::test_server(server).error_code == "ENDPOINT", "Reject URL credentials");
        server.url = "https://example.com/dns-query#fragment";
        check(nd::test_server(server).error_code == "ENDPOINT", "Reject URL fragment");
        server.url = "https://example.com/dns-query"; server.hashes = {"unrecognized-pin"};
        check(nd::test_server(server).error_code == "TLS_PIN", "Never ignore invalid pin");
        server.hashes.clear(); server.ip = "not-an-ip";
        check(nd::test_server(server).error_code == "ENDPOINT", "Reject invalid address override");
        server.ip.clear(); server.enabled = false;
        check(nd::test_server(server).error_code == "SERVER_DISABLED", "Disabled secure server");
        if (argc > 1) {
            const auto config = nd::import_yoga(FIXTURE_PATH).config;
            for (uint32_t id : {1001u,1002u,1003u}) {
                for (const auto& candidate : config.servers) if (candidate.id == id) {
                    const auto result = nd::test_server(candidate);
                    std::cout << id << " " << result.success << " " << result.rtt_ms << " " << result.error_code << " " << result.message << '\n';
                    check(result.success, "Real fixture DoH/DoT failed");
                }
            }
            for(const auto& candidate:config.servers) if(candidate.id==1001) {
                auto transport=nd::make_transport(nd::Protocol::dot);
                for(const auto* hostname:{"iana.org","example.com"}) {
                    const auto query=nd::make_query(hostname);
                    check(!nd::parse_response(transport->exchange(query,candidate),nd::parse_question(query)).addresses.empty(),"Persistent DoT exchange failed");
                }
            }
            server.enabled = true; server.url = "https://expired.badssl.com/"; server.timeout_ms = 5000;
            const auto expired = nd::test_server(server);
            std::cout << "expired certificate: " << expired.error_code << " " << expired.message << '\n';
            check(expired.error_code == "TLS_CERTIFICATE", "Expired certificate must fail verification");
            server.url = "https://wrong.host.badssl.com/";
            const auto wrong = nd::test_server(server);
            std::cout << "wrong certificate name: " << wrong.error_code << '\n';
            check(wrong.error_code == "TLS_CERTIFICATE", "Wrong hostname must fail verification");
            server.url = "https://xbox-dns.ru/dns-query";
            server.hashes = {"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="};
            const auto pin = nd::test_server(server);
            std::cout << "wrong pin: " << pin.error_code << '\n';
            check(pin.error_code == "TLS_PIN", "Wrong pin must fail");
            server.hashes.clear(); server.bootstrap = {"1.1.1.1"};
            check(nd::test_server(server).success, "Explicit bootstrap DoH");
        }
        std::cout << "secure transport checks passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
