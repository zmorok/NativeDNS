#include <nativedns/dns.hpp>
#include <nativedns/router.hpp>
#include <nativedns/interception.hpp>
#include <nativedns/platform.hpp>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using SocketLength = int;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
using SOCKET = int;
using SocketLength = socklen_t;
inline constexpr SOCKET INVALID_SOCKET = -1;
inline int closesocket(SOCKET s) { return ::close(s); }
#endif
#include <functional>
#include <iostream>
#include <thread>
#include <atomic>

void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void fails(const std::function<void()>& fn) { try { fn(); } catch (const nd::Error&) { return; } throw std::runtime_error("Expected DNS parser failure"); }
nd::Packet reply(const nd::Packet& query, bool v6 = false) {
    const auto q = nd::parse_question(query);
    nd::Packet result(query.begin(), query.begin() + static_cast<ptrdiff_t>(q.end));
    result[2] = 0x81; result[3] = 0x80; result[6] = 0; result[7] = 1;
    result[8] = result[9] = result[10] = result[11] = 0;
    const nd::Packet rr{0xc0, 0x0c, 0, static_cast<uint8_t>(v6 ? 28 : 1), 0, 1, 0, 0, 0, 30, 0, static_cast<uint8_t>(v6 ? 16 : 4)};
    result.insert(result.end(), rr.begin(), rr.end());
    if (v6) { result.insert(result.end(), 15, 0); result.push_back(1); }
    else { result.insert(result.end(), {192,0,2,42}); }
    return result;
}
nd::Packet with_edns(nd::Packet query,uint16_t payload_size) {
    query[10]=0;query[11]=1;
    query.insert(query.end(),{0,0,41,static_cast<uint8_t>(payload_size>>8),static_cast<uint8_t>(payload_size),0,0,0,0,0,0});
    return query;
}
nd::Packet padded_response(const nd::Packet& query,size_t padding) {
    auto result=reply(query);result[10]=0;result[11]=1;
    result.insert(result.end(),{0,0,41,4,208,0,0,0,0,static_cast<uint8_t>(padding>>8),static_cast<uint8_t>(padding)});
    result.insert(result.end(),padding,0);return result;
}
enum class Mode { good, malformed, mismatch, servfail, no_data, timeout, eof, truncated };
// Test-only loopback peer. This exercises actual OS socket traffic, not a production transport substitute.
class Peer {
public:
    Peer(bool tcp, Mode mode, bool ipv6 = false, uint16_t port = 0, uint32_t timeout_ms = 0, unsigned request_limit = 1)
        : tcp_(tcp), mode_(mode), ipv6_(ipv6), timeout_ms_(timeout_ms ? timeout_ms : (mode == Mode::timeout ? 80u : 1500u)), request_limit_(request_limit) {
        socket_ = socket(ipv6 ? AF_INET6 : AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP);
        check(socket_ != INVALID_SOCKET, "test socket");
        sockaddr_storage address{}; SocketLength size = 0;
        const auto bind_port = [&](uint16_t candidate) {
            if (ipv6) { auto* a = reinterpret_cast<sockaddr_in6*>(&address); a->sin6_family = AF_INET6; a->sin6_port = htons(candidate); a->sin6_addr = in6addr_loopback; size = sizeof(*a); }
            else { auto* a = reinterpret_cast<sockaddr_in*>(&address); a->sin_family = AF_INET; a->sin_port = htons(candidate); a->sin_addr.s_addr = htonl(INADDR_LOOPBACK); size = sizeof(*a); }
            return bind(socket_, reinterpret_cast<sockaddr*>(&address), size) == 0;
        };
        bool bound = false;
        for (unsigned attempt = 0; attempt < (port ? 1u : 256u); ++attempt) {
            const auto candidate = port ? port : static_cast<uint16_t>(20000 + ((nd::platform::monotonic_millis() + attempt * 7919u) % 28000));
            if (bind_port(candidate)) { bound = true; break; }
        }
        check(bound, "test bind");
        check(getsockname(socket_, reinterpret_cast<sockaddr*>(&address), &size) == 0, "test getsockname");
        port_ = ntohs(ipv6 ? reinterpret_cast<sockaddr_in6*>(&address)->sin6_port : reinterpret_cast<sockaddr_in*>(&address)->sin_port);
        if (tcp) check(listen(socket_, 1) == 0, "test listen");
        worker_ = std::thread([this] { run(); });
    }
    ~Peer() { if (worker_.joinable()) worker_.join(); closesocket(socket_); }
    nd::Server server() const { nd::Server s; s.id = 1; s.name = "loopback"; s.ip = ipv6_ ? "::1" : "127.0.0.1"; s.port = port_; s.protocol = tcp_ ? nd::Protocol::tcp : nd::Protocol::udp; s.timeout_ms = timeout_ms_; return s; }
    void verify() { worker_.join(); check(ok_, "Loopback peer failed"); }
    static uint16_t paired_port() {
        for (unsigned attempt = 0; attempt < 256; ++attempt) {
            const uint16_t port = static_cast<uint16_t>(20000 + ((nd::platform::monotonic_millis() + attempt * 7919u) % 28000));
            SOCKET tcp = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP), udp = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
            if (tcp == INVALID_SOCKET || udp == INVALID_SOCKET) { if (tcp != INVALID_SOCKET) closesocket(tcp); if (udp != INVALID_SOCKET) closesocket(udp); continue; }
            sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(port);
            const bool usable = bind(tcp,reinterpret_cast<sockaddr*>(&address),sizeof(address)) == 0 &&
                                bind(udp,reinterpret_cast<sockaddr*>(&address),sizeof(address)) == 0;
            closesocket(tcp); closesocket(udp); if (usable) return port;
        }
        throw std::runtime_error("cannot reserve paired test port");
    }
private:
    static bool ready(SOCKET s) { fd_set set; FD_ZERO(&set); FD_SET(s, &set); timeval timeout{3,0};
#ifdef _WIN32
        return select(0,&set,nullptr,nullptr,&timeout) > 0;
#else
        return select(s+1,&set,nullptr,nullptr,&timeout) > 0;
#endif
    }
    static bool read_all(SOCKET s, uint8_t* data, size_t size) {
        size_t at = 0; while (at < size) { if (!ready(s)) return false; const int n = recv(s, reinterpret_cast<char*>(data + at), static_cast<int>(size - at), 0); if (n <= 0) return false; at += static_cast<size_t>(n); } return true;
    }
    void run() {
        SOCKET connection = INVALID_SOCKET;
        try {
            check(ready(socket_), "test receive deadline");
            if (tcp_) {
                connection = accept(socket_, nullptr, nullptr); check(connection != INVALID_SOCKET, "accept");
            }
            for(unsigned request_number=0;request_number<request_limit_;++request_number) {
                nd::Packet query(65535); sockaddr_storage client{}; SocketLength client_size = sizeof(client);
                if (tcp_) {
                    uint8_t prefix[2]{}; check(read_all(connection,prefix,2), "read prefix");
                    query.resize(static_cast<size_t>((prefix[0] << 8) | prefix[1]));
                    check(read_all(connection,query.data(),query.size()), "read query");
                } else {
                    const int n = recvfrom(socket_, reinterpret_cast<char*>(query.data()), static_cast<int>(query.size()), 0, reinterpret_cast<sockaddr*>(&client), &client_size);
                    check(n > 0, "recvfrom"); query.resize(static_cast<size_t>(n));
                }
                ++requests;
                if (mode_ == Mode::timeout) std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms_ + 100));
                else if (mode_ != Mode::eof) {
                    auto response = reply(query, nd::parse_question(query).type == 28);
                    if (mode_ == Mode::malformed) response.resize(12); // complete frame, missing question
                    if (mode_ == Mode::mismatch) response[0] ^= 1;
                    if (mode_ == Mode::servfail) response[3] = 0x82;
                    if (mode_ == Mode::no_data) { response.resize(query.size()); response[7] = 0; }
                    if (mode_ == Mode::truncated) { response.resize(query.size()); response[2] |= 2; response[7] = 0; }
                    if (tcp_) {
                        nd::Packet frame{static_cast<uint8_t>(response.size() >> 8), static_cast<uint8_t>(response.size())};
                        frame.insert(frame.end(),response.begin(),response.end());
                        // Force prefix and payload split across writes.
                        for (const auto byte : frame) { check(send(connection,reinterpret_cast<const char*>(&byte),1,0) == 1,"test fragmented send"); }
                    } else check(sendto(socket_,reinterpret_cast<const char*>(response.data()),static_cast<int>(response.size()),0,reinterpret_cast<sockaddr*>(&client),client_size) == static_cast<int>(response.size()),"sendto");
                }
            }
            ok_ = true;
        } catch (const std::exception& error) { std::cerr << "peer: " << error.what() << '\n'; }
        if (connection != INVALID_SOCKET) closesocket(connection);
    }
    SOCKET socket_; bool tcp_; Mode mode_; bool ipv6_; uint16_t port_; uint32_t timeout_ms_; unsigned request_limit_;
    std::thread worker_; bool ok_ = false;
public: std::atomic<unsigned> requests = 0;
};

SOCKET connect_loopback(uint16_t port, int type) {
    SOCKET socket_value = socket(AF_INET,type,type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    check(socket_value != INVALID_SOCKET,"client socket");
    sockaddr_in target{}; target.sin_family=AF_INET; target.sin_addr.s_addr=htonl(INADDR_LOOPBACK); target.sin_port=htons(port);
    if(connect(socket_value,reinterpret_cast<sockaddr*>(&target),sizeof(target)) != 0) {
        closesocket(socket_value);
        throw std::runtime_error("client connect");
    }
    return socket_value;
}
int main() {
#ifdef _WIN32
    WSADATA data{}; if (WSAStartup(MAKEWORD(2,2),&data)) return 2;
#endif
    try {
        auto query = nd::make_query("example.com"); const auto q = nd::parse_question(query);
        const auto servfail=nd::make_error_response(query,2);const auto servfail_parsed=nd::parse_response(servfail,q);
        check(servfail_parsed.rcode==2&&servfail.size()==q.end,"bounded SERVFAIL preserves the DNS question");
        check(nd::client_udp_payload_size(query)==512,"legacy UDP DNS payload limit");
        const auto edns_query=with_edns(query,1400);check(nd::client_udp_payload_size(edns_query)==1232,"EDNS payload is capped to fragmentation-safe size");
        const auto legacy_large=padded_response(query,600);const auto legacy_truncated=nd::fit_udp_response(query,legacy_large);
        check(legacy_truncated.size()<=512&&nd::parse_response(legacy_truncated,q).truncated,"legacy oversized response requests TCP retry");
        const auto edns_medium=padded_response(query,700);check(nd::fit_udp_response(edns_query,edns_medium)==edns_medium,"EDNS response fits advertised payload");
        const auto edns_large=padded_response(query,1300);const auto edns_truncated=nd::fit_udp_response(edns_query,edns_large);
        check(edns_truncated.size()<=1232&&nd::parse_response(edns_truncated,q).truncated,"oversized EDNS response requests TCP retry");
        auto good = reply(query); check(nd::parse_response(good,q).addresses == std::vector<std::string>{"192.0.2.42"},"decode compressed answer");
        auto bad = good; bad[0] ^= 1; fails([&] { (void)nd::parse_response(bad,q); });
        bad = good; bad[q.end] = 0xc0; bad[q.end+1] = static_cast<uint8_t>(q.end); fails([&] { (void)nd::parse_response(bad,q); });
        for (size_t size = 0; size < good.size(); ++size) fails([&] { (void)nd::parse_response(std::span(good.data(),size),q); });
        bad = good; bad[q.end+11] = 16; fails([&] { (void)nd::parse_response(bad,q); });
        bad = good; bad.push_back(0); fails([&] { (void)nd::parse_response(bad,q); });
        // Deterministic malformed-input sweep: safety and bounded termination, no acceptance assumption.
        uint32_t random = 0x12345678;
        for (unsigned i = 0; i < 10000; ++i) {
            nd::Packet bytes(i % 96); for (auto& byte : bytes) { random = random * 1664525 + 1013904223; byte = static_cast<uint8_t>(random >> 24); }
            try { (void)nd::parse_response(bytes,q); } catch (const nd::Error&) {}
        }
        for (bool tcp : {false,true}) for (bool ipv6 : {false,true}) {
            Peer peer(tcp,Mode::good,ipv6); auto result = nd::test_server(peer.server(),"example.com",ipv6 ? 28 : 1); peer.verify();
            check(result.success && !result.addresses.empty() && result.rtt_ms > 0,"real loopback UDP/TCP v4/v6 DNS");
        }
        {
            Peer peer(true,Mode::good,false,0,1500,2);auto config=nd::default_config();auto server=peer.server();server.id=9;config.servers.push_back(server);config.rules.front().server_id=9;
            nd::Logger logger;nd::Router persistent_router(config,logger);nd::Server original=server;
            const auto first_query=nd::make_query("first.example"),second_query=nd::make_query("second.example");
            const auto first=persistent_router.route(first_query,original),second=persistent_router.route(second_query,original);peer.verify();
            check(first.packet.size()>12&&second.packet.size()>12&&peer.requests==2,"plain TCP reuses one upstream connection");
        }
        for (const auto mode : {Mode::malformed,Mode::mismatch,Mode::servfail,Mode::no_data,Mode::timeout,Mode::eof}) {
            Peer peer(true,mode); nd::Logger logger;
            const auto result = nd::test_server(peer.server(),"example.com",1,&logger); peer.verify();
            check(!result.success && !result.error_code.empty() && logger.snapshot(nd::Level::errors_only).size() == 1,"structured test failure and error log");
            if (mode == Mode::timeout) check(result.error_code == "TIMEOUT" && result.rtt_ms < 500,"bounded timeout");
            if (mode == Mode::eof) check(result.error_code == "DNS_EOF"||result.error_code == "SOCKET"||result.error_code == "TIMEOUT","TCP port open is not DNS success");
        }
        const auto fallback_port = Peer::paired_port();
        Peer tcp(true,Mode::good,false,fallback_port); Peer udp(false,Mode::truncated,false,fallback_port);
        auto fallback = nd::test_server(udp.server(),"example.com"); udp.verify(); tcp.verify();
        check(fallback.success && udp.requests == 1 && tcp.requests == 1,"TC retries TCP");
        Peer selected(false,Mode::good), original(false,Mode::good);
        auto config = nd::default_config(); auto upstream = selected.server(); upstream.id = 1002; config.servers.push_back(upstream);
        nd::Rule route; route.id = 2; route.name = "selected"; route.patterns = {"example.com"}; route.server_id = 1002;
        config.rules.insert(config.rules.begin(),route);
        nd::Logger route_log; nd::Router router(config,route_log);
        auto routed = router.route(query,original.server()); selected.verify();
        check(routed.server_id == 1002 && nd::parse_response(routed.packet,q).addresses.size() == 1,"Rule uses selected real upstream");
        const auto route_events=route_log.snapshot(nd::Level::normal);
        check(route_events.size()==1&&route_events[0].code=="DNS_ROUTE"&&
              route_events[0].message.find("example.com [A] - process : server=loopback (UDP) (DNS over UDP), rule=selected, time=")!=std::string::npos,
              "combined readable route log");
        check(nd::dns_type_name(28)=="AAAA"&&nd::dns_type_name(65)=="HTTPS"&&nd::dns_type_name(65280)=="TYPE65280","DNS type log names");
        const auto default_query = nd::make_query("iana.org");
        routed = router.route(default_query,original.server()); original.verify();
        check(routed.rule_id == 1 && routed.server_id == 0 && nd::parse_response(routed.packet,nd::parse_question(default_query)).addresses.size() == 1,"Default original endpoint");
        config.rules[0].action = nd::Action::bypass; config.rules[0].server_id = 0;
        routed = nd::Router(config,route_log).route(query,original.server());
        check(routed.disposition == nd::Disposition::forward_original && routed.packet == query,"Bypass leaves original packet intact");
        config.rules[0].action = nd::Action::block;
        for (auto mode : {nd::BlockMode::zero_address,nd::BlockMode::nxdomain,nd::BlockMode::refused,nd::BlockMode::silent_drop}) {
            config.rules[0].block_mode = mode;
            routed = nd::Router(config,route_log).route(query,original.server());
            if (mode == nd::BlockMode::silent_drop) check(routed.disposition == nd::Disposition::silent_drop,"Silent drop");
            else { const auto a = nd::parse_response(routed.packet,q);
                if (mode == nd::BlockMode::zero_address) check(a.addresses == std::vector<std::string>{"0.0.0.0"},"Zero-address block");
                else check(a.rcode == (mode == nd::BlockMode::nxdomain ? 3 : 5),"Block rcode"); }
        }
        check(selected.requests == 1 && original.requests == 1,"Bypass and Block do not query custom servers");
        for (const auto action : {nd::Action::process,nd::Action::bypass}) {
            Peer peer(false,Mode::good);
            auto proxy_config = nd::default_config(); nd::Rule r; r.id = 2; r.name = "route"; r.patterns = {"example.com"}; r.action = action;
            auto s = peer.server(); s.id = 2;
            if (action == nd::Action::process) { r.server_id = 2; proxy_config.servers.push_back(s); }
            proxy_config.rules.insert(proxy_config.rules.begin(),r);
            auto proxy_router = std::make_shared<nd::Router>(proxy_config,route_log);
            nd::LocalProxy proxy(proxy_router,peer.server(),route_log); proxy.start();
            auto target = peer.server(); target.port = proxy.status().port; target.protocol = action == nd::Action::process ? nd::Protocol::tcp : nd::Protocol::udp;
            const auto result = nd::test_server(target,"example.com"); proxy.stop(); peer.verify();
            check(result.success && peer.requests == 1 && proxy.status().state == nd::State::stopped,"Client -> real local proxy -> upstream Process/Bypass");
        }
        {
            Peer slow(false,Mode::timeout,false,0,600),fast(false,Mode::good);
            auto concurrent_config=nd::default_config();auto slow_server=slow.server();slow_server.id=7;concurrent_config.servers.push_back(slow_server);
            nd::Rule slow_rule;slow_rule.id=7;slow_rule.name="slow";slow_rule.patterns={"slow.example"};slow_rule.server_id=7;
            concurrent_config.rules.insert(concurrent_config.rules.begin(),slow_rule);
            auto concurrent_router=std::make_shared<nd::Router>(concurrent_config,route_log);
            nd::LocalProxy proxy(concurrent_router,fast.server(),route_log);proxy.start();
            const SOCKET slow_client=connect_loopback(proxy.status().port,SOCK_DGRAM);const auto slow_query=nd::make_query("slow.example");
            check(send(slow_client,reinterpret_cast<const char*>(slow_query.data()),static_cast<int>(slow_query.size()),0)==static_cast<int>(slow_query.size()),"send slow UDP query");
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            auto local=fast.server();local.port=proxy.status().port;
            const auto started=std::chrono::steady_clock::now();const auto result=nd::test_server(local,"example.com");
            const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
            closesocket(slow_client);proxy.stop();slow.verify();fast.verify();
            check(result.success&&elapsed<400,"slow UDP upstream must not block unrelated local proxy queries");
        }
        {
            Peer fast(true,Mode::good);auto concurrent_router=std::make_shared<nd::Router>(nd::default_config(),route_log);
            nd::LocalProxy proxy(concurrent_router,fast.server(),route_log);proxy.start();
            const SOCKET slow_client=connect_loopback(proxy.status().port,SOCK_STREAM);
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            auto local=fast.server();local.port=proxy.status().port;
            const auto started=std::chrono::steady_clock::now();const auto result=nd::test_server(local,"example.com");
            const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
            closesocket(slow_client);proxy.stop();fast.verify();
            check(result.success&&elapsed<1000,"slow TCP client must not block local proxy accept loop");
        }
        {
            Peer peer(true,Mode::good); auto proxy_router = std::make_shared<nd::Router>(nd::default_config(),route_log);
            nd::LocalProxy proxy(proxy_router,peer.server(),route_log); proxy.start();
            auto target = peer.server(); target.port = proxy.status().port; target.protocol = nd::Protocol::udp;
            check(nd::test_server(target).success,"Local proxy Default path"); proxy.stop(); peer.verify();
        }
        {
            auto blocked = nd::default_config(); blocked.rules.back().action = nd::Action::block;
            auto proxy_router = std::make_shared<nd::Router>(blocked,route_log);
            nd::Server unused; unused.name = "unused original"; unused.ip = "127.0.0.1"; unused.port = 1;
            nd::LocalProxy proxy(proxy_router,unused,route_log); proxy.start();
            auto target = unused; target.port = proxy.status().port;
            const auto result = nd::test_server(target); check(result.success && result.addresses == std::vector<std::string>{"0.0.0.0"},"Local proxy Block without upstream");
            nd::LocalProxy collision(proxy_router,unused,route_log,proxy.status().port);
            fails([&] { collision.start(); }); check(collision.status().state == nd::State::error,"Bind failure state"); collision.stop();
            proxy.stop();
            for (unsigned i = 0; i < 25; ++i) { proxy.start(); check(proxy.status().state == nd::State::running,"Stress start"); proxy.stop(); proxy.stop(); }
        }
        nd::Server unsupported; unsupported.protocol = nd::Protocol::doq;
        check(nd::test_server(unsupported).error_code == "NOT_IMPLEMENTED","No fake transport success");
        std::cout << "DNS parser and actual loopback transport tests passed\n";
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
}
