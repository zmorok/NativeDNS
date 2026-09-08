#include <nativedns/dns.hpp>
#include <nativedns/dns_network.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <thread>

namespace nd {
namespace {
struct Winsock {
    Winsock() { WSADATA data{}; const int rc = WSAStartup(MAKEWORD(2, 2), &data); if (rc) throw Error("SOCKET_INIT", "WSAStartup: " + std::to_string(rc)); }
    ~Winsock() { WSACleanup(); }
};
void initialize() { static Winsock winsock; }
struct Socket {
    SOCKET value = INVALID_SOCKET;
    explicit Socket(SOCKET s) : value(s) { if (s == INVALID_SOCKET) throw Error("SOCKET", "Socket creation: " + std::to_string(WSAGetLastError())); }
    ~Socket() { closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};
using Clock = detail::NetworkClock;
void socket_error(const char* operation) {
    const auto code = WSAGetLastError();
    throw Error(code == WSAETIMEDOUT ? "TIMEOUT" : "SOCKET", std::string(operation) + ": Winsock " + std::to_string(code));
}
void ready(SOCKET socket, bool writing, Clock::time_point deadline) {
    auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - Clock::now());
    if (remaining.count() <= 0) throw Error("TIMEOUT", "DNS request deadline exceeded");
    timeval timeout{static_cast<long>(remaining.count() / 1000000), static_cast<long>(remaining.count() % 1000000)};
    fd_set requested, errors; FD_ZERO(&requested); FD_ZERO(&errors); FD_SET(socket, &requested); FD_SET(socket, &errors);
    const int result = select(0, writing ? nullptr : &requested, writing ? &requested : nullptr, &errors, &timeout);
    if (result == SOCKET_ERROR) socket_error("select");
    if (!result) throw Error("TIMEOUT", "DNS request timed out");
    if (FD_ISSET(socket, &errors)) {
        int error = 0; int size = sizeof(error);
        if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) == SOCKET_ERROR) socket_error("getsockopt");
        throw Error("SOCKET", "Socket operation failed: Winsock " + std::to_string(error));
    }
}
void transfer(SOCKET socket, uint8_t* bytes, size_t size, bool sending, Clock::time_point deadline) {
    size_t at = 0;
    while (at < size) {
        ready(socket, sending, deadline);
        const int result = sending ? send(socket, reinterpret_cast<const char*>(bytes + at), static_cast<int>(size - at), 0)
                                   : recv(socket, reinterpret_cast<char*>(bytes + at), static_cast<int>(size - at), 0);
        if (result == SOCKET_ERROR) { if (WSAGetLastError() == WSAEWOULDBLOCK) continue; socket_error(sending ? "send" : "recv"); }
        if (!result) throw Error("DNS_EOF", "Connection closed before a complete DNS frame");
        at += static_cast<size_t>(result);
    }
}
std::mutex upstream_mutex;
std::map<std::pair<bool,uint16_t>,size_t> upstream_sockets;
}
namespace detail {
NetworkUpstreamGuard::NetworkUpstreamGuard(bool tcp, uint16_t local_port) : tcp_(tcp),local_port_(local_port) {
    const std::lock_guard lock(upstream_mutex); ++upstream_sockets[{tcp_,local_port_}];
}
NetworkUpstreamGuard::~NetworkUpstreamGuard() {
    const std::lock_guard lock(upstream_mutex); const auto key=std::pair{tcp_,local_port_};
    const auto found=upstream_sockets.find(key); if(found!=upstream_sockets.end()&&!--found->second) upstream_sockets.erase(found);
}
bool is_network_upstream(bool tcp,uint16_t local_port) {
    const std::lock_guard lock(upstream_mutex); return upstream_sockets.contains({tcp,local_port});
}
Packet exchange_network(const Packet& request, const Server& server, bool tcp, Clock::time_point deadline) {
    initialize();
    sockaddr_storage address{}; int address_size = 0;
    auto* v4 = reinterpret_cast<sockaddr_in*>(&address); auto* v6 = reinterpret_cast<sockaddr_in6*>(&address);
    if (InetPtonA(AF_INET, server.ip.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET; v4->sin_port = htons(server.port ? server.port : 53); address_size = sizeof(*v4);
    } else if (InetPtonA(AF_INET6, server.ip.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6; v6->sin6_port = htons(server.port ? server.port : 53); address_size = sizeof(*v6);
    } else throw Error("ENDPOINT", "DNS network transport requires a numeric IP");
    Socket socket(::socket(address.ss_family, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP));
    u_long nonblocking = 1;
    if (ioctlsocket(socket.value, FIONBIO, &nonblocking) == SOCKET_ERROR) socket_error("nonblocking");
    sockaddr_storage local{}; int local_size = address.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    local.ss_family = address.ss_family;
    if (bind(socket.value,reinterpret_cast<const sockaddr*>(&local),local_size) == SOCKET_ERROR) socket_error("local bind");
    if (getsockname(socket.value,reinterpret_cast<sockaddr*>(&local),&local_size) == SOCKET_ERROR) socket_error("local endpoint");
    const uint16_t local_port = ntohs(address.ss_family == AF_INET ? reinterpret_cast<const sockaddr_in*>(&local)->sin_port
                                                                    : reinterpret_cast<const sockaddr_in6*>(&local)->sin6_port);
    NetworkUpstreamGuard upstream(tcp,local_port);
    if (connect(socket.value, reinterpret_cast<const sockaddr*>(&address), address_size) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) socket_error("connect");
        ready(socket.value, true, deadline);
        int error = 0, length = sizeof(error);
        if (getsockopt(socket.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == SOCKET_ERROR) socket_error("connect result");
        if (error) throw Error("SOCKET", "Connect failed: Winsock " + std::to_string(error));
    }
    if (tcp) {
        Packet frame{static_cast<uint8_t>(request.size() >> 8), static_cast<uint8_t>(request.size())};
        frame.insert(frame.end(), request.begin(), request.end());
        transfer(socket.value, frame.data(), frame.size(), true, deadline);
        uint8_t prefix[2]{}; transfer(socket.value, prefix, 2, false, deadline);
        const size_t length = static_cast<size_t>((prefix[0] << 8) | prefix[1]);
        if (length < 12) throw Error("DNS_MALFORMED", "Invalid TCP DNS frame length");
        Packet response(length); transfer(socket.value, response.data(), response.size(), false, deadline); return response;
    }
    ready(socket.value, true, deadline);
    const int sent = send(socket.value, reinterpret_cast<const char*>(request.data()), static_cast<int>(request.size()), 0);
    if (sent == SOCKET_ERROR) socket_error("UDP send");
    if (sent != static_cast<int>(request.size())) throw Error("SOCKET", "Incomplete UDP send");
    Packet response(65535);
    ready(socket.value, false, deadline);
    const int received = recv(socket.value, reinterpret_cast<char*>(response.data()), static_cast<int>(response.size()), 0);
    if (received == SOCKET_ERROR) socket_error("UDP receive");
    response.resize(static_cast<size_t>(received)); return response;
}
}
namespace {
class PlainTransport final : public IDnsTransport {
public:
    explicit PlainTransport(bool tcp) : tcp_(tcp) {}
    Packet exchange(const Packet& request, const Server& server) override {
        if (!server.enabled) throw Error("SERVER_DISABLED", "DNS server is disabled");
        if (!server.timeout_ms || server.timeout_ms > 120000) throw Error("CONFIG", "Invalid request timeout");
        const auto q = parse_question(request);
        if (q.flags & 0x8000) throw Error("DNS_MALFORMED", "Expected query, not response");
        const auto deadline = Clock::now() + std::chrono::milliseconds(server.timeout_ms);
        auto response = detail::exchange_network(request, server, tcp_, deadline);
        auto parsed = parse_response(response, q);
        if (parsed.truncated && !tcp_) {
            response = detail::exchange_network(request, server, true, deadline);
            parsed = parse_response(response, q);
        }
        if (parsed.truncated) throw Error("DNS_TRUNCATED", "Truncated response over TCP");
        return response;
    }
private: bool tcp_;
};
}
std::unique_ptr<IDnsTransport> make_secure_transport(Protocol protocol);
std::unique_ptr<IDnsTransport> make_dnscrypt_transport(Protocol protocol);
std::unique_ptr<IDnsTransport> make_transport(Protocol protocol) {
    if (protocol == Protocol::udp) return std::make_unique<PlainTransport>(false);
    if (protocol == Protocol::tcp) return std::make_unique<PlainTransport>(true);
    if (protocol == Protocol::doh || protocol == Protocol::dot) return make_secure_transport(protocol);
    if (protocol == Protocol::dnscrypt || protocol == Protocol::anonymized_dnscrypt) return make_dnscrypt_transport(protocol);
    throw Error("NOT_IMPLEMENTED", "Transport not implemented: " + protocol_name(protocol));
}
TestResult test_server(const Server& server, const std::string& hostname, uint16_t type, Logger* logger) {
    TestResult result;
    result.protocol = server.protocol; result.server_id = server.id; result.hostname = hostname; result.query_type = type;
    const auto start = Clock::now();
    try {
        if (type != 1 && type != 28) throw Error("QUERY_TYPE", "Server tester requires A or AAAA");
        auto request = make_query(hostname, type);
        auto response = make_transport(server.protocol)->exchange(request, server);
        const auto answer = parse_response(response, parse_question(request));
        result.rcode = answer.rcode; result.authenticated_data = answer.authenticated_data; result.addresses = answer.addresses;
        if (answer.rcode) throw Error("DNS_RCODE", "DNS failure response: RCODE " + std::to_string(answer.rcode));
        if (answer.addresses.empty()) throw Error("DNS_NO_ADDRESS", "DNS response has no matching address answer");
        result.success = true; result.message = "OK";
    } catch (const Error& error) { result.error_code = error.code; result.message = error.what(); }
      catch (const std::exception& error) { result.error_code = "INTERNAL"; result.message = error.what(); }
    result.rtt_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
    if (logger) logger->write(result.success ? Level::normal : Level::errors_only, result.success ? "DNS_TEST_OK" : result.error_code,
        "server=" + std::to_string(server.id) + " host=" + hostname + " " + result.message + " elapsed_ms=" + std::to_string(result.rtt_ms));
    return result;
}
std::vector<TestResult> test_servers(const Config& config, Logger* logger) {
    validate(config);
    std::vector<TestResult> results(config.servers.size());
    std::atomic<size_t> index = 0;
    std::vector<std::jthread> workers;
    for (size_t i = 0; i < std::min<size_t>(config.test_concurrency, config.servers.size()); ++i) {
        workers.emplace_back([&] {
            for (;;) { const auto at = index.fetch_add(1); if (at >= results.size()) return;
                results[at] = test_server(config.servers[at], config.test_target, 1, logger); }
        });
    }
    for (auto& worker : workers) worker.join();
    return results;
}
}
