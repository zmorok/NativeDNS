#include <nativedns/dns.hpp>
#include <nativedns/dns_network.hpp>
#include "../../pool_limits.hpp"
#include <nativedns/platform.hpp>
#include <nativedns/detail/cancellation.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <tuple>

namespace nd {
namespace {
struct Winsock {
    Winsock() {
        WSADATA data{};
        const int rc = WSAStartup(MAKEWORD(2, 2), &data);
        if (rc)
            throw Error("SOCKET_INIT", "WSAStartup: " + std::to_string(rc));
    }
    ~Winsock() {
        WSACleanup();
    }
};
void initialize() {
    static Winsock winsock;
}
struct Socket {
    SOCKET value = INVALID_SOCKET;
    explicit Socket(SOCKET s) : value(s) {
        if (s == INVALID_SOCKET)
            throw Error("SOCKET", "Socket creation: " + std::to_string(WSAGetLastError()));
    }
    ~Socket() {
        closesocket(value);
    }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};
using Clock = detail::NetworkClock;
void socket_error(const char* operation) {
    const auto code = WSAGetLastError();
    throw Error(code == WSAETIMEDOUT ? "TIMEOUT" : "SOCKET",
                std::string(operation) + ": Winsock " + std::to_string(code));
}
void ready(SOCKET socket, bool writing, Clock::time_point deadline) {
    platform::wait_socket(static_cast<std::intptr_t>(socket), writing, deadline);
    int error = 0;
    int size = sizeof(error);
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) ==
        SOCKET_ERROR)
        socket_error("getsockopt");
    if (error)
        throw Error("SOCKET", "Socket operation failed: Winsock " + std::to_string(error));
}
void transfer(
    SOCKET socket, uint8_t* bytes, size_t size, bool sending, Clock::time_point deadline) {
    size_t at = 0;
    while (at < size) {
        ready(socket, sending, deadline);
        const int result =
            sending
                ? send(socket,
                       reinterpret_cast<const char*>(bytes + at),
                       static_cast<int>(size - at),
                       0)
                : recv(socket, reinterpret_cast<char*>(bytes + at), static_cast<int>(size - at), 0);
        if (result == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK)
                continue;
            socket_error(sending ? "send" : "recv");
        }
        if (!result)
            throw Error("DNS_EOF", "Connection closed before a complete DNS frame");
        at += static_cast<size_t>(result);
    }
}
std::mutex upstream_mutex;
std::map<std::tuple<bool, uint16_t, bool>, size_t> upstream_sockets;
} // namespace
namespace detail {
NetworkUpstreamGuard::NetworkUpstreamGuard(bool tcp, uint16_t local_port, bool ipv6)
    : tcp_(tcp), local_port_(local_port), ipv6_(ipv6) {
    const std::lock_guard lock(upstream_mutex);
    ++upstream_sockets[{tcp_, local_port_, ipv6_}];
}
NetworkUpstreamGuard::~NetworkUpstreamGuard() {
    const std::lock_guard lock(upstream_mutex);
    const auto key = std::tuple{tcp_, local_port_, ipv6_};
    const auto found = upstream_sockets.find(key);
    if (found != upstream_sockets.end() && !--found->second)
        upstream_sockets.erase(found);
}
bool is_network_upstream(bool tcp, uint16_t local_port, bool ipv6) {
    const std::lock_guard lock(upstream_mutex);
    return upstream_sockets.contains({tcp, local_port, ipv6});
}
} // namespace detail
namespace {
struct ConnectedSocket {
    std::unique_ptr<detail::NetworkUpstreamGuard> upstream;
    std::unique_ptr<Socket> socket;
};
ConnectedSocket connect_network(const Server& server, bool tcp, Clock::time_point deadline) {
    initialize();
    sockaddr_storage address{};
    int address_size = 0;
    auto* v4 = reinterpret_cast<sockaddr_in*>(&address);
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&address);
    const auto numeric = parse_numeric_endpoint(server.ip);
    if (InetPtonA(AF_INET, numeric.address.c_str(), &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(server.port ? server.port : 53);
        address_size = sizeof(*v4);
    } else if (InetPtonA(AF_INET6, numeric.address.c_str(), &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(server.port ? server.port : 53);
        v6->sin6_scope_id = numeric.scope6 ? numeric.scope6 : server.route.scope6;
        address_size = sizeof(*v6);
    } else
        throw Error("ENDPOINT", "DNS network transport requires a numeric IP");
    std::unique_ptr<detail::NetworkUpstreamGuard> upstream;
    auto socket = std::make_unique<Socket>(::socket(
        address.ss_family, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP));
    platform::bind_upstream_interface(static_cast<std::intptr_t>(socket->value), server.route);
    u_long nonblocking = 1;
    if (ioctlsocket(socket->value, FIONBIO, &nonblocking) == SOCKET_ERROR)
        socket_error("nonblocking");
    sockaddr_storage local{};
    int local_size = address.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    local.ss_family = address.ss_family;
    if (bind(socket->value, reinterpret_cast<const sockaddr*>(&local), local_size) == SOCKET_ERROR)
        socket_error("local bind");
    if (getsockname(socket->value, reinterpret_cast<sockaddr*>(&local), &local_size) ==
        SOCKET_ERROR)
        socket_error("local endpoint");
    const uint16_t local_port = ntohs(
        address.ss_family == AF_INET ? reinterpret_cast<const sockaddr_in*>(&local)->sin_port
                                     : reinterpret_cast<const sockaddr_in6*>(&local)->sin6_port);
    upstream = std::make_unique<detail::NetworkUpstreamGuard>(
        tcp, local_port, address.ss_family == AF_INET6);
    if (connect(socket->value, reinterpret_cast<const sockaddr*>(&address), address_size) ==
        SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK)
            socket_error("connect");
        ready(socket->value, true, deadline);
        int error = 0, length = sizeof(error);
        if (getsockopt(
                socket->value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) ==
            SOCKET_ERROR)
            socket_error("connect result");
        if (error)
            throw Error("SOCKET", "Connect failed: Winsock " + std::to_string(error));
    }
    return {std::move(upstream), std::move(socket)};
}
Packet
exchange_tcp(ConnectedSocket& connection, const Packet& request, Clock::time_point deadline) {
    const auto socket = connection.socket->value;
    Packet frame{static_cast<uint8_t>(request.size() >> 8), static_cast<uint8_t>(request.size())};
    frame.insert(frame.end(), request.begin(), request.end());
    transfer(socket, frame.data(), frame.size(), true, deadline);
    uint8_t prefix[2]{};
    transfer(socket, prefix, 2, false, deadline);
    const size_t length = static_cast<size_t>((prefix[0] << 8) | prefix[1]);
    if (length < 12)
        throw Error("DNS_MALFORMED", "Invalid TCP DNS frame length");
    Packet response(length);
    transfer(socket, response.data(), response.size(), false, deadline);
    return response;
}
} // namespace
namespace detail {
Packet exchange_network(const Packet& request,
                        const Server& server,
                        bool tcp,
                        Clock::time_point deadline) {
    auto connection = connect_network(server, tcp, deadline);
    const auto socket = connection.socket->value;
    if (tcp) {
        return exchange_tcp(connection, request, deadline);
    }
    ready(socket, true, deadline);
    const int sent = send(
        socket, reinterpret_cast<const char*>(request.data()), static_cast<int>(request.size()), 0);
    if (sent == SOCKET_ERROR)
        socket_error("UDP send");
    if (sent != static_cast<int>(request.size()))
        throw Error("SOCKET", "Incomplete UDP send");
    Packet response(65535);
    ready(socket, false, deadline);
    const int received = recv(
        socket, reinterpret_cast<char*>(response.data()), static_cast<int>(response.size()), 0);
    if (received == SOCKET_ERROR)
        socket_error("UDP receive");
    response.resize(static_cast<size_t>(received));
    return response;
}
} // namespace detail
namespace {
class PlainTransport final : public IDnsTransport {
public:
    explicit PlainTransport(bool tcp) : tcp_(tcp) {
    }
    Packet exchange(const Packet& request, const Server& configured_server) override {
        const auto server = with_network_context(configured_server);
        if (!server.enabled)
            throw Error("SERVER_DISABLED", "DNS server is disabled");
        if (!server.timeout_ms || server.timeout_ms > 120000)
            throw Error("CONFIG", "Invalid request timeout");
        const auto q = parse_question(request);
        if (q.flags & 0x8000)
            throw Error("DNS_MALFORMED", "Expected query, not response");
        const auto deadline = Clock::now() + std::chrono::milliseconds(server.timeout_ms);
        auto response = tcp_ ? pooled_tcp(request, server, deadline)
                             : detail::exchange_network(request, server, false, deadline);
        auto parsed = parse_response(response, q);
        if (parsed.truncated && !tcp_) {
            response = pooled_tcp(request, server, deadline);
            parsed = parse_response(response, q);
        }
        if (parsed.truncated)
            throw Error("DNS_TRUNCATED", "Truncated response over TCP");
        return response;
    }

private:
    struct Entry {
        bool busy = false;
        uint64_t generation = 0;
        std::unique_ptr<ConnectedSocket> connection;
        Clock::time_point last_used{};
    };
    struct Lease {
        PlainTransport& owner;
        std::shared_ptr<Entry> entry;
        ~Lease() {
            std::lock_guard lock(owner.pool_mutex_);
            entry->busy = false;
            owner.pool_changed_.notify_one();
        }
    };
    Packet pooled_tcp(const Packet& request, const Server& server, Clock::time_point deadline) {
        const auto key = server.ip + ":" + std::to_string(server.port ? server.port : 53) + '|' +
                         network_route_key(server.route);
        std::shared_ptr<Entry> selected;
        {
            std::unique_lock lock(pool_mutex_);
            for (auto item = pool_.begin(); item != pool_.end();) {
                const bool stale =
                    std::all_of(item->second.begin(), item->second.end(), [&](const auto& entry) {
                        return !entry->busy && entry->generation != server.route.generation;
                    });
                if (stale)
                    item = pool_.erase(item);
                else
                    ++item;
            }
            for (;;) {
                detail::limit_idle_pool(pool_, key);
                auto& entries = pool_[key];
                const auto found = std::find_if(
                    entries.begin(), entries.end(), [](const auto& entry) { return !entry->busy; });
                if (found != entries.end()) {
                    selected = *found;
                    selected->busy = true;
                    break;
                }
                if (entries.size() < 4) {
                    selected = std::make_shared<Entry>();
                    selected->generation = server.route.generation;
                    selected->busy = true;
                    entries.push_back(selected);
                    break;
                }
                if (detail::wait_until_change(pool_changed_, lock, deadline) ==
                    std::cv_status::timeout)
                    throw Error("TIMEOUT", "DNS TCP connection pool is busy");
            }
        }
        Lease lease{*this, selected};
        if (selected->connection && Clock::now() - selected->last_used > std::chrono::seconds(30))
            selected->connection.reset();
        for (unsigned attempt = 0; attempt < 2; ++attempt) {
            try {
                if (!selected->connection)
                    selected->connection =
                        std::make_unique<ConnectedSocket>(connect_network(server, true, deadline));
                auto response = exchange_tcp(*selected->connection, request, deadline);
                selected->last_used = Clock::now();
                return response;
            } catch (const Error& error) {
                selected->connection.reset();
                if (attempt ||
                    !(error.code == "TIMEOUT" || error.code == "SOCKET" || error.code == "DNS_EOF"))
                    throw;
            }
        }
        throw Error("SOCKET", "DNS TCP retry failed");
    }
    bool tcp_;
    std::mutex pool_mutex_;
    std::condition_variable pool_changed_;
    std::map<std::string, std::vector<std::shared_ptr<Entry>>> pool_;
};
} // namespace
std::unique_ptr<IDnsTransport> make_secure_transport(Protocol protocol);
std::unique_ptr<IDnsTransport> make_dnscrypt_transport(Protocol protocol);
std::unique_ptr<IDnsTransport> make_transport(Protocol protocol) {
    if (protocol == Protocol::udp)
        return std::make_unique<PlainTransport>(false);
    if (protocol == Protocol::tcp)
        return std::make_unique<PlainTransport>(true);
    if (protocol == Protocol::doh || protocol == Protocol::dot)
        return make_secure_transport(protocol);
    if (protocol == Protocol::dnscrypt || protocol == Protocol::anonymized_dnscrypt)
        return make_dnscrypt_transport(protocol);
    throw Error("NOT_IMPLEMENTED", "Transport not implemented: " + protocol_name(protocol));
}
TestResult
test_server(const Server& server, const std::string& hostname, uint16_t type, Logger* logger) {
    TestResult result;
    result.protocol = server.protocol;
    result.server_id = server.id;
    result.hostname = hostname;
    result.query_type = type;
    const auto start = Clock::now();
    try {
        if (type != 1 && type != 28)
            throw Error("QUERY_TYPE", "Server tester requires A or AAAA");
        auto request = make_query(hostname, type);
        auto response = make_transport(server.protocol)->exchange(request, server);
        const auto answer = parse_response(response, parse_question(request));
        result.rcode = answer.rcode;
        result.authenticated_data = answer.authenticated_data;
        result.addresses = answer.addresses;
        if (answer.rcode)
            throw Error("DNS_RCODE", "DNS failure response: RCODE " + std::to_string(answer.rcode));
        if (answer.addresses.empty())
            throw Error("DNS_NO_ADDRESS", "DNS response has no matching address answer");
        result.success = true;
        result.message = "OK";
    } catch (const Error& error) {
        result.error_code = error.code;
        result.message = error.what();
    } catch (const std::exception& error) {
        result.error_code = "INTERNAL";
        result.message = error.what();
    }
    result.rtt_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
    if (logger)
        logger->write(result.success ? Level::normal : Level::errors_only,
                      result.success ? "DNS_TEST_OK" : result.error_code,
                      "server=" + std::to_string(server.id) + " host=" + hostname + " " +
                          result.message + " elapsed_ms=" + std::to_string(result.rtt_ms));
    return result;
}
std::vector<TestResult> test_servers(const Config& config, Logger* logger) {
    validate(config);
    std::vector<TestResult> results(config.servers.size());
    std::atomic<size_t> index = 0;
    std::vector<std::jthread> workers;
    for (size_t i = 0; i < std::min<size_t>(config.test_concurrency, config.servers.size()); ++i) {
        workers.emplace_back([&] {
            for (;;) {
                const auto at = index.fetch_add(1);
                if (at >= results.size())
                    return;
                results[at] = test_server(config.servers[at], config.test_target, 1, logger);
            }
        });
    }
    for (auto& worker : workers)
        worker.join();
    return results;
}
} // namespace nd
