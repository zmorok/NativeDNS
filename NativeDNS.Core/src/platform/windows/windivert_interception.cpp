#include <nativedns/interception.hpp>
#include <nativedns/dns_network.hpp>
#include <nativedns/firewall.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/tcp_dns_proxy.hpp>
#include <nativedns/detail/fault_injection.hpp>
#include <windivert.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <thread>
#include <cwctype>
#include <iphlpapi.h>
#include <sodium.h>

namespace nd {
namespace {
std::wstring normalized_driver_path(std::wstring path) {
    if (path.starts_with(L"\\??\\"))
        path.erase(0, 4);
    std::replace(path.begin(), path.end(), L'/', L'\\');
    std::transform(path.begin(), path.end(), path.begin(), [](wchar_t value) {
        return static_cast<wchar_t>(std::towlower(value));
    });
    return path;
}
enum class WinDivertServiceOwner { missing, application, foreign_or_unknown };
WinDivertServiceOwner windivert_service_owner() {
    const SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager)
        return WinDivertServiceOwner::foreign_or_unknown;
    const SC_HANDLE service = OpenServiceW(manager, L"WinDivert", SERVICE_QUERY_CONFIG);
    if (!service) {
        const bool missing = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
        CloseServiceHandle(manager);
        return missing ? WinDivertServiceOwner::missing : WinDivertServiceOwner::foreign_or_unknown;
    }
    DWORD required = 0;
    (void)QueryServiceConfigW(service, nullptr, 0, &required);
    std::vector<uint8_t> storage(required);
    const auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
    const bool queried = required && QueryServiceConfigW(service, config, required, &required);
    bool owned = false;
    if (queried && config->lpBinaryPathName) {
        const auto expected =
            (platform::windivert_directory() / L"WinDivert64.sys").wstring();
        owned =
            normalized_driver_path(config->lpBinaryPathName) == normalized_driver_path(expected);
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return owned ? WinDivertServiceOwner::application : WinDivertServiceOwner::foreign_or_unknown;
}
bool stop_windivert_service() noexcept {
    const SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager)
        return false;
    const SC_HANDLE service =
        OpenServiceW(manager, L"WinDivert", SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        const bool gone = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
        CloseServiceHandle(manager);
        return gone;
    }
    SERVICE_STATUS status{};
    bool stopped = ControlService(service, SERVICE_CONTROL_STOP, &status) != FALSE ||
                   GetLastError() == ERROR_SERVICE_NOT_ACTIVE;
    for (unsigned attempt = 0; stopped && status.dwCurrentState != SERVICE_STOPPED && attempt < 40;
         ++attempt) {
        Sleep(50);
        stopped = QueryServiceStatus(service, &status) != FALSE;
    }
    stopped = stopped && (status.dwCurrentState == SERVICE_STOPPED || status.dwCurrentState == 0);
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return stopped;
}
uint16_t read16(const uint8_t* bytes) {
    return static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
}
void write16(uint8_t* bytes, uint16_t value) {
    bytes[0] = static_cast<uint8_t>(value >> 8);
    bytes[1] = static_cast<uint8_t>(value);
}
uint32_t checksum_add(uint32_t sum, const uint8_t* bytes, size_t size) {
    while (size >= 2) {
        sum += read16(bytes);
        bytes += 2;
        size -= 2;
    }
    if (size)
        sum += static_cast<uint16_t>(bytes[0] << 8);
    return sum;
}
uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    const auto result = static_cast<uint16_t>(~sum);
    return result ? result : 0xffff;
}
struct UdpView {
    size_t udp = 0, payload = 0;
    bool ipv6 = false;
};
struct TcpView {
    size_t tcp = 0, payload = 0;
    bool ipv6 = false;
};
struct Ipv6Transport {
    uint8_t protocol = 0;
    size_t offset = 40;
};
Ipv6Transport ipv6_transport(const Packet& packet) {
    if (packet.size() < 40 || static_cast<size_t>(read16(packet.data() + 4)) + 40 != packet.size())
        throw Error("INTERCEPT_PACKET", "Invalid IPv6 packet length");
    uint8_t next = packet[6];
    size_t at = 40;
    for (unsigned headers = 0; headers < 16; ++headers) {
        if (next == IPPROTO_UDP || next == IPPROTO_TCP)
            return {next, at};
        if (next == 0 || next == 43 || next == 60) {
            if (at + 2 > packet.size())
                throw Error("INTERCEPT_PACKET", "Truncated IPv6 extension header");
            const size_t length = static_cast<size_t>(packet[at + 1] + 1) * 8;
            if (at + length > packet.size())
                throw Error("INTERCEPT_PACKET", "Invalid IPv6 extension header length");
            next = packet[at];
            at += length;
            continue;
        }
        if (next == 44) {
            if (at + 8 > packet.size())
                throw Error("INTERCEPT_PACKET", "Truncated IPv6 fragment header");
            if ((read16(packet.data() + at + 2) & 0xfff9) != 0)
                throw Error("INTERCEPT_PACKET", "Fragmented IPv6 DNS packet is unsupported");
            next = packet[at];
            at += 8;
            continue;
        }
        if (next == 51) {
            if (at + 2 > packet.size())
                throw Error("INTERCEPT_PACKET", "Truncated IPv6 authentication header");
            const size_t length = static_cast<size_t>(packet[at + 1] + 2) * 4;
            if (at + length > packet.size())
                throw Error("INTERCEPT_PACKET", "Invalid IPv6 authentication header length");
            next = packet[at];
            at += length;
            continue;
        }
        throw Error("INTERCEPT_PACKET", "Unsupported IPv6 next header " + std::to_string(next));
    }
    throw Error("INTERCEPT_PACKET", "Too many IPv6 extension headers");
}
UdpView udp_view(const Packet& packet) {
    if (packet.size() < 28)
        throw Error("INTERCEPT_PACKET", "Captured packet is too short");
    const auto version = packet[0] >> 4;
    UdpView view;
    if (version == 4) {
        const size_t header = static_cast<size_t>(packet[0] & 0x0f) * 4;
        if (header < 20 || header + 8 > packet.size() || packet[9] != IPPROTO_UDP ||
            read16(packet.data() + 2) != packet.size())
            throw Error("INTERCEPT_PACKET", "Invalid IPv4 UDP packet");
        if ((read16(packet.data() + 6) & 0x3fff) != 0)
            throw Error("INTERCEPT_PACKET", "Fragmented DNS packet is unsupported");
        view.udp = header;
    } else if (version == 6) {
        const auto transport = ipv6_transport(packet);
        if (transport.protocol != IPPROTO_UDP || transport.offset + 8 > packet.size())
            throw Error("INTERCEPT_PACKET", "IPv6 packet is not UDP");
        view.udp = transport.offset;
        view.ipv6 = true;
    } else
        throw Error("INTERCEPT_PACKET", "Unsupported IP version");
    view.payload = view.udp + 8;
    if (read16(packet.data() + view.udp + 2) != 53 ||
        read16(packet.data() + view.udp + 4) != packet.size() - view.udp)
        throw Error("INTERCEPT_PACKET", "Packet is not a complete UDP DNS query");
    if (packet.size() - view.payload < 12)
        throw Error("INTERCEPT_PACKET", "DNS payload is too short");
    return view;
}
Server original_server(const Packet& packet, const UdpView& view) {
    char address[INET6_ADDRSTRLEN]{};
    const void* source = view.ipv6 ? static_cast<const void*>(packet.data() + 24)
                                   : static_cast<const void*>(packet.data() + 16);
    if (!InetNtopA(view.ipv6 ? AF_INET6 : AF_INET, source, address, sizeof(address)))
        throw Error("INTERCEPT_PACKET", "Cannot format original DNS address");
    Server server;
    server.name = "Original intercepted resolver";
    server.protocol = Protocol::udp;
    server.ip = address;
    server.port = read16(packet.data() + view.udp + 2);
    return server;
}
std::string destination_ip(const Packet& packet, bool ipv6, uint32_t scope6 = 0) {
    char address[INET6_ADDRSTRLEN]{};
    const void* destination = ipv6 ? static_cast<const void*>(packet.data() + 24)
                                   : static_cast<const void*>(packet.data() + 16);
    if (!InetNtopA(ipv6 ? AF_INET6 : AF_INET, destination, address, sizeof(address)))
        throw Error("INTERCEPT_PACKET", "Cannot format TCP DNS destination");
    std::string result = address;
    if (ipv6 && scope6 && packet[24] == 0xfe && (packet[25] & 0xc0) == 0x80)
        result += '%' + std::to_string(scope6);
    return result;
}
TcpView tcp_view(const Packet& packet) {
    if (packet.size() < 40)
        throw Error("INTERCEPT_PACKET", "Captured TCP packet is too short");
    const auto version = packet[0] >> 4;
    TcpView view;
    if (version == 4) {
        const size_t header = static_cast<size_t>(packet[0] & 0x0f) * 4;
        if (header < 20 || header + 20 > packet.size() || packet[9] != IPPROTO_TCP ||
            read16(packet.data() + 2) != packet.size())
            throw Error("INTERCEPT_PACKET", "Invalid IPv4 TCP packet");
        if ((read16(packet.data() + 6) & 0x3fff) != 0)
            throw Error("INTERCEPT_PACKET", "Fragmented TCP packet is unsupported");
        view.tcp = header;
    } else if (version == 6) {
        const auto transport = ipv6_transport(packet);
        if (transport.protocol != IPPROTO_TCP || transport.offset + 20 > packet.size())
            throw Error("INTERCEPT_PACKET", "IPv6 packet is not TCP");
        view.tcp = transport.offset;
        view.ipv6 = true;
    } else
        throw Error("INTERCEPT_PACKET", "Unsupported IP version");
    const size_t tcp_header = static_cast<size_t>(packet[view.tcp + 12] >> 4) * 4;
    if (tcp_header < 20 || view.tcp + tcp_header > packet.size())
        throw Error("INTERCEPT_PACKET", "Invalid TCP header length");
    view.payload = view.tcp + tcp_header;
    return view;
}
bool is_tcp_packet(const Packet& packet) {
    if (packet.empty())
        return false;
    const auto version = packet[0] >> 4;
    if (version == 4)
        return packet.size() > 9 && packet[9] == IPPROTO_TCP;
    if (version != 6)
        return false;
    return ipv6_transport(packet).protocol == IPPROTO_TCP;
}
} // namespace

Packet make_intercepted_udp_response(const Packet& captured, const Packet& dns_response) {
    const auto view = udp_view(captured);
    if (dns_response.size() < 12 || dns_response.size() > 65507 ||
        view.payload + dns_response.size() > 65535)
        throw Error("INTERCEPT_PACKET", "Invalid DNS response size");
    Packet result(captured.begin(), captured.begin() + static_cast<ptrdiff_t>(view.payload));
    result.insert(result.end(), dns_response.begin(), dns_response.end());
    if (view.ipv6) {
        write16(result.data() + 4, static_cast<uint16_t>(result.size() - 40));
        for (size_t i = 0; i < 16; ++i)
            std::swap(result[8 + i], result[24 + i]);
    } else {
        write16(result.data() + 2, static_cast<uint16_t>(result.size()));
        std::swap_ranges(result.begin() + 12, result.begin() + 16, result.begin() + 16);
    }
    std::swap(result[view.udp], result[view.udp + 2]);
    std::swap(result[view.udp + 1], result[view.udp + 3]);
    write16(result.data() + view.udp + 4, static_cast<uint16_t>(8 + dns_response.size()));
    write16(result.data() + view.udp + 6, 0);
    uint32_t udp_sum = 0;
    if (view.ipv6) {
        udp_sum = checksum_add(udp_sum, result.data() + 8, 32);
        const std::array<uint8_t, 8> suffix{0,
                                            0,
                                            static_cast<uint8_t>((8 + dns_response.size()) >> 8),
                                            static_cast<uint8_t>(8 + dns_response.size()),
                                            0,
                                            0,
                                            0,
                                            IPPROTO_UDP};
        udp_sum = checksum_add(udp_sum, suffix.data(), suffix.size());
    } else {
        udp_sum = checksum_add(udp_sum, result.data() + 12, 8);
        const std::array<uint8_t, 4> suffix{0,
                                            IPPROTO_UDP,
                                            static_cast<uint8_t>((8 + dns_response.size()) >> 8),
                                            static_cast<uint8_t>(8 + dns_response.size())};
        udp_sum = checksum_add(udp_sum, suffix.data(), suffix.size());
    }
    udp_sum = checksum_add(udp_sum, result.data() + view.udp, result.size() - view.udp);
    write16(result.data() + view.udp + 6, checksum_finish(udp_sum));
    if (!view.ipv6) {
        write16(result.data() + 10, 0);
        write16(result.data() + 10, checksum_finish(checksum_add(0, result.data(), view.udp)));
    }
    return result;
}

Packet make_intercepted_tcp_reset(const Packet& captured) {
    const auto view = tcp_view(captured);
    if (read16(captured.data() + view.tcp + 2) != 53)
        throw Error("INTERCEPT_PACKET", "Reset requires a TCP DNS destination");
    if (captured[view.tcp + 13] & 0x04)
        return {}; // Never answer a reset with another reset.
    Packet result(captured.begin(), captured.begin() + static_cast<ptrdiff_t>(view.tcp + 20));
    std::swap(result[view.tcp], result[view.tcp + 2]);
    std::swap(result[view.tcp + 1], result[view.tcp + 3]);
    std::fill(result.begin() + static_cast<ptrdiff_t>(view.tcp + 4), result.end(), 0);
    result[view.tcp + 12] = 0x50;
    if (captured[view.tcp + 13] & 0x10) {
        std::copy_n(captured.begin() + static_cast<ptrdiff_t>(view.tcp + 8),
                    4,
                    result.begin() + static_cast<ptrdiff_t>(view.tcp + 4));
        result[view.tcp + 13] = 0x04;
    } else {
        const auto* sequence = captured.data() + view.tcp + 4;
        uint32_t acknowledgement = (static_cast<uint32_t>(sequence[0]) << 24) |
                                   (static_cast<uint32_t>(sequence[1]) << 16) |
                                   (static_cast<uint32_t>(sequence[2]) << 8) | sequence[3];
        acknowledgement += static_cast<uint32_t>(captured.size() - view.payload) +
                           ((captured[view.tcp + 13] & 0x02) ? 1u : 0u) +
                           ((captured[view.tcp + 13] & 0x01) ? 1u : 0u);
        for (unsigned byte = 0; byte < 4; ++byte)
            result[view.tcp + 8 + byte] = static_cast<uint8_t>(acknowledgement >> (24 - 8 * byte));
        result[view.tcp + 13] = 0x14;
    }
    write16(result.data() + (view.ipv6 ? 4 : 2),
            static_cast<uint16_t>(result.size() - (view.ipv6 ? 40 : 0)));
    return make_reflected_tcp_packet(result, 53, false, 53);
}
bool should_reinject_udp_immediately(const Config& config, const Packet& captured) {
    const auto view = udp_view(captured);
    const Packet query(captured.begin() + static_cast<ptrdiff_t>(view.payload), captured.end());
    const auto question = parse_question(query);
    if (question.flags & 0x8000)
        throw Error("DNS_MALFORMED", "Cannot route a reply as a query");
    return evaluate_rule(config, question.name).reinject_udp;
}

Packet make_reflected_tcp_packet(const Packet& captured,
                                 uint16_t proxy_port,
                                 bool toward_proxy,
                                 uint16_t intercepted_port) {
    const auto view = tcp_view(captured);
    if (!proxy_port || !intercepted_port)
        throw Error("INTERCEPT_PACKET", "TCP reflection port is zero");
    if (toward_proxy && read16(captured.data() + view.tcp + 2) != intercepted_port)
        throw Error("INTERCEPT_PACKET", "TCP packet is not addressed to DNS");
    if (!toward_proxy && read16(captured.data() + view.tcp) != proxy_port)
        throw Error("INTERCEPT_PACKET", "TCP packet is not from the stream proxy");
    Packet result = captured;
    if (view.ipv6) {
        for (size_t i = 0; i < 16; ++i)
            std::swap(result[8 + i], result[24 + i]);
    } else {
        std::swap_ranges(result.begin() + 12, result.begin() + 16, result.begin() + 16);
    }
    write16(result.data() + view.tcp + (toward_proxy ? 2 : 0),
            toward_proxy ? proxy_port : intercepted_port);
    write16(result.data() + view.tcp + 16, 0);
    const size_t tcp_length = result.size() - view.tcp;
    uint32_t tcp_sum = 0;
    if (view.ipv6) {
        tcp_sum = checksum_add(tcp_sum, result.data() + 8, 32);
        const std::array<uint8_t, 8> suffix{static_cast<uint8_t>(tcp_length >> 24),
                                            static_cast<uint8_t>(tcp_length >> 16),
                                            static_cast<uint8_t>(tcp_length >> 8),
                                            static_cast<uint8_t>(tcp_length),
                                            0,
                                            0,
                                            0,
                                            IPPROTO_TCP};
        tcp_sum = checksum_add(tcp_sum, suffix.data(), suffix.size());
    } else {
        tcp_sum = checksum_add(tcp_sum, result.data() + 12, 8);
        const std::array<uint8_t, 4> suffix{0,
                                            IPPROTO_TCP,
                                            static_cast<uint8_t>(tcp_length >> 8),
                                            static_cast<uint8_t>(tcp_length)};
        tcp_sum = checksum_add(tcp_sum, suffix.data(), suffix.size());
    }
    tcp_sum = checksum_add(tcp_sum, result.data() + view.tcp, tcp_length);
    write16(result.data() + view.tcp + 16, checksum_finish(tcp_sum));
    if (!view.ipv6) {
        write16(result.data() + 10, 0);
        write16(result.data() + 10, checksum_finish(checksum_add(0, result.data(), view.tcp)));
    }
    return result;
}

bool is_transient_windivert_send_error(uint32_t error) {
    switch (error) {
        case ERROR_HOST_UNREACHABLE:
        case ERROR_NETWORK_UNREACHABLE:
        case ERROR_PORT_UNREACHABLE:
        case ERROR_PROTOCOL_UNREACHABLE:
        case ERROR_INVALID_PARAMETER:
        case ERROR_NOT_FOUND:
        case ERROR_NO_SYSTEM_RESOURCES:
        case ERROR_INSUFFICIENT_BUFFER:
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_IO_PENDING:
        case ERROR_RETRY:
            return true;
        default:
            return false;
    }
}

std::string windivert_filter(bool intercept_others, uint16_t target_port, uint16_t proxy_port) {
    const std::string injected = intercept_others ? "" : "!impostor and ";
    const auto target = std::to_string(target_port), proxy = std::to_string(proxy_port);
    return "(outbound and !loopback and " + injected +
           "!fragment and udp.DstPort == 53 and udp.PayloadLength >= 12) or (outbound and " +
           injected + "tcp and !fragment and (tcp.DstPort == " + target +
           " or tcp.SrcPort == " + proxy + "))";
}
struct WinDivertInterception::Impl {
    using Open = decltype(&WinDivertOpen);
    using Recv = decltype(&WinDivertRecv);
    using Send = decltype(&WinDivertSend);
    using Shutdown = decltype(&WinDivertShutdown);
    using Close = decltype(&WinDivertClose);
    using SetParam = decltype(&WinDivertSetParam);
    using Compile = decltype(&WinDivertHelperCompileFilter);
    using CalcChecksums = decltype(&WinDivertHelperCalcChecksums);
    Logger& logger;
    Router router;
    detail::TcpDnsProxy tcp_proxy;
    detail::FirewallPortRule firewall;
    mutable std::mutex lifecycle;
    std::mutex operations, test_operation;
    struct Counters {
        std::atomic_uint64_t packets_received{0}, udp_dns_captured{0}, tcp_dns_captured{0};
        std::atomic_uint64_t dns_parse_errors{0}, rules_evaluated{0}, queries_processed{0};
        std::atomic_uint64_t queries_bypassed{0}, queries_blocked{0}, upstream_bypassed{0};
        std::atomic_uint64_t packets_injected{0}, send_errors{0}, receive_errors{0};
        std::atomic_uint64_t worker_queue_overflows{0}, processing_errors{0},
            last_capture_timestamp{0};
        std::atomic_uint64_t active_workers{0};
    } counters;
    std::atomic_bool receiver_active{false}, probe_active{false};
    std::atomic_uint64_t verified_send_errors{0};
    std::atomic_uint32_t consecutive_send_errors{0};
    mutable std::mutex probe_mutex;
    InterceptionTestResult last_test;
    Packet probe_query;
    uint32_t probe_source = 0, probe_destination = 0;
    uint16_t probe_port = 0;
    std::chrono::steady_clock::time_point probe_deadline{}, next_probe{};
    std::string active_filter;
    static uint64_t now_ms() {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count());
    }
    void fail(const std::string& code, const std::string& message) {
        {
            std::lock_guard lock(lifecycle);
            if (state != State::running)
                return;
            error_code = code;
            error_message = message;
            state = State::error;
            shutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
        }
        router.cancel_pending();
        queue_changed.notify_all();
        logger.write_limited(Level::errors_only, "fatal|" + code, code, message);
    }
    bool capture_probe(const Packet& packet, const UdpView& view, WINDIVERT_ADDRESS address) {
        if (!probe_active.load(std::memory_order_acquire) || view.ipv6)
            return false;
        std::lock_guard lock(probe_mutex);
        if (!probe_active || std::chrono::steady_clock::now() > probe_deadline ||
            !address.Outbound || address.Loopback ||
            address.Network.IfIdx != last_test.interface_index ||
            read16(packet.data() + view.udp) != probe_port ||
            std::memcmp(packet.data() + 12, &probe_source, 4) != 0 ||
            std::memcmp(packet.data() + 16, &probe_destination, 4) != 0 ||
            packet.size() - view.payload != probe_query.size() ||
            !std::equal(probe_query.begin(), probe_query.end(), packet.begin() + view.payload))
            return false;
        last_test.captured = true;
        (void)parse_question(probe_query);
        last_test.parsed = true;
        auto response = make_intercepted_udp_response(packet, make_error_response(probe_query, 3));
        address.Outbound = 0;
        address.IPChecksum = 0;
        address.UDPChecksum = 0;
        last_test.injected = inject(response, address);
        return true;
    }
    std::atomic<State> state = State::stopped;
    std::string error_code, error_message;
    HMODULE module = nullptr;
    HANDLE handle = INVALID_HANDLE_VALUE;
    Open open = nullptr;
    Recv recv = nullptr;
    Send send = nullptr;
    Shutdown shutdown = nullptr;
    Close close = nullptr;
    SetParam set_param = nullptr;
    Compile compile = nullptr;
    CalcChecksums calc_checksums = nullptr;
    struct Job {
        Packet packet;
        WINDIVERT_ADDRESS address{};
        Router::SnapshotPtr snapshot;
    };
    mutable std::mutex queue_mutex;
    std::condition_variable queue_changed;
    std::deque<Job> jobs;
    size_t queued_bytes = 0;
    std::jthread receiver;
    std::vector<std::jthread> workers;
    std::atomic<uint64_t> overload_count = 0;
    uint16_t tcp_proxy_port = 0, intercepted_tcp_port;
    bool stop_driver_on_release = false;
    Impl(Config value, Logger& output, uint16_t target)
        : logger(output), router(std::move(value), logger), tcp_proxy(router, logger, target),
          intercepted_tcp_port(target) {
    }
    template <class T> T symbol(const char* name) {
        auto address = GetProcAddress(module, name);
        if (!address)
            throw Error("WINDIVERT_LOAD", std::string("Missing WinDivert export: ") + name);
        return reinterpret_cast<T>(address);
    }
    bool inject(const Packet& packet, WINDIVERT_ADDRESS address) {
        UINT sent = 0;
        const auto ok =
            send(handle, packet.data(), static_cast<UINT>(packet.size()), &sent, &address);
        if (!ok || sent != packet.size()) {
            const auto error = ok ? ERROR_WRITE_FAULT : GetLastError();
            counters.send_errors.fetch_add(1, std::memory_order_relaxed);
            if (address.Impostor && error == ERROR_HOST_UNREACHABLE) {
                logger.write_limited(Level::errors_only,
                                     "impostor-loop",
                                     "INTERCEPT_LOOP_PREVENTED",
                                     "Injected packet exhausted its hop limit");
                return false;
            }
            if (is_transient_windivert_send_error(error)) {
                const auto streak =
                    consecutive_send_errors.fetch_add(1, std::memory_order_relaxed) + 1;
                if (streak < 64) {
                    logger.write_limited(Level::errors_only,
                                         "send-transient|" + std::to_string(error),
                                         "WINDIVERT_SEND_TRANSIENT",
                                         "Transient WinDivertSend failure: " +
                                             std::to_string(error) +
                                             " interface_index=" +
                                             std::to_string(address.Network.IfIdx) +
                                             " streak=" + std::to_string(streak));
                    return false;
                }
            }
            throw Error("WINDIVERT_SEND", "WinDivertSend failed: " + std::to_string(error));
        }
        consecutive_send_errors.store(0, std::memory_order_relaxed);
        counters.packets_injected.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    void process(Job job) {
        try {
            const auto view = udp_view(job.packet);
            const auto query =
                Packet(job.packet.begin() + static_cast<ptrdiff_t>(view.payload), job.packet.end());
            auto original = original_server(job.packet, view);
            if (view.ipv6 && job.packet[24] == 0xfe && (job.packet[25] & 0xc0) == 0x80)
                original.route.scope6 = job.address.Network.IfIdx;
            auto routed = router.route(query, original, job.snapshot);
            if (state != State::running)
                return;
            if (routed.disposition == Disposition::forward_original) {
                inject(job.packet, job.address);
                return;
            }
            if (routed.disposition == Disposition::silent_drop || routed.packet.empty())
                return;
            auto response =
                make_intercepted_udp_response(job.packet, fit_udp_response(query, routed.packet));
            job.address.Outbound = 0;
            job.address.IPChecksum = 0;
            job.address.UDPChecksum = 0;
            inject(response, job.address);
        } catch (const Error& error) {
            if (state == State::running) {
                counters.processing_errors.fetch_add(1, std::memory_order_relaxed);
                if (error.code == "WINDIVERT_SEND")
                    fail(error.code, error.what());
                logger.write_limited(
                    Level::errors_only, "worker|" + error.code, error.code, error.what());
            }
        } catch (const std::exception& error) {
            counters.processing_errors.fetch_add(1, std::memory_order_relaxed);
            fail("INTERCEPT_WORKER", error.what());
        } catch (...) {
            counters.processing_errors.fetch_add(1, std::memory_order_relaxed);
            fail("INTERCEPT_WORKER", "Unknown routing worker exception");
        }
    }
    void reject_overload(const Packet& packet, const UdpView& view, WINDIVERT_ADDRESS address) {
        counters.worker_queue_overflows.fetch_add(1, std::memory_order_relaxed);
        const Packet query(packet.begin() + static_cast<ptrdiff_t>(view.payload), packet.end());
        const auto response = make_intercepted_udp_response(packet, make_error_response(query, 2));
        address.Outbound = 0;
        address.IPChecksum = 0;
        address.UDPChecksum = 0;
        inject(response, address);
        const auto count = ++overload_count;
        if (count == 1 || (count & (count - 1)) == 0)
            logger.write(
                Level::errors_only,
                "WINDIVERT_SATURATED",
                "Routing queue is full; returned SERVFAIL (count=" + std::to_string(count) + ")");
    }
    void receive_loop() {
        receiver_active = true;
        try {
            while (state == State::running) {
                Packet packet(WINDIVERT_MTU_MAX);
                UINT length = 0;
                WINDIVERT_ADDRESS address{};
                if (!recv(handle,
                          packet.data(),
                          static_cast<UINT>(packet.size()),
                          &length,
                          &address)) {
                    const auto error = GetLastError();
                    if (state != State::running) {
                        if (error != ERROR_NO_DATA && error != ERROR_OPERATION_ABORTED) {
                            counters.receive_errors.fetch_add(1, std::memory_order_relaxed);
                            std::lock_guard lock(lifecycle);
                            error_code = "WINDIVERT_RECV";
                            error_message =
                                "Receive failed during shutdown: " + std::to_string(error);
                        }
                        break;
                    }
                    counters.receive_errors.fetch_add(1, std::memory_order_relaxed);
                    throw Error("WINDIVERT_RECV", "WinDivertRecv failed: " + std::to_string(error));
                }
                counters.packets_received.fetch_add(1, std::memory_order_relaxed);
                counters.last_capture_timestamp.store(now_ms(), std::memory_order_relaxed);
                packet.resize(length);
                bool policy_selected = false;
                try {
                    if (is_tcp_packet(packet)) {
                        const auto view = tcp_view(packet);
                        counters.tcp_dns_captured.fetch_add(1, std::memory_order_relaxed);
                        const auto source_port = read16(packet.data() + view.tcp);
                        const auto destination_port = read16(packet.data() + view.tcp + 2);
                        if (!address.Outbound) {
                            inject(packet, address);
                            continue;
                        }
                        if (destination_port == intercepted_tcp_port &&
                            detail::is_network_upstream(true, source_port, view.ipv6)) {
                            counters.upstream_bypassed.fetch_add(1, std::memory_order_relaxed);
                            inject(packet, address);
                            continue;
                        }
                        if (destination_port == 53 && router.snapshot()->options.block_tcp53) {
                            policy_selected = true;
                            auto reset = make_intercepted_tcp_reset(packet);
                            if (!reset.empty()) {
                                address.Outbound = 0;
                                address.IPChecksum = 0;
                                address.TCPChecksum = 0;
                                inject(reset, address);
                            }
                            continue;
                        }
                        const bool toward_proxy = destination_port == intercepted_tcp_port;
                        if (!toward_proxy && source_port != tcp_proxy_port) {
                            inject(packet, address);
                            continue;
                        }
                        policy_selected = true;
                        const auto flags = packet[view.tcp + 13];
                        if (toward_proxy && (flags & 0x02) != 0 && (flags & 0x10) == 0)
                            tcp_proxy.expect_connection(
                                destination_ip(packet, view.ipv6, address.Network.IfIdx),
                                source_port);
                        else if (toward_proxy && (flags & 0x04) != 0)
                            tcp_proxy.forget_connection(
                                destination_ip(packet, view.ipv6, address.Network.IfIdx),
                                source_port);
                        if (logger.enabled(Level::debug))
                            logger.write(Level::debug,
                                         "WINDIVERT_TCP_REFLECT",
                                         std::string(toward_proxy ? "to_proxy" : "to_client") +
                                             " source_port=" + std::to_string(source_port));
                        auto reflected = make_reflected_tcp_packet(
                            packet, tcp_proxy_port, toward_proxy, intercepted_tcp_port);
                        address.Outbound = 0;
                        address.IPChecksum = 0;
                        address.TCPChecksum = 0;
                        if (!calc_checksums(
                                reflected.data(), static_cast<UINT>(reflected.size()), &address, 0))
                            throw Error("WINDIVERT_CHECKSUM",
                                        "Cannot calculate reflected TCP checksums");
                        inject(reflected, address);
                        continue;
                    }
                    const auto view = udp_view(packet);
                    counters.udp_dns_captured.fetch_add(1, std::memory_order_relaxed);
                    if (capture_probe(packet, view, address))
                        continue;
                    const auto source_port = read16(packet.data() + view.udp);
                    const bool upstream =
                        detail::is_network_upstream(false, source_port, view.ipv6);
                    if (upstream) {
                        counters.upstream_bypassed.fetch_add(1, std::memory_order_relaxed);
                        if (logger.enabled(Level::debug))
                            logger.write(Level::debug,
                                         "WINDIVERT_UPSTREAM_BYPASS",
                                         "source_port=" + std::to_string(source_port));
                        inject(packet, address);
                        continue;
                    }
                    policy_selected = true;
                    const auto captured_question = parse_question(Packet(
                        packet.begin() + static_cast<ptrdiff_t>(view.payload), packet.end()));
                    if (captured_question.flags & 0x8000)
                        throw Error("DNS_MALFORMED", "Cannot route a reply as a query");
                    auto snapshot = router.snapshot();
                    const auto captured_decision =
                        evaluate_rule(snapshot->config, captured_question.name);
                    const auto& captured_rule = *captured_decision.rule;
                    if (logger.enabled(Level::debug))
                        logger.write(
                            Level::debug,
                            "DNS_CAPTURE",
                            "transport=udp name=" + captured_question.name + " interface_index=" +
                                std::to_string(address.Network.IfIdx) + " generation=" +
                                std::to_string(NetworkMonitor::shared().snapshot()->generation) +
                                " impostor=" + (address.Impostor ? "1" : "0") +
                                " rule=" + captured_rule.name +
                                " action=" + action_name(captured_rule.action) +
                                " server=" + std::to_string(captured_rule.server_id));
                    if (captured_decision.reinject_udp) {
                        counters.rules_evaluated.fetch_add(1, std::memory_order_relaxed);
                        if (captured_rule.action == Action::bypass)
                            counters.queries_bypassed.fetch_add(1, std::memory_order_relaxed);
                        counters.queries_processed.fetch_add(1, std::memory_order_relaxed);
                        const auto original = original_server(packet, view);
                        if (logger.enabled(Level::normal))
                            logger.write(
                                Level::normal,
                                "DNS_ROUTE",
                                route_log_message(captured_question, captured_rule, &original),
                                {captured_question.name,
                                 dns_type_name(captured_question.type),
                                 captured_rule.name,
                                 action_name(captured_rule.action)});
                        if (logger.enabled(Level::debug))
                            logger.write(
                                Level::debug,
                                "WINDIVERT_RULE_FAST_PATH",
                                captured_question.name +
                                    " bypass/original query reinjected before worker queue");
                        inject(packet, address);
                        continue;
                    }
                    bool queued = false;
                    {
                        std::lock_guard lock(queue_mutex);
                        if (jobs.size() < 4096 &&
                            queued_bytes + packet.size() <= 32 * 1024 * 1024) {
                            queued_bytes += packet.size();
                            jobs.push_back({std::move(packet), address, std::move(snapshot)});
                            queued = true;
                        }
                    }
                    if (queued)
                        queue_changed.notify_one();
                    else
                        reject_overload(packet, view, address);
                } catch (const Error& error) {
                    counters.processing_errors.fetch_add(1, std::memory_order_relaxed);
                    if (error.code == "DNS_MALFORMED" || error.code == "INTERCEPT_PACKET")
                        counters.dns_parse_errors.fetch_add(1, std::memory_order_relaxed);
                    if (error.code == "WINDIVERT_SEND")
                        throw;
                    logger.write_limited(
                        Level::errors_only,
                        "capture|" + error.code + '|' + std::to_string(address.Network.IfIdx),
                        error.code,
                        std::string(error.what()) +
                            " interface_index=" + std::to_string(address.Network.IfIdx));
                    if (!policy_selected) {
                        inject(packet, address);
                    }
                }
            }
        } catch (const Error& error) {
            fail(error.code, error.what());
        } catch (const std::exception& error) {
            counters.processing_errors.fetch_add(1, std::memory_order_relaxed);
            fail("INTERCEPT_RECEIVER", error.what());
        } catch (...) {
            counters.processing_errors.fetch_add(1, std::memory_order_relaxed);
            fail("INTERCEPT_RECEIVER", "Unknown receiver exception");
        }
        receiver_active = false;
        queue_changed.notify_all();
    }
    void worker_loop() {
        struct Active {
            std::atomic_uint64_t& count;
            explicit Active(std::atomic_uint64_t& value) : count(value) {
                ++count;
            }
            ~Active() {
                --count;
            }
        } active(counters.active_workers);
        for (;;) {
            Job job;
            {
                std::unique_lock lock(queue_mutex);
                queue_changed.wait(lock, [&] { return state != State::running || !jobs.empty(); });
                if (state != State::running)
                    return;
                if (jobs.empty())
                    continue;
                job = std::move(jobs.front());
                queued_bytes -= job.packet.size();
                jobs.pop_front();
            }
            process(std::move(job));
        }
    }
    void release() {
        firewall.disable();
        tcp_proxy.stop();
        tcp_proxy_port = 0;
        if (handle != INVALID_HANDLE_VALUE) {
            close(handle);
            handle = INVALID_HANDLE_VALUE;
        }
        if (module) {
            FreeLibrary(module);
            module = nullptr;
        }
        if (stop_driver_on_release) {
            const auto owner = windivert_service_owner();
            if (owner == WinDivertServiceOwner::application && stop_windivert_service())
                logger.write(Level::verbose,
                             "WINDIVERT_DRIVER_STOPPED",
                             "NativeDNS WinDivert driver service stopped");
            else if (owner == WinDivertServiceOwner::missing)
                logger.write(Level::verbose,
                             "WINDIVERT_DRIVER_STOPPED",
                             "NativeDNS WinDivert driver service was already removed");
            else
                logger.write(Level::verbose,
                             "WINDIVERT_DRIVER_RETAINED",
                             "WinDivert service is foreign, still in use, or ownership could not "
                             "be verified");
            stop_driver_on_release = false;
        }
    }
};

WinDivertInterception::WinDivertInterception(Config config,
                                             Logger& logger,
                                             uint16_t intercepted_tcp_port)
    : impl_(std::make_unique<Impl>(std::move(config), logger, intercepted_tcp_port)) {
}
WinDivertInterception::~WinDivertInterception() {
    stop();
}
void WinDivertInterception::start() {
    auto& p = *impl_;
    std::lock_guard operation(p.operations);
    std::unique_lock lock(p.lifecycle);
    if (p.state != State::stopped)
        throw Error("LIFECYCLE", "WinDivert interception is not stopped");
    p.state = State::starting;
    p.error_code.clear();
    p.error_message.clear();
    {
        std::lock_guard probe_lock(p.probe_mutex);
        p.last_test = {};
    }
    try {
        p.router.resume();
        p.firewall.disable();
        for (const auto& conflict : platform::interception_conflicts())
            p.logger.write(conflict.suspected ? Level::errors_only : Level::normal,
                           conflict.code,
                           conflict.message);
        p.logger.write(Level::verbose,
                       "FIREWALL_STALE_CLEANUP",
                       "Removed any stale TCP interception firewall rule");
        detail::fault_point("windivert.tcp_proxy");
        p.tcp_proxy_port = p.tcp_proxy.start();
        p.logger.write(Level::verbose,
                       "TCP_PROXY_STARTED",
                       "TCP reflection proxy listening on port=" +
                           std::to_string(p.tcp_proxy_port));
        try {
            const auto owner = windivert_service_owner();
            p.stop_driver_on_release = owner == WinDivertServiceOwner::missing ||
                                       owner == WinDivertServiceOwner::application;
        } catch (...) {
            p.stop_driver_on_release = false;
        }
        detail::fault_point("windivert.load");
        p.module =
            LoadLibraryExW((platform::windivert_directory() / L"WinDivert.dll").c_str(),
                           nullptr,
                           LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!p.module)
            throw Error("WINDIVERT_LOAD",
                        "Cannot load WinDivert.dll: " + std::to_string(GetLastError()));
        p.logger.write(Level::verbose, "WINDIVERT_LOADED", "WinDivert.dll loaded successfully");
        p.open = p.symbol<Impl::Open>("WinDivertOpen");
        p.recv = p.symbol<Impl::Recv>("WinDivertRecv");
        p.send = p.symbol<Impl::Send>("WinDivertSend");
        p.shutdown = p.symbol<Impl::Shutdown>("WinDivertShutdown");
        p.close = p.symbol<Impl::Close>("WinDivertClose");
        p.set_param = p.symbol<Impl::SetParam>("WinDivertSetParam");
        p.compile = p.symbol<Impl::Compile>("WinDivertHelperCompileFilter");
        p.calc_checksums = p.symbol<Impl::CalcChecksums>("WinDivertHelperCalcChecksums");
        const auto filter = windivert_filter(p.router.snapshot()->options.intercept_others,
                                             p.intercepted_tcp_port,
                                             p.tcp_proxy_port);
        p.active_filter = filter;
        const char* filter_error = nullptr;
        UINT filter_position = 0;
        if (!p.compile(filter.c_str(),
                       WINDIVERT_LAYER_NETWORK,
                       nullptr,
                       0,
                       &filter_error,
                       &filter_position))
            throw Error("WINDIVERT_FILTER",
                        std::string(filter_error ? filter_error : "Invalid filter") + " at " +
                            std::to_string(filter_position));
        detail::fault_point("windivert.open");
        p.handle = p.open(filter.c_str(),
                          WINDIVERT_LAYER_NETWORK,
                          p.router.snapshot()->options.windivert_priority,
                          0);
        if (p.handle == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            throw Error(error == ERROR_ACCESS_DENIED ? "ELEVATION_REQUIRED" : "WINDIVERT_OPEN",
                        "WinDivertOpen failed: " + std::to_string(error));
        }
        p.logger.write(Level::verbose, "WINDIVERT_HANDLE_OPEN", "WinDivert network handle opened");
        if (!p.set_param(p.handle, WINDIVERT_PARAM_QUEUE_TIME, WINDIVERT_PARAM_QUEUE_TIME_MAX) ||
            !p.set_param(p.handle, WINDIVERT_PARAM_QUEUE_LENGTH, 8192) ||
            !p.set_param(p.handle, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX))
            throw Error("WINDIVERT_QUEUE",
                        "Cannot configure WinDivert queue: " + std::to_string(GetLastError()));
        detail::fault_point("windivert.firewall");
        p.firewall.enable(p.tcp_proxy_port);
        p.logger.write(Level::verbose, "FIREWALL_RULE_ACTIVE", "TCP proxy firewall rule enabled");
        p.consecutive_send_errors.store(0, std::memory_order_relaxed);
        p.state = State::running;
        const auto worker_count = std::clamp(std::thread::hardware_concurrency(), 4u, 16u);
        for (unsigned i = 0; i < worker_count; ++i)
            p.workers.emplace_back([&p] {
                try {
                    p.worker_loop();
                } catch (const std::exception& error) {
                    p.fail("INTERCEPT_WORKER", error.what());
                } catch (...) {
                    p.fail("INTERCEPT_WORKER", "Unknown worker loop failure");
                }
            });
        p.receiver = std::jthread([&p] { p.receive_loop(); });
        p.logger.write(Level::normal,
                       "WINDIVERT_STARTED",
                       "Transparent UDP/TCP DNS interception started; TCP proxy port=" +
                           std::to_string(p.tcp_proxy_port) +
                           ", routing workers=" + std::to_string(worker_count));
        p.logger.write(
            Level::verbose,
            "INTERCEPTION_SCOPE",
            "backend=WinDivert priority=" +
                std::to_string(p.router.snapshot()->options.windivert_priority) +
                " UDP/TCP port=53; encrypted OS/application DNS "
                "on HTTPS/TLS/QUIC ports is outside this filter; network-layer process ID is "
                "unavailable; "
                "interceptOthers=" +
                std::to_string(p.router.snapshot()->options.intercept_others));
    } catch (...) {
        const auto failure = std::current_exception();
        p.state = State::stopping;
        p.router.cancel_pending();
        lock.unlock();
        if (p.handle != INVALID_HANDLE_VALUE && p.shutdown)
            p.shutdown(p.handle, WINDIVERT_SHUTDOWN_BOTH);
        p.queue_changed.notify_all();
        if (p.receiver.joinable())
            p.receiver.join();
        for (auto& worker : p.workers)
            if (worker.joinable())
                worker.join();
        p.workers.clear();
        lock.lock();
        {
            std::lock_guard queue_lock(p.queue_mutex);
            p.jobs.clear();
            p.queued_bytes = 0;
        }
        try {
            std::rethrow_exception(failure);
        } catch (const Error& error) {
            p.error_code = error.code;
            p.error_message = error.what();
        } catch (const std::exception& error) {
            p.error_code = "INTERNAL";
            p.error_message = error.what();
        }
        p.release();
        p.state = State::error;
        std::rethrow_exception(failure);
    }
}
void WinDivertInterception::stop() {
    auto& p = *impl_;
    std::lock_guard operation(p.operations);
    {
        std::lock_guard lock(p.lifecycle);
        if (p.state == State::stopped)
            return;
        p.state = State::stopping;
    }
    p.router.cancel_pending();
    if (p.handle != INVALID_HANDLE_VALUE)
        p.shutdown(p.handle, WINDIVERT_SHUTDOWN_BOTH);
    p.queue_changed.notify_all();
    if (p.receiver.joinable())
        p.receiver.join();
    for (auto& worker : p.workers)
        if (worker.joinable())
            worker.join();
    p.workers.clear();
    {
        std::lock_guard lock(p.lifecycle);
        {
            std::lock_guard queue_lock(p.queue_mutex);
            p.jobs.clear();
            p.queued_bytes = 0;
        }
        p.release();
        p.state = State::stopped;
    }
}
void WinDivertInterception::reload(Config config) {
    std::lock_guard operation(impl_->operations);
    const auto options = runtime_options(config);
    if (options.intercept_others != impl_->router.snapshot()->options.intercept_others ||
        options.windivert_priority != impl_->router.snapshot()->options.windivert_priority)
        throw Error("RESTART_REQUIRED",
                    "Changing interceptOthers or windivertPriority requires a CoreHost restart");
    impl_->router.reload(std::move(config));
}
void WinDivertInterception::cancel_pending() {
    impl_->router.cancel_pending();
}
InterceptionStatus WinDivertInterception::status() const {
    const auto& p = *impl_;
    std::lock_guard lock(p.lifecycle);
    return {p.state.load(), p.tcp_proxy_port, true, true, true, p.error_code, p.error_message};
}

InterceptionDiagnostics WinDivertInterception::diagnostics() const {
    auto& p = *impl_;
    InterceptionDiagnostics v;
    {
        std::lock_guard lock(p.lifecycle);
        v.supported = true;
        v.library_loaded = p.module != nullptr;
        v.handle_open = p.handle != INVALID_HANDLE_VALUE;
        v.priority = p.router.snapshot()->options.windivert_priority;
        v.filter = p.active_filter;
        v.health = p.state == State::error ? "ERROR" : "UNVERIFIED";
        std::lock_guard probe_lock(p.probe_mutex);
        v.last_test = p.last_test;
        if (p.state == State::running) {
            if (v.last_test.success())
                v.health = "VERIFIED";
            else if (!v.last_test.in_progress && v.last_test.failure_stage != "NOT_RUN")
                v.health = "DEGRADED";
        }
    }
    v.receiver_active = p.receiver_active.load();
#define ND_LOAD(name) v.name = p.counters.name.load(std::memory_order_relaxed)
    ND_LOAD(packets_received);
    ND_LOAD(udp_dns_captured);
    ND_LOAD(tcp_dns_captured);
    ND_LOAD(dns_parse_errors);
    ND_LOAD(rules_evaluated);
    ND_LOAD(queries_processed);
    ND_LOAD(queries_bypassed);
    ND_LOAD(queries_blocked);
    ND_LOAD(upstream_bypassed);
    ND_LOAD(packets_injected);
    ND_LOAD(send_errors);
    ND_LOAD(receive_errors);
    ND_LOAD(worker_queue_overflows);
    ND_LOAD(processing_errors);
    ND_LOAD(last_capture_timestamp);
    ND_LOAD(active_workers);
#undef ND_LOAD
    const auto routed = p.router.statistics();
    v.rules_evaluated += routed.rules_evaluated;
    v.queries_processed += routed.queries_completed;
    v.queries_blocked += routed.blocked;
    v.queries_bypassed += routed.bypassed;
    v.dns_parse_errors += routed.parse_errors;
    v.processing_errors += routed.route_errors;
    v.negative_replies = routed.negative_replies;
    v.upstream_error_rcodes = routed.upstream_error_rcodes;
    v.upstream_attempts = routed.upstream_attempts;
    v.upstream_replies = routed.upstream_replies;
    v.upstream_errors = routed.upstream_errors;
    {
        std::lock_guard lock(p.queue_mutex);
        v.queued_jobs = p.jobs.size();
        v.queued_bytes = p.queued_bytes;
    }
    if (v.health == "VERIFIED" && v.send_errors > p.verified_send_errors.load())
        v.health = "DEGRADED";
    return v;
}
InterceptionTestResult WinDivertInterception::self_test() {
    auto& p = *impl_;
    std::unique_lock test_lock(p.test_operation, std::try_to_lock);
    if (!test_lock.owns_lock())
        throw Error("DIAGNOSTIC_BUSY", "An interception test is already running");
    std::lock_guard operation(p.operations); // Handle remains open for this bounded operation.
    if (p.state != State::running)
        throw Error("LIFECYCLE", "Interception must be running");
    if (std::chrono::steady_clock::now() < p.next_probe)
        throw Error("DIAGNOSTIC_BUSY", "Wait five seconds between active interception tests");
    p.next_probe = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    {
        std::lock_guard lock(p.probe_mutex);
        p.last_test = {};
        p.last_test.in_progress = true;
        p.last_test.timestamp_ms = Impl::now_ms();
        p.last_test.failure_stage = "SOCKET";
    }
    struct Socket {
        SOCKET value = INVALID_SOCKET;
        ~Socket() {
            if (value != INVALID_SOCKET)
                closesocket(value);
        }
    } client;
    const auto require = [](bool ok, const char* message) {
        if (!ok)
            throw Error("INTERCEPTION_TEST",
                        std::string(message) + " error=" + std::to_string(WSAGetLastError()));
    };
    try {
        if (sodium_init() < 0)
            throw Error("RANDOM", "Cannot initialize secure probe randomness");
        std::array<unsigned char, 16> nonce{};
        randombytes_buf(nonce.data(), nonce.size());
        char hex[33]{};
        sodium_bin2hex(hex, sizeof(hex), nonce.data(), nonce.size());
        auto request = make_query(std::string(hex) + ".interception.invalid");
        randombytes_buf(request.data(), 2);
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(53);
        // TEST-NET address, never a public resolver. TTL 1 further limits leakage.
        InetPtonA(AF_INET, "192.0.2.1", &destination.sin_addr);
        SOCKADDR_INET target{};
        target.Ipv4 = destination;
        SOCKADDR_INET source{};
        MIB_IPFORWARD_ROW2 route{};
        const auto route_error = GetBestRoute2(nullptr, 0, nullptr, &target, 0, &route, &source);
        if (route_error != NO_ERROR || source.si_family != AF_INET ||
            (ntohl(source.Ipv4.sin_addr.s_addr) >> 24) == 127 || source.Ipv4.sin_addr.s_addr == 0)
            throw Error("INTERCEPTION_TEST",
                        "No usable non-loopback IPv4 route; error=" + std::to_string(route_error));
        client.value =
            socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // Not an upstream-registered socket.
        require(client.value != INVALID_SOCKET, "Cannot create probe socket");
        const DWORD iface = htonl(route.InterfaceIndex);
        const int ttl = 1;
        require(setsockopt(client.value,
                           IPPROTO_IP,
                           IP_UNICAST_IF,
                           reinterpret_cast<const char*>(&iface),
                           sizeof(iface)) == 0,
                "Cannot bind probe interface");
        require(setsockopt(client.value,
                           IPPROTO_IP,
                           IP_TTL,
                           reinterpret_cast<const char*>(&ttl),
                           sizeof(ttl)) == 0,
                "Cannot set probe TTL");
        source.Ipv4.sin_port = 0;
        require(
            bind(client.value, reinterpret_cast<sockaddr*>(&source.Ipv4), sizeof(sockaddr_in)) == 0,
            "Cannot bind probe address");
        require(connect(client.value,
                        reinterpret_cast<sockaddr*>(&destination),
                        sizeof(destination)) == 0,
                "Cannot connect probe socket");
        sockaddr_in local{};
        int size = sizeof(local);
        require(getsockname(client.value, reinterpret_cast<sockaddr*>(&local), &size) == 0,
                "Cannot inspect probe socket");
        u_long nonblocking = 1;
        require(ioctlsocket(client.value, FIONBIO, &nonblocking) == 0,
                "Cannot make probe nonblocking");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        {
            std::lock_guard lock(p.probe_mutex);
            p.probe_query = request;
            p.probe_source = local.sin_addr.s_addr;
            p.probe_destination = destination.sin_addr.s_addr;
            p.probe_port = ntohs(local.sin_port);
            p.probe_deadline = deadline;
            p.last_test.interface_index = route.InterfaceIndex;
            p.last_test.failure_stage = "SEND";
            p.probe_active.store(true, std::memory_order_release);
        }
        require(send(client.value,
                     reinterpret_cast<const char*>(request.data()),
                     static_cast<int>(request.size()),
                     0) == static_cast<int>(request.size()),
                "Cannot send UDP/53 probe");
        {
            std::lock_guard lock(p.probe_mutex);
            p.last_test.sent = true;
            p.last_test.failure_stage = "CAPTURE";
        }
        platform::wait_socket(static_cast<std::intptr_t>(client.value), false, deadline);
        Packet response(512);
        const auto count = recv(client.value,
                                reinterpret_cast<char*>(response.data()),
                                static_cast<int>(response.size()),
                                0);
        require(count > 0, "No UDP probe response");
        response.resize(static_cast<size_t>(count));
        const auto expected = make_error_response(request, 3);
        std::lock_guard lock(p.probe_mutex);
        p.last_test.received = response == expected;
        if (!p.last_test.received)
            p.last_test.message = "Unexpected response; synthetic reply was not delivered";
    } catch (const std::exception& error) {
        std::lock_guard lock(p.probe_mutex);
        p.last_test.message = error.what();
    }
    std::lock_guard lock(p.probe_mutex);
    p.probe_active.store(false, std::memory_order_release);
    p.probe_query.clear();
    auto& result = p.last_test;
    result.in_progress = false;
    if (result.success()) {
        p.verified_send_errors = p.counters.send_errors.load();
        result.failure_stage = "NONE";
        result.message = "UDP/IPv4 capture and synthetic reply delivery verified; IPv6, TCP and "
                         "upstream routing are not verified by this probe";
    } else {
        if (result.sent)
            result.failure_stage = !result.captured   ? "CAPTURE"
                                   : !result.parsed   ? "DNS_PARSE"
                                   : !result.injected ? "INJECTION"
                                                      : "DELIVERY";
        result.message +=
            "; possible causes include a competing DNS interceptor, filter scope, network "
            "restrictions or a NativeDNS error; no specific cause is confirmed";
    }
    p.logger.write(result.success() ? Level::normal : Level::errors_only,
                   "INTERCEPTION_SELF_TEST",
                   "stage=" + result.failure_stage + " " + result.message);
    return result;
}
} // namespace nd
