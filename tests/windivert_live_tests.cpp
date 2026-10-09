#include <nativedns/host.hpp>
#include <nativedns/network.hpp>
#include <nativedns/platform.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <fstream>
#include <iostream>

namespace {
using Clock = std::chrono::steady_clock;
void check(bool condition, const std::string& message) {
    if (!condition)
        throw std::runtime_error(message + " (Winsock " + std::to_string(WSAGetLastError()) + ")");
}
struct Socket {
    SOCKET value;
    explicit Socket(bool tcp) : value(socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0)) {
        check(value != INVALID_SOCKET, "Create raw test socket");
        u_long nonblocking = 1;
        if (ioctlsocket(value, FIONBIO, &nonblocking)) {
            closesocket(value);
            throw std::runtime_error("Set raw test socket nonblocking");
        }
    }
    ~Socket() {
        closesocket(value);
    }
    Socket(const Socket&) = delete;
};
void transfer(SOCKET socket, uint8_t* data, size_t size, bool writing, Clock::time_point deadline) {
    size_t at = 0;
    while (at < size) {
        nd::platform::wait_socket(static_cast<std::intptr_t>(socket), writing, deadline);
        const auto count =
            writing
                ? send(socket,
                       reinterpret_cast<const char*>(data + at),
                       static_cast<int>(size - at),
                       0)
                : recv(socket, reinterpret_cast<char*>(data + at), static_cast<int>(size - at), 0);
        if (count < 0 && WSAGetLastError() == WSAEWOULDBLOCK)
            continue;
        check(count > 0, writing ? "Send DNS frame" : "Receive DNS frame");
        at += static_cast<size_t>(count);
    }
}
nd::Packet query(bool tcp, const std::string& destination, const std::string& name) {
    Socket client(tcp); // Intentionally bypasses NativeDNS' upstream socket registry.
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(53);
    check(inet_pton(AF_INET, destination.c_str(), &address.sin_addr) == 1,
          "Numeric test destination");
    const auto deadline = Clock::now() + std::chrono::seconds(8);
    const int connected =
        connect(client.value, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (connected) {
        check(WSAGetLastError() == WSAEWOULDBLOCK, "Connect raw DNS client");
        nd::platform::wait_socket(static_cast<std::intptr_t>(client.value), true, deadline);
        int error = 0, size = sizeof(error);
        check(getsockopt(
                  client.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) == 0,
              "Read DNS connection result");
        if (error)
            throw nd::Error("RAW_CONNECT", "Winsock " + std::to_string(error));
    }
    auto request = nd::make_query(name);
    if (!tcp) {
        transfer(client.value, request.data(), request.size(), true, deadline);
        nd::platform::wait_socket(static_cast<std::intptr_t>(client.value), false, deadline);
        nd::Packet response(65535);
        const int count = recv(client.value,
                               reinterpret_cast<char*>(response.data()),
                               static_cast<int>(response.size()),
                               0);
        check(count > 0, "Receive UDP DNS response");
        response.resize(static_cast<size_t>(count));
        (void)nd::parse_response(response, nd::parse_question(request));
        return response;
    }
    nd::Packet framed{static_cast<uint8_t>(request.size() >> 8),
                      static_cast<uint8_t>(request.size())};
    framed.insert(framed.end(), request.begin(), request.end());
    transfer(client.value, framed.data(), framed.size(), true, deadline);
    uint8_t prefix[2]{};
    transfer(client.value, prefix, 2, false, deadline);
    const size_t length = (static_cast<size_t>(prefix[0]) << 8) | prefix[1];
    check(length >= 12, "Valid TCP DNS response length");
    nd::Packet response(length);
    transfer(client.value, response.data(), response.size(), false, deadline);
    (void)nd::parse_response(response, nd::parse_question(request));
    return response;
}
void reload(nd::Config& config, const std::filesystem::path& path, const std::string& pipe) {
    nd::save_config(config, path);
    const auto response = nd::pipe_request(pipe, nd::IpcOperation::reload_config);
    check(response.status == 0 && response.payload == "RELOADED",
          "Live transactional reload: " + response.payload);
}
void exercise(std::ostream& output, const std::filesystem::path& directory) {
    check(nd::platform::is_elevated(), "Real WinDivert tests require elevation");
    for (const auto& conflict : nd::platform::interception_conflicts())
        if (conflict.suspected)
            throw std::runtime_error("Test environment conflict: " + conflict.message);
    auto config = nd::default_config();
    config.logging.file_enabled = false;
    config.logging.screen = nd::Level::debug;
    config.rules.back().action = nd::Action::bypass;
    nd::Rule selected;
    selected.id = 2;
    selected.name = "Live interception test";
    selected.patterns = {"native-dns-live.invalid", "iana.org"};
    selected.action = nd::Action::block;
    selected.block_mode = nd::BlockMode::nxdomain;
    config.rules.insert(config.rules.begin(), selected);
    nd::Server upstream;
    upstream.id = 1;
    upstream.name = "Live upstream";
    upstream.ip = "1.1.1.1";
    upstream.timeout_ms = 5000;
    config.servers.push_back(upstream);
    config.settings["clearDnsCache"] = "true";
    const auto path = directory / "windivert-live-config.xml";
    const std::string pipe =
        R"(\\.\pipe\NativeDNS.Test.Live.)" + std::to_string(nd::platform::process_id());
    nd::save_config(config, path);
    nd::CoreHost host(config, {}, 53, pipe, nd::InterceptionMode::transparent, path);
    const auto dump = [&] {
        for (const auto& event : host.logger().snapshot(nd::Level::debug))
            output << event.code << ' ' << event.message << '\n';
    };
    try {
        host.start();
        check(nd::pipe_request(pipe, nd::IpcOperation::status).payload.starts_with("RUNNING"),
              "Live CoreHost status");
        for (bool tcp : {false, true}) {
            const auto response = query(tcp, "8.8.8.8", "native-dns-live.invalid");
            check((response[3] & 15) == 3, "Live Block returns NXDOMAIN");
            output << "PASS Block " << (tcp ? "TCP" : "UDP") << '\n';
        }
        config.rules.front().action = nd::Action::process;
        config.rules.front().server_id = 1;
        config.settings["ttlMin"] = "20";
        config.settings["ttlMax"] = "20";
        reload(config, path, pipe);
        for (bool tcp : {false, true}) {
            const auto response = query(tcp, "8.8.8.8", "iana.org");
            const auto answer = nd::parse_response(response, nd::parse_question(response));
            check(answer.rcode == 0 && !answer.addresses.empty(),
                  "Live Process resolves DNS through own upstream");
            check(answer.cache_ttl <= 20, "Live TTL maximum");
            output << "PASS Process " << (tcp ? "TCP" : "UDP") << " TTL=" << answer.cache_ttl
                   << '\n';
        }
        const auto network = nd::NetworkMonitor::shared().snapshot();
        const auto active =
            std::find_if(network->interfaces.begin(),
                         network->interfaces.end(),
                         [](const nd::InterfaceInfo& info) {
                             return info.up && !info.gateways.empty() && info.index4;
                         });
        if (active != network->interfaces.end()) {
            config.rules.front().interface_id = active->id;
            reload(config, path, pipe);
            const auto response = query(false, "8.8.8.8", "iana.org");
            check(!nd::parse_response(response, nd::parse_question(response)).addresses.empty(),
                  "Live bound Process");
            output << "PASS Interface binding " << active->name << '\n';
            config.rules.front().interface_id.clear();
        }
        config.settings.erase("ttlMin");
        config.settings.erase("ttlMax");
        config.rules.front().server_id = 0;
        for (const auto action : {nd::Action::process, nd::Action::bypass}) {
            config.rules.front().action = action;
            reload(config, path, pipe);
            for (bool tcp : {false, true}) {
                const auto response = query(tcp, "1.1.1.1", "iana.org");
                check(!nd::parse_response(response, nd::parse_question(response)).addresses.empty(),
                      "Live original resolver");
                output << "PASS " << (action == nd::Action::process ? "Process/0" : "Bypass") << ' '
                       << (tcp ? "TCP" : "UDP") << '\n';
            }
        }
        config.settings["blockTcpPort53"] = "true";
        reload(config, path, pipe);
        bool reset = false;
        try {
            (void)query(true, "1.1.1.1", "iana.org");
        } catch (const nd::Error& error) {
            reset = error.code == "RAW_CONNECT" && std::string(error.what()) == "Winsock 10061";
        }
        check(reset, "Live TCP/53 rejected by reset, without waiting for timeout");
        output << "PASS blockTcpPort53 reset\n";
        config.settings.erase("blockTcpPort53");
        config.rules.front().action = nd::Action::block;
        reload(config, path, pipe);
        for (int cycle = 0; cycle < 3; ++cycle) {
            check(nd::pipe_request(pipe, nd::IpcOperation::stop).payload == "STOPPED", "Live Stop");
            check(nd::pipe_request(pipe, nd::IpcOperation::start).payload.starts_with("RUNNING"),
                  "Live Start");
            check((query(false, "8.8.8.8", "native-dns-live.invalid")[3] & 15) == 3,
                  "Block after restart");
        }
        output << "PASS Stop/Start cycles\n";
        check(nd::pipe_request(pipe, nd::IpcOperation::restart).payload == "RESTARTING" &&
                  host.restart_requested(),
              "Live Restart IPC");
        host.stop();
        check(host.status().state == nd::State::stopped, "Live shutdown cleanup");
        output << "PASS Restart and cleanup\n";
        dump();
    } catch (...) {
        host.stop();
        dump();
        throw;
    }
}
} // namespace
int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr
            << "Usage: windivert_live_tests <absolute-result-path> (administrator required)\n";
        return 2;
    }
    std::ofstream output(std::filesystem::path(argv[1]), std::ios::trunc);
    if (!output)
        return 2;
    output << std::unitbuf;
    try {
        WSADATA data{};
        check(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Initialize test Winsock");
        exercise(output, std::filesystem::path(argv[1]).parent_path());
        output << "RESULT PASS\n";
        return 0;
    } catch (const std::exception& error) {
        output << "RESULT FAIL " << error.what() << '\n';
        return 1;
    }
}
