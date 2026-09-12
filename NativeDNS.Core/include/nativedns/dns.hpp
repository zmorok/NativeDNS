#pragma once
#include <nativedns/config.hpp>
#include <nativedns/logger.hpp>
#include <span>
#include <memory>

namespace nd {
using Packet = std::vector<uint8_t>;
struct Question {
    uint16_t id = 0, flags = 0, type = 0, klass = 0;
    std::string name;
    size_t end = 0;
};
struct DnsAnswer {
    uint16_t rcode = 0;
    bool truncated = false, authenticated_data = false;
    std::vector<std::string> addresses;
};
Packet make_query(const std::string& hostname, uint16_t type = 1);
Packet make_error_response(const Packet& request, uint16_t rcode);
uint16_t client_udp_payload_size(std::span<const uint8_t> request);
Packet fit_udp_response(const Packet& request, const Packet& response);
Question parse_question(std::span<const uint8_t> packet);
DnsAnswer parse_response(std::span<const uint8_t> packet, const Question& expected);
std::string dns_type_name(uint16_t type);
class IDnsTransport {
public:
    virtual ~IDnsTransport() = default;
    virtual Packet exchange(const Packet& request, const Server& server) = 0;
};
std::unique_ptr<IDnsTransport> make_transport(Protocol protocol);
struct TestResult {
    bool success = false;
    Protocol protocol = Protocol::udp;
    uint32_t server_id = 0;
    std::string hostname;
    uint16_t query_type = 1, rcode = 0;
    bool authenticated_data = false;
    double rtt_ms = 0;
    std::vector<std::string> addresses;
    std::string error_code, message;
};
TestResult test_server(const Server& server, const std::string& hostname = "iana.org", uint16_t type = 1, Logger* logger = nullptr);
std::vector<TestResult> test_servers(const Config& config, Logger* logger = nullptr);
}
