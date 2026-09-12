#pragma once
#include <nativedns/dns.hpp>
#include <array>
#include <span>

namespace nd {
struct DnsCryptCertificate {
    uint16_t encryption_system = 0;
    std::array<uint8_t, 32> resolver_public_key{};
    std::array<uint8_t, 8> client_magic{};
    uint32_t serial = 0;
    uint32_t valid_from = 0;
    uint32_t valid_until = 0;
};

std::array<uint8_t, 32> parse_dnscrypt_provider_key(const std::string& text);
void validate_dnscrypt_server(const Server& server);
DnsCryptCertificate select_dnscrypt_certificate(const std::vector<Packet>& blobs,
    std::span<const uint8_t, 32> provider_key, uint64_t unix_time);
std::vector<Packet> extract_dnscrypt_certificates(const Packet& response);
std::array<uint8_t, 32> dnscrypt_shared_key(std::span<const uint8_t, 32> client_secret,
    const DnsCryptCertificate& certificate);
Packet build_dnscrypt_query(const Packet& request, const DnsCryptCertificate& certificate,
    std::span<const uint8_t, 32> client_secret, std::span<const uint8_t, 12> client_nonce,
    size_t minimum_wire_size = 512);
Packet open_dnscrypt_response(const Packet& response, std::span<const uint8_t, 32> shared_key,
    std::span<const uint8_t, 12> client_nonce, uint16_t encryption_system = 2);
Packet build_anonymized_dnscrypt_packet(const Packet& payload,const Server& server);
Packet build_anonymized_dnscrypt_certificate_packet(const Packet& request,const Server& server);
}
