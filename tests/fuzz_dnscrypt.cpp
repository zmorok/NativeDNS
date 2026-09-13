#include <nativedns/dnscrypt.hpp>
#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const nd::Packet packet(data, data + size);
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    if (size >= 32)
        std::copy_n(data, 32, key.begin());
    try {
        const auto certificates = nd::extract_dnscrypt_certificates(packet);
        try {
            (void)nd::select_dnscrypt_certificate(certificates, key, 1);
        } catch (...) {
        }
    } catch (...) {
    }
    try {
        (void)nd::open_dnscrypt_response(
            packet, key, nonce, size ? static_cast<uint16_t>((data[0] % 2) + 1) : 2);
    } catch (...) {
    }
    nd::Server server;
    server.ip = "127.0.0.1";
    server.port = 443;
    server.relay = "127.0.0.2:443";
    try {
        (void)nd::build_anonymized_dnscrypt_packet(packet, server);
    } catch (...) {
    }
    return 0;
}
