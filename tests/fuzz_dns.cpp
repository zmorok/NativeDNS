#include <nativedns/dns.hpp>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const nd::Packet packet(data, data + size);
    try {
        const auto question = nd::parse_question(packet);
        try {
            (void)nd::parse_response(packet, question);
        } catch (...) {
        }
        try {
            (void)nd::make_error_response(packet, 2);
        } catch (...) {
        }
        try {
            (void)nd::make_block_response(packet, nd::BlockMode::zero_address);
        } catch (...) {
        }
    } catch (...) {
    }
    try {
        (void)nd::client_udp_payload_size(packet);
    } catch (...) {
    }
    return 0;
}
