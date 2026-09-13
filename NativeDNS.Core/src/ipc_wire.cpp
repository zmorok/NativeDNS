#include <nativedns/detail/ipc_wire.hpp>
#include <nativedns/config.hpp>

namespace nd::detail {
namespace {
uint16_t get16(const uint8_t* in) {
    return static_cast<uint16_t>(in[0] | (in[1] << 8));
}
uint32_t get32(const uint8_t* in) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i)
        value |= static_cast<uint32_t>(in[i]) << (i * 8);
    return value;
}
uint64_t get64(const uint8_t* in) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i)
        value |= static_cast<uint64_t>(in[i]) << (i * 8);
    return value;
}
} // namespace
IpcWireHeader parse_ipc_header(std::span<const uint8_t> bytes, bool response) {
    if (bytes.size() != ipc_header_size)
        throw Error("IPC_PROTOCOL", "Invalid IPC header size");
    if (get32(bytes.data()) != 0x31444e4e || get16(bytes.data() + 4) != 1)
        throw Error("IPC_PROTOCOL", "Bad IPC magic/version");
    IpcWireHeader header{
        get16(bytes.data() + 6), get64(bytes.data() + 8), get32(bytes.data() + 16)};
    const auto base = static_cast<uint16_t>(header.operation & 0x7fff);
    if (!header.request || base < 1 || base > 10 ||
        (response ? (header.operation & 0x8000) == 0 : (header.operation & 0x8000) != 0))
        throw Error("IPC_PROTOCOL", "Invalid IPC request header");
    if (response ? (header.length < 4 || header.length > ipc_max_payload + 4)
                 : header.length > ipc_max_payload)
        throw Error("IPC_PROTOCOL", "Invalid IPC payload size");
    return header;
}
} // namespace nd::detail
