#pragma once
#include <cstddef>
#include <cstdint>
#include <span>

namespace nd::detail {
inline constexpr size_t ipc_header_size = 20;
inline constexpr uint32_t ipc_max_payload = 1024 * 1024;
struct IpcWireHeader {
    uint16_t operation = 0;
    uint64_t request = 0;
    uint32_t length = 0;
};
IpcWireHeader parse_ipc_header(std::span<const uint8_t> bytes, bool response);
} // namespace nd::detail
