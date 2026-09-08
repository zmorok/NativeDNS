#pragma once
#include <array>
#include <cstdint>
#include <filesystem>
#include <chrono>
#include <string>
#include <ctime>
#include <memory>

namespace nd::platform {

bool is_numeric_ip(const std::string& text);
// Writes the binary representation. IPv4 is returned in the last 4 bytes and
// ipv6=false; IPv6 fills all 16 bytes.
bool parse_ip(const std::string& text, std::array<uint8_t,16>& bytes, bool& ipv6);
std::string format_ip(const void* bytes, bool ipv6);
uint16_t secure_random_u16();
uint32_t secure_random_u32();
uint64_t monotonic_millis();
uint32_t process_id();
std::filesystem::path executable_path();
std::filesystem::path user_config_directory();

class ProcessInstanceLock {
public:
    explicit ProcessInstanceLock(const std::string& name);
    ~ProcessInstanceLock();
    ProcessInstanceLock(const ProcessInstanceLock&) = delete;
    ProcessInstanceLock& operator=(const ProcessInstanceLock&) = delete;
    bool acquired() const noexcept;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
void wait_socket(std::intptr_t socket, bool writing, std::chrono::steady_clock::time_point deadline);
void configure_upstream_socket(std::intptr_t socket);
void atomic_publish_file(const std::filesystem::path& temp, const std::filesystem::path& target, const std::filesystem::path& backup);
void local_time(std::time_t instant, std::tm& output);

}
