#pragma once
#include <array>
#include <cstdint>
#include <filesystem>
#include <chrono>
#include <string>
#include <ctime>
#include <memory>
#include <vector>
#include <functional>
#include <thread>

namespace nd::platform {

bool is_numeric_ip(const std::string& text);
// Writes the binary representation. IPv4 is returned in the last 4 bytes and
// ipv6=false; IPv6 fills all 16 bytes.
bool parse_ip(const std::string& text, std::array<uint8_t, 16>& bytes, bool& ipv6);
std::string format_ip(const void* bytes, bool ipv6);
uint16_t secure_random_u16();
uint32_t secure_random_u32();
uint64_t monotonic_millis();
struct MonotonicClocks {
    uint64_t boottime_ms = 0; // advances during OS suspend/sleep
    uint64_t active_ms = 0;   // pauses during OS suspend/sleep
};
MonotonicClocks monotonic_clocks();
class SuspendResumeSubscription {
public:
    explicit SuspendResumeSubscription(std::function<void()> on_resume);
    ~SuspendResumeSubscription();
    SuspendResumeSubscription(const SuspendResumeSubscription&) = delete;
    SuspendResumeSubscription& operator=(const SuspendResumeSubscription&) = delete;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
enum class ThreadPriority { below_normal, normal, above_normal, highest };
void elevate_service_process_priority() noexcept;
void set_current_thread_priority(ThreadPriority priority) noexcept;
uint32_t process_id();
struct ProcessIdentity {
    uint32_t pid = 0;
    uint64_t started = 0;
};
// Match the full executable path. The birth token prevents PID-reuse mistakes.
std::vector<ProcessIdentity> matching_processes(const std::filesystem::path& executable);
void force_stop_process(const std::filesystem::path& executable, ProcessIdentity identity);
std::filesystem::path executable_path();
// Root of the staged application, independent of its internal binary directory.
std::filesystem::path application_root_directory();
std::filesystem::path application_binary_directory();
std::filesystem::path gui_entrypoint();
std::filesystem::path core_host_executable();
std::filesystem::path windivert_directory();
void initialize_application_paths();
std::filesystem::path user_config_directory();
bool is_elevated();
// Windows can release interception handles by exiting after stuck cleanup.
// Linux must finish nftables cleanup and currently has no forced-exit fallback.
std::jthread watch_shutdown_deadline(std::function<bool()> shutdown_requested);
enum class DistributionKind { portable, executable, appimage, package };
DistributionKind distribution_kind();
const char* distribution_name(DistributionKind kind) noexcept;
const char* distribution_label(DistributionKind kind) noexcept;
DistributionKind detect_distribution_in_directory(const std::filesystem::path& root,
                                                  bool registry_installed = false);
std::string system_summary();
// Application text is UTF-8, independently of the Windows ANSI/OEM code pages.
std::string path_to_utf8(const std::filesystem::path& path);
std::filesystem::path path_from_utf8(const std::string& text);
std::vector<std::string> command_line_arguments(int argc, char** argv);

enum class InstanceScope { session, machine };
class ProcessInstanceLock {
public:
    explicit ProcessInstanceLock(const std::string& name,
                                 InstanceScope scope = InstanceScope::session);
    ~ProcessInstanceLock();
    ProcessInstanceLock(const ProcessInstanceLock&) = delete;
    ProcessInstanceLock& operator=(const ProcessInstanceLock&) = delete;
    bool acquired() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
void wait_socket(std::intptr_t socket,
                 bool writing,
                 std::chrono::steady_clock::time_point deadline);
void configure_upstream_socket(std::intptr_t socket);
uint16_t prepare_upstream_socket(std::intptr_t socket, bool tcp);
bool socket_is_ipv6(std::intptr_t socket);
int close_upstream_socket(std::intptr_t socket) noexcept;
std::vector<std::string> resolve_host(const std::string& hostname);
// Numeric OS-configured resolvers, without performing any DNS lookup.
std::vector<std::string> system_dns_servers();
void flush_dns_cache();
void atomic_publish_file(const std::filesystem::path& temp,
                         const std::filesystem::path& target,
                         const std::filesystem::path& backup);
void local_time(std::time_t instant, std::tm& output);

} // namespace nd::platform
