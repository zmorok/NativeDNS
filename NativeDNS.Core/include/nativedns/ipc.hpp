#pragma once
#include <nativedns/config.hpp>
#include <nativedns/platform.hpp>
#include <atomic>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>

namespace nd {
enum class IpcOperation : uint16_t {
    ping = 1,
    status = 2,
    start = 3,
    stop = 4,
    logs = 5,
    shutdown = 6,
    clear_file_log = 7,
    clear_display = 8,
    restart = 9,
    configure_file_log = 10,
    reload_config = 11
};
struct IpcResponse {
    uint32_t status = 0;
    std::string payload;
};
class PipeServer {
public:
    using Handler = std::function<IpcResponse(IpcOperation, const std::string&)>;
    PipeServer(std::string name, Handler handler);
    ~PipeServer();
    void start();
    void stop();
    bool running() const {
        return running_;
    }

private:
    void run();
    std::string name_;
    Handler handler_;
    void* native_stop_ = nullptr;
    void* startup_event_ = nullptr;
    std::jthread thread_;
    std::atomic_bool running_ = false;
    std::mutex error_mutex_;
    std::string startup_error_;
    std::condition_variable startup_cv_;
    bool startup_ready_ = false;
    std::unique_ptr<platform::ProcessInstanceLock> owner_;
};
IpcResponse pipe_request(const std::string& name,
                         IpcOperation operation,
                         const std::string& payload = {},
                         uint32_t timeout_ms = 3000);
#ifdef _WIN32
inline constexpr const char* core_pipe_name = R"(\\.\pipe\NativeDNS.Core.v1)";
inline constexpr const char* core_log_pipe_name = R"(\\.\pipe\NativeDNS.Core.Logs.v1)";
#else
inline constexpr const char* core_pipe_name = "/tmp/nativedns-core-v1.sock";
inline constexpr const char* core_log_pipe_name = "/tmp/nativedns-core-logs-v1.sock";
#endif
} // namespace nd
