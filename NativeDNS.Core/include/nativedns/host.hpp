#pragma once
#include <nativedns/interception.hpp>
#include <nativedns/ipc.hpp>
#include <condition_variable>

namespace nd {
enum class InterceptionMode { local_proxy, transparent, windivert = transparent };
class CoreHost {
public:
    CoreHost(Config config, Server original, uint16_t local_port = 0,
             std::string pipe_name = core_pipe_name,
             InterceptionMode mode = InterceptionMode::local_proxy);
    ~CoreHost();
    void start();
    void stop();
    void wait_for_shutdown();
    bool restart_requested() const { return restart_requested_; }
    InterceptionStatus status() const;
    Logger& logger() { return logger_; }
private:
    IpcResponse handle(IpcOperation operation, const std::string& payload);
    mutable std::mutex mutex_;
    std::condition_variable shutdown_cv_;
    bool shutdown_requested_ = false;
    std::atomic_bool stopped_ = true;
    Config config_;
    Server original_;
    uint16_t local_port_;
    std::string pipe_name_;
    std::string log_pipe_name_;
    Logger logger_;
    std::filesystem::path file_log_path_;
    bool file_log_enabled_ = false;
    std::shared_ptr<Router> router_;
    std::unique_ptr<IInterceptionProvider> interception_;
    std::unique_ptr<PipeServer> ipc_;
    std::unique_ptr<PipeServer> log_ipc_;
    std::atomic_bool restart_requested_ = false;
};
}
