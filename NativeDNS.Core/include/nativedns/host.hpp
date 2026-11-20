#pragma once
#include <nativedns/interception.hpp>
#include <nativedns/ipc.hpp>
#include <nativedns/network_preparation.hpp>
#include <condition_variable>

namespace nd {
enum class InterceptionMode { local_proxy, transparent, windivert = transparent };
class CoreHost {
public:
    CoreHost(Config config,
             Server original,
             uint16_t local_port = 0,
             std::string pipe_name = core_pipe_name,
             InterceptionMode mode = InterceptionMode::local_proxy,
             std::filesystem::path config_path = {},
             bool diagnostic_logging = false);
    ~CoreHost();
    void start();
    void stop();
    void wait_for_shutdown();
    void request_shutdown() {
        *shutdown_requested_ = true;
        shutdown_cv_.notify_all();
    }
    bool restart_requested() const {
        return restart_requested_;
    }
    bool shutdown_requested() const {
        return shutdown_requested_->load();
    }
    std::shared_ptr<const std::atomic_bool> shutdown_signal() const {
        return shutdown_requested_;
    }
    InterceptionStatus status() const;
    Logger& logger() {
        return logger_;
    }

private:
    IpcResponse handle(IpcOperation operation, const std::string& payload);
    void log_configuration();
    void configure_logging();
    void inspect_network(const Config& config);
    bool prepare_network(const Config& config);
    void restore_network() noexcept;
    mutable std::mutex mutex_;
    std::mutex reload_mutex_;
    std::mutex network_prep_mutex_;
    std::mutex ipc_lifecycle_mutex_;
    std::condition_variable shutdown_cv_;
    std::shared_ptr<std::atomic_bool> shutdown_requested_ =
        std::make_shared<std::atomic_bool>(false);
    std::atomic_bool stopped_ = true;
    Config config_;
    LoggingSettings saved_logging_;
    std::string saved_config_id_;
    Server original_;
    InterceptionMode mode_;
    uint16_t local_port_;
    std::string pipe_name_;
    std::filesystem::path config_path_;
    std::atomic_bool diagnostic_logging_ = false;
    const bool startup_diagnostic_logging_;
    std::atomic<Level> screen_level_ = Level::normal;
    std::string log_pipe_name_;
    Logger logger_;
    std::filesystem::path file_log_path_;
    std::shared_ptr<Router> router_;
    std::unique_ptr<IInterceptionProvider> interception_;
    std::unique_ptr<NetworkPreparation> network_preparation_;
    std::unique_ptr<PipeServer> ipc_;
    std::unique_ptr<PipeServer> log_ipc_;
    std::unique_ptr<PipeServer> shutdown_ipc_;
    std::atomic_bool restart_requested_ = false;
};
} // namespace nd
