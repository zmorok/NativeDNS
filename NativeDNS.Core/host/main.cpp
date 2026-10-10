#include <nativedns/host.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/autostart.hpp>
#include <iostream>
#include <charconv>

namespace {
void log_startup_failure(const char* code, const std::string& message) noexcept {
    try {
        nd::Logger logger(16);
        logger.configure_file(
            true,
            nd::Level::errors_only,
            nd::timestamped_log_path(nd::platform::application_root_directory() / "logs"));
        logger.write(nd::Level::errors_only, code, message);
    } catch (...) {
    }
}

nd::Server default_original() {
    nd::Server s;
    s.id = 1;
    s.name = "System fallback";
    s.protocol = nd::Protocol::udp;
    s.ip = "1.1.1.1";
    s.port = 53;
    s.timeout_ms = 3000;
    return s;
}

void usage() {
    std::cout << "NativeDNSCoreHost --config <file> [--transparent] [--port N]\n"
              << "NativeDNSCoreHost --register-autostart <config> [--gui-executable <file>]\n"
              << "NativeDNSCoreHost --unregister-autostart\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        std::filesystem::path config_path;
        std::filesystem::path autostart_config;
        std::filesystem::path autostart_gui;
        bool transparent = false;
        bool register_autostart = false;
        bool unregister_autostart = false;
        uint16_t port = 0;

        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--config" && i + 1 < argc)
                config_path = argv[++i];
            else if (arg == "--transparent")
                transparent = true;
            else if (arg == "--port" && i + 1 < argc) {
                const std::string value = argv[++i];
                unsigned parsed = 0;
                const auto [end, error] =
                    std::from_chars(value.data(), value.data() + value.size(), parsed);
                if (error != std::errc{} || end != value.data() + value.size() || !parsed ||
                    parsed > 65535)
                    throw nd::Error("PORT", "Port must be an integer in 1..65535");
                port = static_cast<uint16_t>(parsed);
            } else if (arg == "--register-autostart" && i + 1 < argc) {
                register_autostart = true;
                autostart_config = argv[++i];
            } else if (arg == "--unregister-autostart")
                unregister_autostart = true;
            else if (arg == "--gui-executable" && i + 1 < argc)
                autostart_gui = argv[++i];
            else if (arg == "--help") {
                usage();
                return 0;
            } else {
                std::cerr << "Unknown or incomplete argument: " << arg << "\n";
                usage();
                return 2;
            }
        }

        if (register_autostart && unregister_autostart)
            throw nd::Error("AUTOSTART", "Conflicting autostart operations");

        if (register_autostart) {
            nd::enable_autostart(nd::platform::executable_path(), autostart_config, autostart_gui);
            return 0;
        }
        if (unregister_autostart) {
            nd::disable_autostart();
            return 0;
        }

        nd::platform::ProcessInstanceLock instanceLock(nd::core_instance_name,
                                                       nd::platform::InstanceScope::machine);
        if (!instanceLock.acquired()) {
            std::cerr << "NativeDNSCoreHost is already running\n";
            return 0;
        }

        if (config_path.empty()) {
            config_path = nd::platform::user_config_directory() / "NativeDNS.xml";
            if (!std::filesystem::exists(config_path)) {
                std::filesystem::create_directories(config_path.parent_path());
                nd::save_config(nd::default_config(), config_path);
            }
        }

        for (;;) {
            auto config = nd::load_config(config_path);
            // Outlive CoreHost and its file/transport destructors as well as stop().
            std::jthread shutdown_deadline;
            nd::CoreHost host(std::move(config),
                              default_original(),
                              port,
                              nd::core_pipe_name,
                              transparent ? nd::InterceptionMode::transparent
                                          : nd::InterceptionMode::local_proxy,
                              config_path);
            // Windows enforces the deadline independently of backend/IPC locks.
            shutdown_deadline = nd::platform::watch_shutdown_deadline(
                [signal = host.shutdown_signal()] { return signal->load(); });
            host.start();
            try {
                host.wait_for_shutdown();
            } catch (const std::exception& error) {
                host.request_shutdown();
                host.logger().write(nd::Level::errors_only, "CORE_RUNTIME_FAILED", error.what());
                host.stop();
                throw;
            }
            const bool restart = host.restart_requested();
            host.logger().write(
                nd::Level::normal, "CORE_SHUTDOWN_REQUESTED", "Graceful shutdown requested");
            host.stop();
            if (!restart)
                return 0;
        }
    } catch (const nd::Error& e) {
        log_startup_failure(e.code.c_str(), e.what());
        std::cerr << e.code << ": " << e.what() << "\n";
        return 10;
    } catch (const std::exception& e) {
        log_startup_failure("INTERNAL", e.what());
        std::cerr << "INTERNAL: " << e.what() << "\n";
        return 11;
    }
}
