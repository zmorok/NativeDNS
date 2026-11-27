#include <nativedns/host.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/autostart.hpp>
#include <iostream>
#include <charconv>
#include <algorithm>

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
    std::cout << "NativeDNSCoreHost --config <file> [--transparent] [--port N] [--diagnostics]\n"
              << "NativeDNSCoreHost --register-autostart <config> [--gui-executable <file>]\n"
              << "NativeDNSCoreHost --unregister-autostart\n";
}
} // namespace

int run_core_host(int argc, char** native_argv, bool use_utf8_argv) {
    try {
        nd::platform::initialize_application_paths();
        const auto argv = use_utf8_argv
                              ? std::vector<std::string>(native_argv, native_argv + argc)
                              : nd::platform::command_line_arguments(argc, native_argv);
        argc = static_cast<int>(argv.size());
        if (std::find(argv.begin(), argv.end(), "--layout-check") != argv.end()) {
            std::cout << "root=" << nd::platform::path_to_utf8(nd::platform::application_root_directory())
                      << "\ndriver=" << nd::platform::path_to_utf8(nd::platform::windivert_directory()) << '\n';
            return 0;
        }
        std::filesystem::path config_path;
        std::filesystem::path autostart_config;
        std::filesystem::path autostart_gui;
        bool transparent = false;
        bool diagnostic_logging = NATIVEDNS_DIAGNOSTIC_DEFAULT != 0;
        bool register_autostart = false;
        bool unregister_autostart = false;
        nd::platform::ProcessIdentity force_target;
        uint16_t port = 0;

        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--config" && i + 1 < argc)
                config_path = nd::platform::path_from_utf8(argv[++i]);
            else if (arg == "--transparent")
                transparent = true;
            else if (arg == "--diagnostics")
                diagnostic_logging = true;
            else if (arg == "--force-shutdown" && i + 2 < argc) {
                const std::string pid = argv[++i], started = argv[++i];
                const auto [pid_end, pid_error] =
                    std::from_chars(pid.data(), pid.data() + pid.size(), force_target.pid);
                const auto [start_end, start_error] = std::from_chars(
                    started.data(), started.data() + started.size(), force_target.started);
                if (pid_error != std::errc{} || pid_end != pid.data() + pid.size() ||
                    start_error != std::errc{} || start_end != started.data() + started.size() ||
                    !force_target.pid || !force_target.started)
                    throw nd::Error("PROCESS_IDENTITY", "Invalid force-shutdown process identity");
            } else if (arg == "--port" && i + 1 < argc) {
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
                autostart_config = nd::platform::path_from_utf8(argv[++i]);
            } else if (arg == "--unregister-autostart")
                unregister_autostart = true;
            else if (arg == "--gui-executable" && i + 1 < argc)
                autostart_gui = nd::platform::path_from_utf8(argv[++i]);
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

        if (force_target.pid) {
            if (register_autostart || unregister_autostart || !config_path.empty() || transparent ||
                port || !autostart_gui.empty())
                throw nd::Error("PROCESS_IDENTITY", "Conflicting force-shutdown operations");
            const auto self = nd::platform::executable_path();
            const bool unified =
                self.filename() == "NativeDNS.exe" &&
                std::filesystem::is_regular_file(
                    self.parent_path() / "bin" / "NativeDNS.CoreHost.dll");
            nd::platform::force_stop_process(self, force_target, unified ? "--core-host" : "");
            return 0;
        }

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

        bool autostart_repaired = false;
#ifdef _WIN32
        if (transparent) {
            try {
                const auto status = nd::autostart_status();
                if (status.enabled && status.needs_repair) {
                    nd::enable_autostart(nd::platform::executable_path(),
                                         config_path,
                                         nd::platform::gui_entrypoint());
                    autostart_repaired = true;
                }
            } catch (...) {
            }
        }
#endif

        nd::platform::elevate_service_process_priority();
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
                              config_path,
                              diagnostic_logging);
            if (autostart_repaired) {
                host.logger().write(nd::Level::normal,
                                    "AUTOSTART_REPAIRED",
                                    "Updated autostart registration to the current application path");
                autostart_repaired = false;
            }
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

#ifdef NATIVEDNS_COREHOST_MODULE
extern "C" __declspec(dllexport) int nativedns_run_core_host(int argc, char** argv) {
    return run_core_host(argc, argv, true);
}
#else
int main(int argc, char** argv) {
    return run_core_host(argc, argv, false);
}
#endif
