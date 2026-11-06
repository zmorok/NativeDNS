#include <nativedns/host.hpp>
#include <nativedns/network_preflight.hpp>
#include <fstream>
#include <iostream>

namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
}
int main() {
    try {
        auto config = nd::default_config();
        config.logging.screen = config.logging.file = nd::Level::normal;
        config.logging.file_enabled = false;
        const auto token = std::to_string(nd::platform::process_id()) + '-' +
                           std::to_string(nd::platform::monotonic_millis());
        const auto path = std::filesystem::temp_directory_path() / ("diagnostic-profile-" + token + ".xml");
        nd::save_config(config, path);
        auto effective = config;
        nd::enable_diagnostic_logging(effective);
        check(effective.rules == config.rules && effective.servers == config.servers &&
                  effective.logging.screen == nd::Level::debug && effective.logging.file == nd::Level::debug &&
                  effective.logging.file_enabled, "Diagnostic profile changed routing or missed a log setting");
        const auto endpoint = std::string(nd::core_pipe_name) + ".Profile." + token;
        const auto marker = "PROFILE_DEBUG_" + token;
        nd::Server original;
        original.name = "Unused loopback upstream";
        original.ip = "127.0.0.1"; original.port = 1;
        {
            nd::CoreHost host(config, original, 0, endpoint, nd::InterceptionMode::local_proxy, path, true);
            host.start();
            check(host.logger().enabled(nd::Level::debug), "Debug capture was not enabled on startup");
            check(nd::pipe_request(endpoint, nd::IpcOperation::configure_file_log, "0\t1").status != 0,
                  "Diagnostic file capture could be silently disabled");
            const auto id = nd::configuration_fingerprint(effective);
            check(nd::pipe_request(endpoint, nd::IpcOperation::reload_config, id).payload == "RELOADED config_id=" + id,
                  "Import/reload did not retain the diagnostic profile");
            host.logger().write(nd::Level::debug, marker, "Full diagnostic capture retained");
            host.logger().flush_file();
            const auto base_id = nd::configuration_fingerprint(config);
            check(nd::pipe_request(endpoint, nd::IpcOperation::reload_config, base_id + "\tdiagnostics=0").status == 0,
                  "Switching back to normal capture was rejected");
            check(!host.logger().enabled(nd::Level::debug), "Normal launch retained forced Debug capture");
            check(nd::load_config(path) == config, "Diagnostic mode changed the saved normal configuration");
            check(nd::pipe_request(endpoint, nd::IpcOperation::reload_config, id + "\tdiagnostics=1").status == 0,
                  "A reused CoreHost did not accept Debug capture");
            check(host.logger().enabled(nd::Level::debug), "Debug capture missing after normal-to-debug switch");
            check(nd::pipe_request(endpoint, nd::IpcOperation::reload_config, base_id + "\tdiagnostics=1").status != 0,
                  "A mismatched effective config ID was accepted");
            const auto routing = nd::routing_fingerprint(config);
            const auto info = [&] {
                const auto response =
                    nd::pipe_request(endpoint, nd::IpcOperation::interception_status, {}, 5000);
                check(!response.status, "Diagnostics request failed");
                check(response.payload.find("saved_config_id=" + base_id) != std::string::npos,
                      "Saved document identity changed");
                check(response.payload.find("routing_config_id=" + routing) != std::string::npos,
                      "Applied routing identity changed");
                return response.payload;
            };
            check(info().find("runtime_profile=Debug") != std::string::npos,
                  "Debug profile not reported");
            check(
                nd::pipe_request(endpoint, nd::IpcOperation::diagnostic_profile, "Normal").status ==
                    0,
                "Runtime Normal failed");
            check(info().find("runtime_profile=Normal") != std::string::npos,
                  "Normal profile not reported");
            check(
                nd::pipe_request(endpoint, nd::IpcOperation::diagnostic_profile, "Debug").status ==
                    0,
                "Runtime Debug failed");
            check(nd::pipe_request(
                      endpoint, nd::IpcOperation::diagnostic_profile, "Debug --exec anything")
                          .status != 0,
                  "Arbitrary profile accepted");
            check(nd::pipe_request(endpoint,
                                   nd::IpcOperation::reload_config,
                                   "routing=" + routing + "\tdiagnostics=0")
                          .status == 0,
                  "Routing identity reload rejected valid Normal profile");
            check(nd::pipe_request(endpoint,
                                   nd::IpcOperation::reload_config,
                                   "routing=" + routing + "\tdiagnostics=1")
                          .status == 0,
                  "Routing identity reload rejected valid Debug profile");
            check(nd::pipe_request(
                      endpoint, nd::IpcOperation::reload_config, "routing=" + std::string(64, '0'))
                          .status != 0,
                  "Real routing mismatch was ignored");
            check(nd::pipe_request(endpoint, nd::IpcOperation::interception_test).status != 0,
                  "Local proxy incorrectly claims transparent self-test support");
            check(nd::pipe_request(endpoint, nd::IpcOperation::flush_file_log).status == 0,
                  "IPC flush failed");
            check(nd::load_config(path) == config, "Runtime profiles changed XML");
            host.stop();
        }
        bool found = false;
        const auto directory = nd::platform::application_root_directory() / "logs";
        for (const auto& item : std::filesystem::directory_iterator(directory)) {
            if (!item.is_regular_file()) continue;
            std::ifstream file(item.path(), std::ios::binary);
            const std::string contents((std::istreambuf_iterator<char>(file)), {});
            if (contents.find("[DEBUG] " + marker) == std::string::npos) continue;
            found = true;
            file.close();
            std::filesystem::remove(item.path());
        }
        check(found, "Debug events were not actually written to a file");
        std::filesystem::remove(path);
        auto backup = path; backup += ".bak"; std::filesystem::remove(backup);
        std::cout << "diagnostic logging profile passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
