#include <nativedns/logger.hpp>
#include <nativedns/router.hpp>
#include <nativedns/core_api.h>
#include <nativedns/platform.hpp>
#include "../NativeDNS.Core/src/bounded_executor.hpp"
#include <future>
#include <iostream>
#include <thread>
#include <stdexcept>
#include <filesystem>
#include <fstream>
#include <cctype>
#include <algorithm>
#ifdef NATIVEDNS_TEST_LEGACY_CODEPAGE
#include <windows.h>
#endif
void check(bool value, const char* message = "foundation assertion failed") {
    if (!value)
        throw std::runtime_error(message);
}
int main() {
    try {
#ifdef NATIVEDNS_TEST_LEGACY_CODEPAGE
        std::cout << "Test ANSI code page=" << GetACP() << '\n';
        if (GetACP() != 1251)
            return 77;
#endif
        check(NativeDns_GetApiVersion() == 1);
        {
            nd::detail::BoundedExecutor executor;
            std::promise<void> began, release;
            auto released = release.get_future().share();
            auto started = began.get_future();
            std::atomic_uint ran = 0;
            executor.start(1, 2);
            check(executor.submit([&] {
                began.set_value();
                released.get();
                ++ran;
            }),
                  "accept active executor job");
            check(started.wait_for(std::chrono::seconds(2)) == std::future_status::ready,
                  "executor begins work");
            check(executor.submit([&] { ++ran; }) && executor.submit([&] { ++ran; }),
                  "queue accepts its bounded capacity");
            check(!executor.submit([&] { ++ran; }), "queue rejects overload");
            release.set_value();
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (ran < 3 && std::chrono::steady_clock::now() < deadline)
                std::this_thread::yield();
            check(ran == 3, "queued work recovers after overload");
            executor.stop();
            check(!executor.submit([] {}), "stopped executor rejects work");
            executor.start(1, 1);
            std::promise<void> restarted;
            auto done = restarted.get_future();
            check(executor.submit([&] { restarted.set_value(); }), "executor restarts");
            check(done.wait_for(std::chrono::seconds(2)) == std::future_status::ready,
                  "restarted worker executes");
            executor.stop();
        }
        auto config = nd::default_config();
        check(config.rules.size() == 1 && config.rules.back().is_default &&
              config.rules.back().server_id == 0);
        nd::Logger logger(32);
        std::jthread first([&] {
            for (int i = 0; i < 100; ++i)
                logger.write(nd::Level::debug, "DEBUG", "test");
        });
        std::jthread second([&] {
            for (int i = 0; i < 100; ++i)
                logger.write(nd::Level::normal, "INFO", "test");
        });
        first.join();
        second.join();
        logger.write(nd::Level::errors_only, "TIMEOUT", "line1\nline2");
        auto events = logger.snapshot(nd::Level::debug);
        check(events.size() == 32 && events.back().sequence == 201);
        check(logger.snapshot(nd::Level::errors_only).size() == 1);
        check(events.back().message == "line1 line2");
        logger.clear_display();
        check(logger.snapshot(nd::Level::debug).empty());
        logger.write(nd::Level::normal, "INFO", "after clear");
        check(logger.snapshot(nd::Level::normal).back().sequence == 202);
        {
            nd::Logger limited;
            for (int i = 0; i < 100; ++i)
                limited.write_limited(nd::Level::errors_only,
                                      "resolver-1",
                                      "TIMEOUT",
                                      "first resolver",
                                      {},
                                      std::chrono::milliseconds(100));
            limited.write_limited(
                nd::Level::errors_only, "resolver-2", "TIMEOUT", "second resolver");
            check(limited.snapshot(nd::Level::errors_only).size() == 2,
                  "Repeated errors are bounded without hiding independent failures");
            std::this_thread::sleep_for(std::chrono::milliseconds(110));
            limited.write_limited(nd::Level::errors_only, "resolver-1", "TIMEOUT", "still failing");
            check(limited.snapshot(nd::Level::errors_only).back().message ==
                      "suppressed=99 still failing",
                  "Persistent failures include the number of suppressed repetitions");
            limited.clear_display();
            limited.write_limited(nd::Level::errors_only, "resolver-1", "TIMEOUT", "after clear");
            check(limited.snapshot(nd::Level::errors_only).size() == 1,
                  "Clearing display exposes the next failure immediately");
        }
        {
            auto policy = nd::default_config();
            policy.rules.front().action = nd::Action::block;
            nd::Router counted(policy, logger);
            (void)counted.route(nd::make_query("stats.invalid"), {});
            policy.rules.front().action = nd::Action::bypass;
            counted.reload(policy);
            (void)counted.route(nd::make_query("stats.invalid"), {});
            (void)counted.route(nd::Packet{0}, {});
            const auto stats = counted.statistics();
            check(stats.queries_completed == 3 && stats.rules_evaluated == 2 &&
                      stats.blocked == 1 && stats.bypassed == 1 && stats.parse_errors == 1 &&
                      stats.route_errors == 1 && stats.upstream_attempts == 0,
                  "Routing stage counters disagree with actual operations");
        }
        const auto directory = std::filesystem::current_path() /
                               ("logger-test-" + std::to_string(nd::platform::process_id()));
        std::filesystem::create_directories(directory);
        const auto timestamped = nd::timestamped_log_path(directory).filename().string();
        check(timestamped.size() == 29 && timestamped.starts_with("NativeDNS-") &&
                  timestamped.ends_with(".log") && timestamped[16] == '-' &&
                  std::all_of(timestamped.begin() + 10,
                              timestamped.begin() + 16,
                              [](unsigned char c) { return std::isdigit(c); }) &&
                  std::all_of(timestamped.begin() + 17,
                              timestamped.begin() + 25,
                              [](unsigned char c) { return std::isdigit(c); }),
              "timestamped log file name");
        const auto path = directory / "native.log";
        logger.configure_file(true, nd::Level::normal, path, 1024, 2);
        logger.write(nd::Level::debug, "DEBUG", "must not reach file");
        for (int i = 0; i < 40; ++i)
            logger.write(nd::Level::normal, "NORMAL", std::string(70, 'x'));
        logger.flush_file();
        check(std::filesystem::exists(path) && std::filesystem::exists(path.string() + ".1"),
              "log rotation");
        {
            std::ifstream stream(path, std::ios::binary);
            std::string contents((std::istreambuf_iterator<char>(stream)), {});
            check(contents.find("must not reach file") == std::string::npos &&
                      contents.find("NORMAL") != std::string::npos,
                  "independent file level");
            check(contents.find("[INFO]") != std::string::npos, "file log contains readable level");
            check(contents.size() > 20 && contents[3] == '.' && contents[6] == '.' &&
                      contents[11] == ' ' && contents[14] == ':' && contents[17] == ':',
                  "file log date/time format");
        }
        logger.clear_display();
        check(std::filesystem::file_size(path) > 0, "display clear does not clear file");
        logger.clear_file();
        check(std::filesystem::file_size(path) == 0, "clear file");
        logger.configure_file(false, nd::Level::normal, {});
        std::filesystem::remove(path);
        std::filesystem::remove(path.string() + ".1");
        std::filesystem::remove(path.string() + ".2");

        logger.configure_file(
            true, nd::Level::normal, nd::timestamped_log_path(directory), 1024, 2);
        for (int i = 0; i < 40; ++i)
            logger.write(nd::Level::normal, "TIMESTAMPED", std::string(70, 'x'));
        logger.configure_file(false, nd::Level::normal, {});
        size_t timestamped_file_count = 0;
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            const auto name = entry.path().filename().string();
            check(name.size() == 29 && name.starts_with("NativeDNS-") && name.ends_with(".log"),
                  "timestamped rotation file name");
            ++timestamped_file_count;
            std::filesystem::remove(entry.path());
        }
        check(timestamped_file_count == 3, "timestamped log retention");
        {
            const auto healthy = logger.file_status();
            check(healthy.written_events >= 80 && healthy.writer_active &&
                      healthy.last_write_timestamp_ms > 0,
                  "Writer diagnostics missed actual writes");
            const auto blocked_path = directory / "blocked";
            {
                std::ofstream file(blocked_path);
                file << "not a directory";
            }
            bool failed = false;
            try {
                logger.configure_file(true, nd::Level::debug, blocked_path / "output.log");
            } catch (...) {
                failed = true;
            }
            const auto status = logger.file_status();
            check(failed && status.state == "FAILED" && !status.enabled &&
                      !status.last_error.empty() && status.path.is_absolute(),
                  "Log open failure not observable");
            logger.write(nd::Level::errors_only, "MEMORY_FALLBACK", "survives file failure");
            const auto memory = logger.snapshot(nd::Level::debug);
            check(std::any_of(memory.begin(),
                              memory.end(),
                              [](const auto& e) { return e.code == "MEMORY_FALLBACK"; }),
                  "File failure lost memory events");
            const auto recovery = directory / "recovered.log";
            logger.configure_file(true, nd::Level::debug, recovery);
            logger.write(nd::Level::debug, "RECOVERED", "actual disk write");
            logger.flush_file();
            check(logger.file_status().state == "ENABLED" &&
                      logger.file_status().path == std::filesystem::absolute(recovery),
                  "Logger did not recover after configuration repair");
            // Replacing the owned file with a directory forces a real append failure.
            std::filesystem::remove(recovery);
            std::filesystem::create_directory(recovery);
            logger.write(nd::Level::debug, "WRITE_FAILURE", "cannot append");
            try {
                logger.flush_file();
            } catch (...) {
            }
            check(logger.file_status().state == "FAILED" && logger.file_status().lost_events > 0,
                  "Append failure not counted or sink still reports enabled");
            std::filesystem::remove(recovery);
            logger.configure_file(false, nd::Level::normal, {});
            std::filesystem::remove(blocked_path);
        }
        std::filesystem::remove(directory);
        {
            const auto unicode_directory = std::filesystem::temp_directory_path() /
                nd::platform::path_from_utf8("NativeDNS-тест-日本語-😀-" + std::to_string(nd::platform::process_id()));
            std::filesystem::create_directories(unicode_directory);
            const auto unrelated = unicode_directory / nd::platform::path_from_utf8("чужой-файл-日本語.txt");
            { std::ofstream file(unrelated); file << "keep"; }
            const auto unicode_log = nd::timestamped_log_path(unicode_directory);
            const std::string message = "Сервер 日本語 😀";
            logger.configure_file(true, nd::Level::normal, unicode_log, 1024, 2);
            logger.write(nd::Level::normal, "UNICODE", message);
            logger.configure_file(false, nd::Level::normal, {});
            std::ifstream file(unicode_log, std::ios::binary);
            const std::string contents((std::istreambuf_iterator<char>(file)), {});
            check(contents.find(message) != std::string::npos, "file log must retain UTF-8 bytes");
            file.close();
            check(std::filesystem::exists(unrelated), "log pruning removed an unrelated Unicode file");
            std::filesystem::remove(unicode_log);
            std::filesystem::remove(unrelated);
            std::filesystem::remove(unicode_directory);
        }
        {
            const auto dist_root = std::filesystem::temp_directory_path() /
                ("NativeDNS-dist-test-" + std::to_string(nd::platform::process_id()));
            std::filesystem::remove_all(dist_root);
            std::filesystem::create_directories(dist_root / "bin");
            std::filesystem::create_directories(dist_root / "app");
            check(nd::platform::detect_distribution_in_directory(dist_root, false) ==
                      nd::platform::DistributionKind::portable,
                  "Default distribution without marker is portable");
            check(nd::platform::detect_distribution_in_directory(dist_root, true) ==
                      nd::platform::DistributionKind::executable,
                  "Registry fallback identifies executable installation");
            { std::ofstream f(dist_root / "unins000.exe"); f << "stub"; }
            check(nd::platform::detect_distribution_in_directory(dist_root, false) ==
                      nd::platform::DistributionKind::executable,
                  "Inno Setup uninstaller fallback identifies executable installation");
            { std::ofstream f(dist_root / "app" / "distribution"); f << "portable\n"; }
            check(nd::platform::detect_distribution_in_directory(dist_root, true) ==
                      nd::platform::DistributionKind::portable,
                  "Explicit app/distribution marker overrides fallback");
            { std::ofstream f(dist_root / "bin" / "distribution"); f << "Executable\r\n"; }
            check(nd::platform::detect_distribution_in_directory(dist_root, false) ==
                      nd::platform::DistributionKind::executable,
                  "bin/distribution marker takes precedence and is case-insensitive");
            check(std::string(nd::platform::distribution_name(nd::platform::DistributionKind::portable)) == "portable" &&
                  std::string(nd::platform::distribution_label(nd::platform::DistributionKind::portable)) == "Portable" &&
                  std::string(nd::platform::distribution_name(nd::platform::DistributionKind::executable)) == "executable" &&
                  std::string(nd::platform::distribution_label(nd::platform::DistributionKind::executable)) == "Executable",
                  "Distribution names and UI labels match");
            check(nd::platform::system_summary().find("distribution=") != std::string::npos,
                  "system_summary includes distribution field");
            std::filesystem::remove_all(dist_root);
        }
        std::cout << "foundation passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
