#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

namespace nd::updater {

using StatusProgressCallback = std::function<void(int percent, const std::wstring& status)>;

bool wait_for_process_exit(uint32_t pid, uint32_t timeout_ms);
void stop_core_host_gracefully(const std::filesystem::path& install_dir, uint32_t timeout_ms = 12000);

void apply_portable_update(const std::filesystem::path& zip_path,
                           const std::filesystem::path& install_dir,
                           const std::filesystem::path& temp_work_dir,
                           bool russian_ui = false,
                           const StatusProgressCallback& progress = {},
                           int move_retries = 40,
                           uint32_t retry_delay_ms = 200);

std::wstring build_inno_setup_arguments(const std::filesystem::path& install_dir);

void run_executable_installer(const std::filesystem::path& setup_exe,
                              const std::filesystem::path& install_dir);

void relaunch_application(const std::filesystem::path& install_dir,
                          const std::wstring& extra_args = {});

} // namespace nd::updater
