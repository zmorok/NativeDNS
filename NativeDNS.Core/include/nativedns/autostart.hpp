#pragma once
#include <filesystem>
#include <string>

namespace nd {
struct AutostartStatus {
    bool enabled=false;
    bool needs_repair=false;
    std::filesystem::path executable;
    std::string arguments;
};
void enable_autostart(const std::filesystem::path& executable,const std::filesystem::path& config,
                      const std::filesystem::path& gui_executable = {});
void disable_autostart();
AutostartStatus autostart_status();
bool start_autostart_core(const std::filesystem::path& executable,const std::filesystem::path& config);
}
