#pragma once
#include <filesystem>
#include <string>

namespace nd {
struct AutostartStatus {
    bool enabled=false;
    std::filesystem::path executable;
    std::string arguments;
};
void enable_autostart(const std::filesystem::path& executable,const std::filesystem::path& config);
void disable_autostart();
AutostartStatus autostart_status();
}
