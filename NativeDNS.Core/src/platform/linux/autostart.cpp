#include <nativedns/autostart.hpp>
#include <nativedns/config.hpp>

#include <cstdlib>
#include <fstream>

namespace nd {
namespace {
std::filesystem::path desktop_path() {
    std::filesystem::path base;
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg) {
        base = xdg;
    } else if (const char* home = std::getenv("HOME"); home && *home) {
        base = std::filesystem::path(home) / ".config";
    } else {
        throw Error("AUTOSTART", "HOME/XDG_CONFIG_HOME is unavailable");
    }
    return base / "autostart" / "nativedns.desktop";
}

std::string quote(const std::filesystem::path& path) {
    std::string source = path.string();
    std::string output = "\"";
    for (const char character : source) {
        if (character == '\\' || character == '\"') {
            output += '\\';
        }
        output += character;
    }
    output += '\"';
    return output;
}
}

void enable_autostart(const std::filesystem::path& executable, const std::filesystem::path& config,
                      const std::filesystem::path&) {
    if (!std::filesystem::is_regular_file(executable)) {
        throw Error("AUTOSTART", "NativeDNS executable does not exist");
    }
    if (!std::filesystem::is_regular_file(config)) {
        throw Error("AUTOSTART", "Autostart config does not exist");
    }

    (void)load_config(config);
    const auto path = desktop_path();
    std::filesystem::create_directories(path.parent_path());

    std::ofstream output(path, std::ios::trunc);
    if (!output) {
        throw Error("AUTOSTART", "Cannot create XDG autostart entry");
    }
    output << "[Desktop Entry]\n"
           << "Type=Application\n"
           << "Name=NativeDNS\n"
           << "Comment=Start NativeDNS in background\n"
           << "Exec=" << quote(std::filesystem::absolute(executable)) << " --background\n"
           << "Terminal=false\n"
           << "X-GNOME-Autostart-enabled=true\n";
    output.flush();
    if (!output) {
        throw Error("AUTOSTART", "Cannot write XDG autostart entry");
    }
}

void disable_autostart() {
    std::error_code error;
    std::filesystem::remove(desktop_path(), error);
    if (error) {
        throw Error("AUTOSTART", "Cannot remove XDG autostart entry: " + error.message());
    }
}

AutostartStatus autostart_status() {
    AutostartStatus result;
    const auto path = desktop_path();
    result.enabled = std::filesystem::is_regular_file(path);
    if (!result.enabled) {
        return result;
    }

    std::ifstream input(path);
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind("Exec=", 0) == 0) {
            result.arguments = line.substr(5);
            break;
        }
    }
    return result;
}

bool start_autostart_core(const std::filesystem::path&, const std::filesystem::path&) {
    return false;
}
}
