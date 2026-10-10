#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <fstream>
#include <sstream>

namespace nd::platform {
namespace {
uint64_t birth(uint32_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    std::getline(input, line);
    const auto end = line.rfind(')');
    if (end == std::string::npos)
        return 0;
    std::istringstream fields(line.substr(end + 1));
    std::string value;
    for (unsigned field = 3; field <= 22; ++field)
        if (!(fields >> value))
            return 0;
    return std::stoull(value);
}
bool matches(uint32_t pid, const std::filesystem::path& executable) {
    std::error_code error;
    const auto image =
        std::filesystem::read_symlink("/proc/" + std::to_string(pid) + "/exe", error);
    return !error && image == std::filesystem::weakly_canonical(executable);
}
} // namespace

std::vector<ProcessIdentity> matching_processes(const std::filesystem::path& executable) {
    std::vector<ProcessIdentity> result;
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        const auto name = entry.path().filename().string();
        if (name.empty() || name.find_first_not_of("0123456789") != std::string::npos)
            continue;
        const auto pid = static_cast<uint32_t>(std::stoul(name));
        const auto started = birth(pid);
        if (pid != process_id() && started && matches(pid, executable))
            result.push_back({pid, started});
    }
    return result;
}

void force_stop_process(const std::filesystem::path&, ProcessIdentity) {
    // SIGKILL would leave nftables redirection pointing at a dead DNS proxy.
    // Keep the GUI alive until a separately validated cleanup path is available.
    throw Error("PROCESS_FORCE_UNSUPPORTED",
                "Linux emergency termination requires validated nftables cleanup; "
                "use the independent graceful shutdown channel.");
}
} // namespace nd::platform
