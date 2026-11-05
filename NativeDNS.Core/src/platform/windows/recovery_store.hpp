#pragma once
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace nd::platform::detail {
enum class RecoveryScope { machine, current_user };
void ensure_recovery_directory(const std::filesystem::path& directory);
std::filesystem::path network_recovery_directory();
class RecoveryFile {
public:
    // Production callers use the protected machine recovery directory. Tests
    // supply an isolated directory without touching machine network settings.
    RecoveryFile(const std::filesystem::path& directory, const std::string& name,
                 RecoveryScope scope = RecoveryScope::machine);
    ~RecoveryFile();
    RecoveryFile(const RecoveryFile&) = delete;
    RecoveryFile& operator=(const RecoveryFile&) = delete;
    std::optional<std::string> load();
    void save(const std::string& bytes);
    void clear();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace nd::platform::detail
