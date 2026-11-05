#pragma once
#include <nativedns/network_preflight.hpp>
#include <optional>

namespace nd {
struct PreparedNetworkSetting {
    std::string key, original, prepared;
    bool operator==(const PreparedNetworkSetting&) const = default;
};
struct NetworkPreparationResult {
    bool changed = false;
    std::vector<PreflightFinding> findings;
};
struct NetworkPreparationScan {
    std::vector<PreparedNetworkSetting> settings;
    std::vector<PreflightFinding> findings;
};
std::string serialize_network_journal(const std::vector<PreparedNetworkSetting>& settings);
std::vector<PreparedNetworkSetting> parse_network_journal(const std::string& bytes);
class NetworkPreparationBackend {
public:
    virtual ~NetworkPreparationBackend() = default;
    virtual NetworkPreparationScan scan(const NetworkSnapshot& network) = 0;
    // Missing means the user removed this setting. An inaccessible/disconnected
    // adapter throws instead, retaining its recovery record for a later retry.
    virtual std::optional<std::string> read(const std::string& key) = 0;
    virtual void replace(const std::string& key, const std::string& expected, const std::string& value) = 0;
    virtual std::vector<PreparedNetworkSetting> load_journal() = 0;
    virtual void save_journal(const std::vector<PreparedNetworkSetting>& settings) = 0;
};
class NetworkPreparation {
public:
    explicit NetworkPreparation(std::unique_ptr<NetworkPreparationBackend> backend);
    NetworkPreparationResult apply(const Config& config, const NetworkSnapshot& network);
    NetworkPreparationResult restore();
private:
    void load();
    bool restore_at(size_t index, NetworkPreparationResult& result);
    std::unique_ptr<NetworkPreparationBackend> backend_;
    std::vector<PreparedNetworkSetting> active_;
    bool loaded_ = false, recovered_ = false;
};
namespace platform {
// Null on platforms without automatic system-DNS preparation.
std::unique_ptr<NetworkPreparation> make_network_preparation();
} // namespace platform
} // namespace nd
