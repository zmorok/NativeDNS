#include <nativedns/network_preparation.hpp>
#include <algorithm>
#include <set>

namespace nd {
namespace {
constexpr size_t max_settings = 256, max_text = 16384, max_journal = 2 * 1024 * 1024;
void validate_setting(const PreparedNetworkSetting& setting) {
    if (setting.key.empty() || setting.key.size() > 512 ||
        setting.key.find_first_of("\r\n\t") != std::string::npos ||
        setting.key.find('\0') != std::string::npos || setting.original.size() > max_text ||
        setting.prepared.size() > max_text || setting.original == setting.prepared)
        throw Error("DNS_PREPARATION_JOURNAL", "Invalid network recovery setting");
}
void failure(NetworkPreparationResult& result, const std::string& key, const std::exception& error) {
    result.findings.push_back({Level::errors_only, "DNS_PREPARATION_FAILED", "setting=" + key + "; " + error.what()});
}
}
std::string serialize_network_journal(const std::vector<PreparedNetworkSetting>& settings) {
    if (settings.size() > max_settings) throw Error("DNS_PREPARATION_JOURNAL", "Too many network recovery settings");
    std::string result = "NDN1";
    const auto number = [&](size_t n) {
        for (unsigned shift = 0; shift < 32; shift += 8) result.push_back(static_cast<char>((n >> shift) & 255));
    };
    number(settings.size());
    std::set<std::string> keys;
    for (const auto& setting : settings) {
        validate_setting(setting);
        if (!keys.insert(setting.key).second) throw Error("DNS_PREPARATION_JOURNAL", "Duplicate network recovery setting");
        for (const auto* value : {&setting.key, &setting.original, &setting.prepared}) {
            number(value->size()); result += *value;
            if (result.size() > max_journal) throw Error("DNS_PREPARATION_JOURNAL", "Network recovery journal exceeds 2 MiB");
        }
    }
    return result;
}
std::vector<PreparedNetworkSetting> parse_network_journal(const std::string& bytes) {
    if (bytes.size() > max_journal || !bytes.starts_with("NDN1"))
        throw Error("DNS_PREPARATION_JOURNAL", "Invalid network recovery journal");
    size_t cursor = 4;
    const auto number = [&]() {
        if (bytes.size() - cursor < 4) throw Error("DNS_PREPARATION_JOURNAL", "Truncated network recovery journal");
        uint32_t n = 0;
        for (unsigned shift = 0; shift < 32; shift += 8)
            n |= static_cast<uint32_t>(static_cast<unsigned char>(bytes[cursor++])) << shift;
        return n;
    };
    const auto count = number();
    if (count > max_settings) throw Error("DNS_PREPARATION_JOURNAL", "Too many network recovery settings");
    std::vector<PreparedNetworkSetting> result;
    for (uint32_t i = 0; i < count; ++i) {
        PreparedNetworkSetting setting;
        for (auto* value : {&setting.key, &setting.original, &setting.prepared}) {
            const auto size = number();
            if (size > bytes.size() - cursor) throw Error("DNS_PREPARATION_JOURNAL", "Truncated network recovery value");
            *value = bytes.substr(cursor, size); cursor += size;
        }
        result.push_back(std::move(setting));
    }
    if (cursor != bytes.size() || serialize_network_journal(result) != bytes)
        throw Error("DNS_PREPARATION_JOURNAL", "Invalid network recovery encoding");
    return result;
}
NetworkPreparation::NetworkPreparation(std::unique_ptr<NetworkPreparationBackend> backend)
    : backend_(std::move(backend)) {}
void NetworkPreparation::load() {
    if (loaded_) return;
    auto saved = backend_->load_journal();
    (void)serialize_network_journal(saved);
    active_ = std::move(saved); loaded_ = true;
}
bool NetworkPreparation::restore_at(size_t index, NetworkPreparationResult& result) {
    const auto setting = active_[index];
    try {
        const auto current = backend_->read(setting.key);
        if (current && *current != setting.original && *current != setting.prepared) {
            result.findings.push_back({Level::errors_only, "DNS_PREPARATION_CONFLICT",
                "setting=" + setting.key + "; external changes preserved; original settings retained in recovery journal"});
            return false;
        }
        if (current && *current == setting.prepared) {
            backend_->replace(setting.key, setting.prepared, setting.original);
            result.changed = true;
            result.findings.push_back({Level::normal, "DNS_PREPARATION_RESTORED", "setting=" + setting.key});
        } else if (!current) {
            result.findings.push_back({Level::normal, "DNS_PREPARATION_SUPERSEDED",
                "setting=" + setting.key + "; removed DNS setting was not recreated"});
        }
        auto remaining = active_; remaining.erase(remaining.begin() + static_cast<std::ptrdiff_t>(index));
        backend_->save_journal(remaining); // A failed save leaves the original record retryable.
        active_ = std::move(remaining);
        return true;
    } catch (const std::exception& error) { failure(result, setting.key, error); return false; }
}
NetworkPreparationResult NetworkPreparation::restore() {
    NetworkPreparationResult result;
    try { load(); }
    catch (const std::exception& error) { failure(result, "recovery-journal", error); return result; }
    // Undo in reverse order: per-server properties precede adapter auto-upgrade
    // flags, so re-enabling DDR cannot race with the remaining restoration.
    for (size_t i = active_.size(); i > 0; --i) (void)restore_at(i - 1, result);
    return result;
}
NetworkPreparationResult NetworkPreparation::apply(const Config& config, const NetworkSnapshot& network) {
    NetworkPreparationResult result;
    try { load(); }
    catch (const std::exception& error) { failure(result, "recovery-journal", error); return result; }
    const bool needed = runtime_options(config).prepare_system_dns &&
        std::any_of(config.rules.begin(), config.rules.end(), [](const Rule& rule) {
            return rule.enabled &&
                   (rule.action == Action::block ||
                    (rule.action == Action::process && (rule.server_id != 0 || rule.pool_id != 0)));
        });
    if (!recovered_ || !needed) {
        result = restore(); recovered_ = true;
    }
    if (!needed) return result;
    NetworkPreparationScan scan;
    try { scan = backend_->scan(network); }
    catch (const std::exception& error) { failure(result, "system-dns", error); return result; }
    result.findings.insert(result.findings.end(), scan.findings.begin(), scan.findings.end());
    for (const auto& setting : scan.settings) {
        if (std::any_of(active_.begin(), active_.end(), [&](const auto& saved) { return saved.key == setting.key; })) {
            result.findings.push_back({Level::errors_only, "DNS_PREPARATION_OVERRIDDEN",
                "setting=" + setting.key + "; external resolver changes require review; existing recovery data retained"});
            continue;
        }
        try {
            validate_setting(setting);
            auto next = active_; next.push_back(setting);
            (void)serialize_network_journal(next);
            backend_->save_journal(next); // Always durable before changing an adapter.
            active_ = std::move(next);
            try {
                backend_->replace(setting.key, setting.original, setting.prepared);
                result.changed = true;
                result.findings.push_back({Level::normal, "DNS_PREPARATION_APPLIED", "setting=" + setting.key});
            } catch (const std::exception& error) {
                failure(result, setting.key, error);
                (void)restore_at(active_.size() - 1, result);
            }
        } catch (const std::exception& error) { failure(result, setting.key, error); return result; }
    }
    return result;
}
} // namespace nd
