#include <nativedns/network_preparation.hpp>
#include <iostream>
#include <map>
#include <set>

namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void fails(F action) {
    try { action(); } catch (const nd::Error&) { return; }
    throw std::runtime_error("Expected recovery failure");
}
bool has(const nd::NetworkPreparationResult& result, const std::string& code) {
    for (const auto& finding : result.findings) if (finding.code == code) return true;
    return false;
}
struct State {
    std::map<std::string, std::string> values{{"adapter-ddr", "encrypted"}, {"server-doh", "encrypted"}};
    std::string journal;
    std::set<std::string> unavailable;
    std::vector<std::string> writes;
    int saves = 0, fail_save = 0, scans = 0;
    bool partial_failure = false, write_failure = false, concurrent_change = false;
};
struct Backend final : nd::NetworkPreparationBackend {
    std::shared_ptr<State> state;
    explicit Backend(std::shared_ptr<State> s) : state(std::move(s)) {}
    nd::NetworkPreparationScan scan(const nd::NetworkSnapshot&) override {
        ++state->scans;
        nd::NetworkPreparationScan result;
        for (const auto& [key, value] : state->values)
            if (value != "off") result.settings.push_back({key, value, "off"});
        return result;
    }
    std::optional<std::string> read(const std::string& key) override {
        if (state->unavailable.contains(key)) throw nd::Error("UNAVAILABLE", "Adapter is disconnected");
        const auto item = state->values.find(key);
        return item == state->values.end() ? std::nullopt : std::optional(item->second);
    }
    void replace(const std::string& key, const std::string& expected, const std::string& value) override {
        check(!state->journal.empty(), "OS settings were modified before journal persistence");
        check(nd::parse_network_journal(state->journal).size() > 0, "Recovery journal was not valid before OS write");
        if (state->concurrent_change) { state->concurrent_change = false; state->values[key] = "user change"; }
        if (state->values.at(key) != expected) throw nd::Error("CONFLICT", "Concurrent edit");
        if (state->write_failure) { state->write_failure = false; throw nd::Error("ACCESS", "Injected OS refusal"); }
        state->values[key] = value; state->writes.push_back(key);
        if (state->partial_failure) { state->partial_failure = false; throw nd::Error("PARTIAL", "Interrupted after OS write"); }
    }
    std::vector<nd::PreparedNetworkSetting> load_journal() override {
        return state->journal.empty() ? std::vector<nd::PreparedNetworkSetting>{} : nd::parse_network_journal(state->journal);
    }
    void save_journal(const std::vector<nd::PreparedNetworkSetting>& settings) override {
        if (++state->saves == state->fail_save) throw nd::Error("JOURNAL_IO", "Injected disk failure");
        state->journal = settings.empty() ? "" : nd::serialize_network_journal(settings);
    }
};
auto manager(const std::shared_ptr<State>& state) { return nd::NetworkPreparation(std::make_unique<Backend>(state)); }
}
int main() {
    try {
        auto config = nd::default_config();
        config.rules.back().action = nd::Action::block;
        const nd::NetworkSnapshot network;
        check(nd::runtime_options(config).prepare_system_dns, "System DNS preparation is not enabled by default");
        {
            auto state = std::make_shared<State>(); auto preparation = manager(state);
            check(!preparation.apply(nd::default_config(), network).changed && !state->scans && state->writes.empty(),
                  "Original-resolver-only configuration changed OS DNS encryption");
            (void)preparation.apply(config, network);
            check(preparation.apply(nd::default_config(), network).changed && state->journal.empty(),
                  "Removing custom DNS policy did not restore OS settings");
        }
        {
            auto state = std::make_shared<State>(); auto preparation = manager(state);
            check(preparation.apply(config, network).changed && state->values.at("server-doh") == "off", "Settings were not prepared");
            const auto saves = state->saves;
            check(!preparation.apply(config, network).changed && state->saves == saves, "Unchanged state rewrote the journal");
            check(preparation.restore().changed && state->journal.empty(), "Normal shutdown did not restore settings");
            check(state->values.at("server-doh") == "encrypted" && state->writes.back() == "adapter-ddr", "Settings were not restored in reverse order");
        }
        {
            auto state = std::make_shared<State>();
            { auto preparation = manager(state); (void)preparation.apply(config, network); }
            const auto scans = state->scans;
            auto restart = manager(state); auto disabled = config; disabled.settings["windowsPrepareSystemDns"] = "0";
            check(restart.apply(disabled, network).changed && state->journal.empty() && state->scans == scans,
                  "Restart with preparation disabled did not recover previous settings");
        }
        for (int phase : {1, 2}) {
            auto state = std::make_shared<State>(); state->fail_save = phase; auto preparation = manager(state);
            check(has(preparation.apply(config, network), "DNS_PREPARATION_FAILED"), "Disk failure was hidden");
            if (phase == 1) check(state->writes.empty(), "Failed initial journal write modified OS settings");
            state->fail_save = 0; (void)preparation.restore();
            check(state->journal.empty() && state->values.at("adapter-ddr") == "encrypted", "Disk failure recovery lost original settings");
        }
        {
            auto state = std::make_shared<State>(); state->write_failure = true; auto preparation = manager(state);
            check(has(preparation.apply(config, network), "DNS_PREPARATION_FAILED"), "OS refusal was hidden");
            (void)preparation.restore(); check(state->journal.empty(), "Unapplied OS changes left recovery data");
        }
        {
            auto state = std::make_shared<State>(); state->partial_failure = true; auto preparation = manager(state);
            check(has(preparation.apply(config, network), "DNS_PREPARATION_FAILED"), "Partial OS write was hidden");
            check(state->values.at("adapter-ddr") == "encrypted", "Partial OS write was not rolled back");
            (void)preparation.restore(); check(state->journal.empty(), "Partial write left an unrecoverable journal");
        }
        {
            auto state = std::make_shared<State>(); auto preparation = manager(state); (void)preparation.apply(config, network);
            state->values["server-doh"] = "user change";
            check(has(preparation.restore(), "DNS_PREPARATION_CONFLICT") && state->values.at("server-doh") == "user change",
                  "Restoration overwrote an external edit");
            check(nd::parse_network_journal(state->journal).size() == 1, "Conflicting recovery record was discarded");
            state->values["server-doh"] = "encrypted"; (void)preparation.restore();
            check(state->journal.empty(), "Manually restored setting did not clear recovery data");
        }
        {
            auto state = std::make_shared<State>(); auto preparation = manager(state); (void)preparation.apply(config, network);
            state->values.erase("server-doh"); state->unavailable.insert("adapter-ddr");
            const auto result = preparation.restore();
            check(has(result, "DNS_PREPARATION_SUPERSEDED") && has(result, "DNS_PREPARATION_FAILED") &&
                      !state->values.contains("server-doh") && !state->journal.empty(), "Removed/disconnected adapter handling lost recovery data");
            state->unavailable.clear(); (void)preparation.restore(); check(state->journal.empty(), "Reconnected adapter was not restored");
        }
        {
            auto state = std::make_shared<State>(); auto preparation = manager(state); (void)preparation.apply(config, network);
            state->fail_save = state->saves + 1; (void)preparation.restore();
            state->fail_save = 0; (void)preparation.restore();
            check(state->journal.empty() && state->values.at("server-doh") == "encrypted", "Failed journal clear could not be retried");
        }
        {
            auto state = std::make_shared<State>(); state->journal = "corrupt"; auto preparation = manager(state);
            check(has(preparation.apply(config, network), "DNS_PREPARATION_FAILED") && state->writes.empty() && state->journal == "corrupt",
                  "Corrupt recovery data modified OS state");
        }
        const std::vector<nd::PreparedNetworkSetting> records{{"one", "original", "prepared"}};
        check(nd::parse_network_journal(nd::serialize_network_journal(records)) == records, "Journal round trip failed");
        auto truncated = nd::serialize_network_journal(records); truncated.pop_back();
        fails([&] { (void)nd::parse_network_journal(truncated); });
        fails([&] { (void)nd::serialize_network_journal({records.front(), records.front()}); });
        std::cout << "network preparation transactions passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
