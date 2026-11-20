#include "../NativeDNS.Core/src/platform/windows/network_preparation.hpp"
#include "../NativeDNS.Core/src/platform/windows/recovery_store.hpp"
#include <nativedns/platform.hpp>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

namespace {
using namespace std::string_literals;
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void fails(F action, const char* code) {
    try { action(); } catch (const nd::Error& error) { check(error.code == code, "Unexpected recovery error"); return; }
    throw std::runtime_error("Expected recovery error");
}
bool has(const nd::NetworkPreparationResult& result, const std::string& code) {
    for (const auto& finding : result.findings) if (finding.code == code) return true;
    return false;
}
std::vector<std::wstring> split(std::wstring value) {
    std::replace(value.begin(), value.end(), L',', L' ');
    std::wistringstream input(value); std::vector<std::wstring> result; std::wstring item;
    while (input >> item) result.push_back(item);
    return result;
}
struct Entry {
    bool profile = false, dot = false;
    ULONG index = 0;
    uint64_t flags = 0;
    std::wstring text;
    USHORT port = 0;
    DNS_SERVER_PROPERTY_TYPE override_type = DnsServerInvalidProperty;
};
struct Export {
    std::wstring names, profiles, domain = L"home.example", search = L"home.example,office.example";
    std::vector<std::wstring> texts;
    std::vector<DNS_DOH_SERVER_SETTINGS> doh;
    std::vector<DNS_DOT_SERVER_SETTINGS> dot;
    std::vector<DNS_SERVER_PROPERTY> adapter, profile;
    Export(const std::wstring& n, const std::wstring& p, const std::vector<Entry>& entries) : names(n), profiles(p) {
        texts.reserve(entries.size()); doh.resize(entries.size()); dot.resize(entries.size());
        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i]; texts.push_back(entry.text);
            auto* text = texts.back().empty() ? nullptr : texts.back().data();
            doh[i] = {text, entry.flags}; dot[i] = {text, entry.flags, entry.port};
            DNS_SERVER_PROPERTY property{}; property.Version = DNS_SERVER_PROPERTY_VERSION1; property.ServerIndex = entry.index;
            property.Type = entry.override_type != DnsServerInvalidProperty
                                ? entry.override_type
                                : (entry.dot ? DnsServerDotProperty : DnsServerDohProperty);
            if (entry.dot) property.Property.DotSettings = &dot[i]; else property.Property.DohSettings = &doh[i];
            (entry.profile ? profile : adapter).push_back(property);
        }
    }
};
struct FakeApi final : nd::platform::detail::InterfaceDnsApi {
    std::wstring names = L"111.88.96.54,1.1.1.1,2001:db8::53", profiles = L"9.9.9.9";
    ULONG ddr = 7;
    std::vector<Entry> entries{{false, false, 0, 17, L"https://automatic.example/dns-query", 0}, {false, false, 1, 6, L"https://dns.example/dns-query?key=тест", 0},
                               {false, true, 1, 3, L"dot.example", 853}, {false, false, 2, 1, {}, 0},
                               {true, false, 0, 2, L"https://profile.example/dns-query", 0}};
    std::map<DNS_INTERFACE_SETTINGS*, std::unique_ptr<Export>> allocated;
    bool version3_only = false, disconnected = false, fail_set = false, partial_set = false, ignore_set = false;
    bool unsupported = false;
    bool add_external_dns = false;
    int sets = 0, ipv6_sets = 0, v4_rejections = 0;
    std::function<void()> before_set;
    DWORD get(GUID, DNS_INTERFACE_SETTINGS* base) override {
        check(base->Flags == 0, "GetInterfaceDnsSettings requires empty input flags");
        if (unsupported) return ERROR_NOT_SUPPORTED;
        if (disconnected) return ERROR_NOT_FOUND;
        if (version3_only && base->Version == DNS_INTERFACE_SETTINGS_VERSION4) { ++v4_rejections; return ERROR_INVALID_PARAMETER; }
        const auto version = base->Version;
        auto data = std::make_unique<Export>(names, profiles, entries); auto& e = *data;
        auto* output = reinterpret_cast<DNS_INTERFACE_SETTINGS4*>(base);
        *output = {}; output->Version = version;
        output->NameServer = e.names.data(); output->ProfileNameServer = e.profiles.data();
        output->Domain = e.domain.data(); output->SearchList = e.search.data(); output->RegistrationEnabled = 1;
        output->cServerProperties = static_cast<ULONG>(e.adapter.size()); output->ServerProperties = e.adapter.empty() ? nullptr : e.adapter.data();
        output->cProfileServerProperties = static_cast<ULONG>(e.profile.size()); output->ProfileServerProperties = e.profile.empty() ? nullptr : e.profile.data();
        if (version == DNS_INTERFACE_SETTINGS_VERSION4) output->EncryptedDnsAdapterFlags = ddr;
        allocated[base] = std::move(data);
        return NO_ERROR;
    }
    void free(DNS_INTERFACE_SETTINGS* base) override { check(allocated.erase(base) == 1, "API snapshot was not freed exactly once"); }
    DWORD set(GUID, const DNS_INTERFACE_SETTINGS* base) override {
        if (before_set) before_set();
        ++sets;
        const auto& s = *reinterpret_cast<const DNS_INTERFACE_SETTINGS4*>(base);
        check(!(s.Flags & (DNS_SETTING_NAMESERVER | DNS_SETTING_PROFILE_NAMESERVER | DNS_SETTING_SEARCHLIST | DNS_SETTING_DOMAIN)) &&
                  !s.Domain && !s.SearchList && !s.SupplementalSearchList && !s.RegistrationEnabled && !s.EnableLLMNR &&
                  !s.QueryAdapterName && !s.RegisterAdapterName, "Setter changed an unrelated DNS option");
        if (fail_set) { fail_set = false; return ERROR_ACCESS_DENIED; }
        if (ignore_set) { ignore_set = false; return NO_ERROR; }
        if (s.Flags == DNS_SETTING_ENCRYPTED_DNS_ADAPTER_FLAGS) {
            check(s.Version == DNS_INTERFACE_SETTINGS_VERSION4 && !s.NameServer && !s.ProfileNameServer &&
                      !s.cServerProperties && !s.cProfileServerProperties, "DDR update included unrelated fields");
            ddr = s.EncryptedDnsAdapterFlags;
        } else {
            const bool profile = (s.Flags & (DNS_SETTING_DOH_PROFILE | DNS_SETTING_DOT_PROFILE)) != 0;
            const bool dot = (s.Flags & (DNS_SETTING_DOT | DNS_SETTING_DOT_PROFILE)) != 0;
            const bool ipv6 = (s.Flags & DNS_SETTING_IPV6) != 0;
            const auto expected_flags = (ipv6 ? DNS_SETTING_IPV6 : 0) |
                (dot ? (profile ? DNS_SETTING_DOT_PROFILE : DNS_SETTING_DOT) : (profile ? DNS_SETTING_DOH_PROFILE : DNS_SETTING_DOH));
            check(s.Flags == expected_flags && s.Version == DNS_INTERFACE_SETTINGS_VERSION3, "Invalid per-server setter flags");
            const auto* address = profile ? s.ProfileNameServer : s.NameServer;
            const auto count = profile ? s.cProfileServerProperties : s.cServerProperties;
            const auto* properties = profile ? s.ProfileServerProperties : s.ServerProperties;
            check(address && count == 1 && properties && properties->ServerIndex == 0 &&
                      properties->Version == DNS_SERVER_PROPERTY_VERSION1, "Setter did not isolate one DNS server property");
            check(profile ? (!s.NameServer && !s.cServerProperties) : (!s.ProfileNameServer && !s.cProfileServerProperties),
                  "Setter mixed adapter/profile settings");
            const auto list = split(profile ? profiles : names);
            const auto found = std::find(list.begin(), list.end(), address);
            check(found != list.end(), "Setter tried to recreate a removed DNS address");
            const auto index = static_cast<ULONG>(found - list.begin());
            check(ipv6 == (std::wstring(address).find(L':') != std::wstring::npos), "IPv6 encryption used IPv4 setter flags");
            if (ipv6) ++ipv6_sets;
            Entry changed{profile, dot, index};
            if (dot) {
                check(properties->Type == DnsServerDotProperty, "Wrong DoT property type");
                const auto& value = *properties->Property.DotSettings;
                changed.flags = value.Flags; changed.port = value.Port; if (value.Hostname) changed.text = value.Hostname;
            } else {
                check(properties->Type == DnsServerDohProperty, "Wrong DoH property type");
                const auto& value = *properties->Property.DohSettings;
                check(!(value.Flags & DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO) || !value.Template, "AUTO DoH restoration pinned a derived URI template");
                changed.flags = value.Flags; if (value.Template) changed.text = value.Template;
            }
            const auto entry = std::find_if(entries.begin(), entries.end(), [&](const auto& e) { return e.profile == profile && e.dot == dot && e.index == index; });
            if (entry != entries.end()) entries.erase(entry);
            // Windows may omit a disabled property entirely in the next query.
            if (changed.flags || !changed.text.empty()) entries.push_back(changed);
        }
        if (add_external_dns) { add_external_dns = false; names += L",8.8.8.8"; }
        if (partial_set) { partial_set = false; return ERROR_GEN_FAILURE; }
        return NO_ERROR;
    }
    std::wstring fingerprint() const {
        std::vector<std::wstring> rows;
        for (const auto& e : entries)
            rows.push_back(std::to_wstring(e.profile) + L"/" + std::to_wstring(e.dot) + L"/" + std::to_wstring(e.index) + L"/" +
                std::to_wstring(e.flags) + L"/" + (!e.dot && (e.flags & DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO) ? L"" : e.text) + L"/" + std::to_wstring(e.port));
        std::sort(rows.begin(), rows.end());
        auto result = names + L"|" + profiles + L"|" + std::to_wstring(ddr);
        for (const auto& row : rows) result += L"|" + row;
        return result;
    }
};
nd::NetworkSnapshot network() {
    nd::NetworkSnapshot result; nd::InterfaceInfo info;
    info.id = "{29B84DDE-9992-45CF-8996-AF6BDE717B56}"; info.name = "Wi-Fi"; info.up = true;
    info.addresses = {"192.0.2.10", "2001:db8::10"}; result.interfaces.push_back(info);
    return result;
}
auto backend(const std::shared_ptr<FakeApi>& api, std::optional<std::string>& journal) {
    return nd::platform::detail::make_windows_network_backend(api, [&journal] { return journal; },
        [&journal](const auto& bytes) { journal = bytes; });
}
struct Sandbox {
    std::filesystem::path root;
    Sandbox() {
        root = std::filesystem::temp_directory_path() / (L"NativeDNS-recovery-test-" + std::to_wstring(nd::platform::process_id()) +
            L"-" + std::to_wstring(nd::platform::secure_random_u32()) + L"-Кириллица-日本語");
        check(std::filesystem::create_directory(root), "Test directory exists");
    }
    ~Sandbox() {
        if (root.parent_path() == std::filesystem::temp_directory_path() && root.filename().wstring().starts_with(L"NativeDNS-recovery-test-")) {
            std::error_code ignored; std::filesystem::remove_all(root, ignored);
        }
    }
};
}
int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--inspect-system") {
            std::optional<std::string> journal;
            auto api = nd::platform::detail::make_system_dns_api();
            auto inspection = nd::platform::detail::make_windows_network_backend(api, [&] { return journal; },
                [&](const auto&) { throw std::runtime_error("Read-only inspection attempted a journal write"); });
            const auto current = nd::NetworkMonitor::shared().snapshot();
            const auto scan = inspection->scan(*current);
            std::cout << "read_only=1 interfaces=" << current->interfaces.size() << " candidates=" << scan.settings.size() << '\n';
            for (const auto& item : scan.settings) std::cout << "candidate=" << item.key << '\n';
            for (const auto& item : scan.findings) std::cout << item.code << ' ' << item.message << '\n';
            return 0;
        }
        auto config = nd::default_config(); config.rules.back().action = nd::Action::block;
        const auto snapshot = network();
        for (bool old_api : {false, true}) {
            auto api = std::make_shared<FakeApi>(); api->version3_only = old_api;
            const auto original = api->fingerprint(); std::optional<std::string> journal;
            api->before_set = [&] { check(journal && !nd::parse_network_journal(*journal).empty(), "Adapter changed before journal persistence"); };
            nd::NetworkPreparation preparation(backend(api, journal));
            const auto result = preparation.apply(config, snapshot);
            check(result.changed && !has(result, "DNS_PREPARATION_FAILED") && api->ipv6_sets > 0,
                  "Windows adapter/profile/IPv6 preparation failed");
            check(!preparation.apply(config, snapshot).changed, "Prepared Windows settings were repeatedly written");
            check(preparation.restore().changed && api->fingerprint() == original && !journal && api->allocated.empty(),
                  "Windows restoration did not preserve original DNS settings");
            if (old_api) check(api->v4_rejections > 0, "Older Windows API fallback was not exercised");
        }
        for (int failure = 0; failure < 3; ++failure) {
            auto api = std::make_shared<FakeApi>(); const auto original = api->fingerprint(); std::optional<std::string> journal;
            api->fail_set = failure == 0; api->partial_set = failure == 1; api->ignore_set = failure == 2;
            nd::NetworkPreparation preparation(backend(api, journal));
            check(has(preparation.apply(config, snapshot), "DNS_PREPARATION_FAILED"), "OS failure or failed readback was hidden");
            (void)preparation.restore();
            check(api->fingerprint() == original && !journal, "OS failure rollback lost original settings");
        }
        {
            auto api = std::make_shared<FakeApi>(); api->unsupported = true; std::optional<std::string> journal;
            nd::NetworkPreparation preparation(backend(api, journal));
            const auto result = preparation.apply(config, snapshot);
            check(has(result, "DNS_PREPARATION_UNAVAILABLE") && result.findings.front().level == nd::Level::normal &&
                      !result.changed && !api->sets && !journal, "Unsupported Windows API was treated as a failed DNS operation");
        }
        {
            auto api = std::make_shared<FakeApi>();
            api->entries.push_back(
                {false, false, 0, 1, L"future", 0, static_cast<DNS_SERVER_PROPERTY_TYPE>(99)});
            std::optional<std::string> journal;
            nd::NetworkPreparation preparation(backend(api, journal));
            const auto result = preparation.apply(config, snapshot);
            check(has(result, "DNS_PREPARATION_UNAVAILABLE") &&
                      result.findings.front().level == nd::Level::errors_only &&
                      !result.changed && !api->sets && !journal,
                  "Unknown DNS_SERVER_PROPERTY_TYPE must fail explicitly instead of assuming DoT");
        }
        {
            auto api = std::make_shared<FakeApi>(); const auto original = api->fingerprint(); std::optional<std::string> journal;
            { nd::NetworkPreparation first(backend(api, journal)); (void)first.apply(config, snapshot); }
            api->disconnected = true;
            nd::NetworkPreparation restart(backend(api, journal));
            check(has(restart.restore(), "DNS_PREPARATION_FAILED") && journal, "Disconnected adapter recovery data was lost");
            api->disconnected = false;
            check(restart.restore().changed && api->fingerprint() == original && !journal, "Reconnected adapter was not recovered");
        }
        {
            auto api = std::make_shared<FakeApi>(); std::optional<std::string> journal;
            nd::NetworkPreparation preparation(backend(api, journal)); (void)preparation.apply(config, snapshot);
            api->entries.push_back({false, false, 0, 2, L"https://user.example/dns-query", 0});
            check(has(preparation.restore(), "DNS_PREPARATION_CONFLICT") && journal &&
                      nd::parse_network_journal(*journal).size() == 1, "A user encryption change was overwritten");
            check(api->entries.front().text == L"https://user.example/dns-query", "User template was changed during recovery");
        }
        {
            auto api = std::make_shared<FakeApi>(); std::optional<std::string> journal; api->add_external_dns = true;
            nd::NetworkPreparation preparation(backend(api, journal));
            check(has(preparation.apply(config, snapshot), "DNS_PREPARATION_FAILED"), "Concurrent DNS list change was not detected");
            (void)preparation.restore();
            check(api->names.ends_with(L",8.8.8.8"), "Recovery overwrote a concurrent DNS address change");
        }
        {
            Sandbox box;
            fails([&] { nd::platform::detail::ensure_recovery_directory(box.root); }, "DNS_PREPARATION_SECURITY");
            fails([&] { nd::platform::detail::RecoveryFile machine(box.root, "system-dns"); }, "DNS_PREPARATION_SECURITY");
            const std::string bytes = "NDN1\0binary\0data"s;
            {
                nd::platform::detail::RecoveryFile file(box.root, "system-dns", nd::platform::detail::RecoveryScope::current_user);
                check(!file.load(), "New journal was not empty"); file.save(bytes);
                check(file.load() == bytes, "Persistent journal corrupted binary/Unicode data");
                fails([&] { nd::platform::detail::RecoveryFile second(box.root, "system-dns", nd::platform::detail::RecoveryScope::current_user); }, "DNS_PREPARATION_IO");
            }
            nd::platform::detail::RecoveryFile restart(box.root, "system-dns", nd::platform::detail::RecoveryScope::current_user);
            check(restart.load() == bytes, "Next process could not load persisted recovery data");
            restart.clear(); check(!restart.load(), "Recovered journal could not be cleared");
        }
        std::cout << "Windows DNS preparation API and isolated recovery storage passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
