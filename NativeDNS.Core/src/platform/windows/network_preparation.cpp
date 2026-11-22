#include "network_preparation.hpp"
#include "recovery_store.hpp"
#include <nativedns/platform.hpp>
#include <objbase.h>
#include <algorithm>
#include <cctype>
#include <charconv>
#include <map>
#include <set>
#include <sstream>

namespace nd::platform {
namespace {
enum class Kind { doh, dot, ddr };
struct Target { std::string id, server; bool profile = false; Kind kind = Kind::doh; };
struct Value {
    uint64_t flags = 0;
    uint16_t port = 0;
    std::string text;
};
constexpr const char* off = "0\t0\t";
[[noreturn]] void api_error(const char* operation, DWORD error) {
    throw Error("DNS_PREPARATION_API", std::string(operation) + " Windows error=" + std::to_string(error));
}
std::string string_value(const wchar_t* text) {
    if (!text) return {};
    size_t count = 0;
    while (count <= 16384 && text[count]) ++count;
    if (count > 16384) throw Error("DNS_PREPARATION_LIMIT", "Windows DNS text exceeds 16384 characters");
    return narrow(std::wstring(text, count));
}
std::vector<std::string> servers(const wchar_t* text) {
    auto value = string_value(text);
    std::replace(value.begin(), value.end(), ',', ' ');
    std::istringstream input(value);
    std::vector<std::string> result;
    std::string address;
    while (input >> address) {
        std::array<uint8_t, 16> bytes{}; bool ipv6 = false;
        if (!parse_ip(address, bytes, ipv6) || result.size() >= 64)
            throw Error("DNS_PREPARATION_UNSUPPORTED", "Invalid or excessive OS DNS server list");
        result.push_back(format_ip(ipv6 ? bytes.data() : bytes.data() + 12, ipv6));
    }
    return result;
}
std::string key(const Target& target) {
    return "dns|" + target.id + '|' + (target.profile ? "profile|" : "adapter|") +
           (target.kind == Kind::doh ? "doh|" : target.kind == Kind::dot ? "dot|" : "ddr|") + target.server;
}
GUID guid(const std::string& text) {
    GUID id{};
    if (text.size() != 38 || FAILED(CLSIDFromString(widen(text).c_str(), &id)))
        throw Error("DNS_PREPARATION_JOURNAL", "Invalid interface recovery identifier");
    return id;
}
std::string interface_id(GUID id) {
    wchar_t text[40]{};
    if (!StringFromGUID2(id, text, 40)) throw Error("DNS_PREPARATION_API", "Cannot format interface identifier");
    auto result = narrow(text);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}
Target parse_key(const std::string& value) {
    std::vector<std::string> fields;
    size_t start = 0;
    for (;;) {
        const auto end = value.find('|', start);
        fields.push_back(value.substr(start, end == std::string::npos ? end : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (fields.size() != 5 || fields[0] != "dns" || (fields[2] != "adapter" && fields[2] != "profile") ||
        (fields[3] != "doh" && fields[3] != "dot" && fields[3] != "ddr"))
        throw Error("DNS_PREPARATION_JOURNAL", "Invalid DNS recovery key");
    Target result{interface_id(guid(fields[1])), fields[4], fields[2] == "profile",
                  fields[3] == "doh" ? Kind::doh : fields[3] == "dot" ? Kind::dot : Kind::ddr};
    if ((result.kind == Kind::ddr && (result.profile || !result.server.empty())) ||
        (result.kind != Kind::ddr && !is_numeric_ip(result.server)) || key(result) != value)
        throw Error("DNS_PREPARATION_JOURNAL", "Invalid DNS recovery target");
    return result;
}
std::string encode(Value value, Kind kind) {
    if (!value.flags && value.text.empty() && (!value.port || (kind == Kind::dot && value.port == 853))) return off;
    if (value.text.size() > 16000 || value.text.find_first_of("\t\r\n") != std::string::npos || value.text.find('\0') != std::string::npos)
        throw Error("DNS_PREPARATION_UNSUPPORTED", "Invalid encrypted DNS template/hostname");
    return std::to_string(value.flags) + '\t' + std::to_string(value.port) + '\t' + value.text;
}
Value decode(const std::string& bytes, Kind kind) {
    const auto first = bytes.find('\t'), second = first == std::string::npos ? first : bytes.find('\t', first + 1);
    if (second == std::string::npos) throw Error("DNS_PREPARATION_JOURNAL", "Invalid encrypted DNS value");
    Value result;
    const auto [flags_end, flags_error] = std::from_chars(bytes.data(), bytes.data() + first, result.flags);
    unsigned port = 0;
    const auto [port_end, port_error] = std::from_chars(bytes.data() + first + 1, bytes.data() + second, port);
    result.text = bytes.substr(second + 1);
    if (flags_error != std::errc{} || flags_end != bytes.data() + first || port_error != std::errc{} ||
        port_end != bytes.data() + second || port > 65535 || result.flags & ~(kind == Kind::ddr ? 7ull : 63ull))
        throw Error("DNS_PREPARATION_UNSUPPORTED", "Unsupported encrypted DNS flags/port");
    if (kind == Kind::doh && (((result.flags & 3) == 3) ||
        ((result.flags & DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO) && !result.text.empty()) ||
        ((result.flags & DNS_DOH_SERVER_SETTINGS_ENABLE) && result.text.empty())))
        throw Error("DNS_PREPARATION_UNSUPPORTED", "Unrestorable Windows DoH template/flags combination");
    result.port = static_cast<uint16_t>(port);
    if ((kind != Kind::dot && port) || (kind == Kind::ddr && !result.text.empty()) || encode(result, kind) != bytes)
        throw Error("DNS_PREPARATION_JOURNAL", "Noncanonical encrypted DNS value");
    return result;
}
struct Snapshot {
    std::shared_ptr<detail::InterfaceDnsApi> api;
    DNS_INTERFACE_SETTINGS4 value{};
    bool acquired = false;
    Snapshot(std::shared_ptr<detail::InterfaceDnsApi> provider, GUID id) : api(std::move(provider)) {
        value.Version = DNS_INTERFACE_SETTINGS_VERSION4;
        auto status = api->get(id, reinterpret_cast<DNS_INTERFACE_SETTINGS*>(&value));
        if (status == ERROR_INVALID_PARAMETER || status == ERROR_NOT_SUPPORTED) {
            value = {}; value.Version = DNS_INTERFACE_SETTINGS_VERSION3;
            status = api->get(id, reinterpret_cast<DNS_INTERFACE_SETTINGS*>(&value));
        }
        if (status == ERROR_INVALID_PARAMETER || status == ERROR_NOT_SUPPORTED ||
            status == ERROR_FILE_NOT_FOUND)
            throw Error("DNS_PREPARATION_UNAVAILABLE", "This Windows interface does not expose DNS encryption settings");
        if (status != NO_ERROR) api_error("Cannot inspect interface DNS", status);
        acquired = true;
    }
    ~Snapshot() { if (acquired) api->free(reinterpret_cast<DNS_INTERFACE_SETTINGS*>(&value)); }
    Snapshot(const Snapshot&) = delete;
    Snapshot& operator=(const Snapshot&) = delete;
};
Value property(const DNS_SERVER_PROPERTY& item) {
    if (item.Version != DNS_SERVER_PROPERTY_VERSION1)
        throw Error("DNS_PREPARATION_UNSUPPORTED", "Unsupported DNS server property version");
    if (item.Type == DnsServerDohProperty && item.Property.DohSettings) {
        const auto& value = *item.Property.DohSettings;
        // AUTO templates are inherited from the system list. Get may expose
        // the effective template; Set requires NULL rather than pinning it.
        return {value.Flags, 0, value.Flags & DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO ? std::string{} : string_value(value.Template)};
    }
    if (item.Type == DnsServerDotProperty && item.Property.DotSettings) {
        const auto& value = *item.Property.DotSettings;
        return {value.Flags, value.Port, string_value(value.Hostname)};
    }
    throw Error("DNS_PREPARATION_UNSUPPORTED", "Unsupported or missing DNS encryption property");
}
std::map<std::string, std::string> state(const Snapshot& snapshot, const std::string& id) {
    std::map<std::string, std::string> result;
    for (const bool profile : {false, true}) {
        const auto list = servers(profile ? snapshot.value.ProfileNameServer : snapshot.value.NameServer);
        const auto count = profile ? snapshot.value.cProfileServerProperties : snapshot.value.cServerProperties;
        const auto* properties = profile ? snapshot.value.ProfileServerProperties : snapshot.value.ServerProperties;
        if (count > 128 || (count && !properties)) throw Error("DNS_PREPARATION_UNSUPPORTED", "Invalid OS DNS property array");
        for (const auto& address : list)
            for (const auto kind : {Kind::doh, Kind::dot}) result[key({id, address, profile, kind})] = off;
        std::set<std::string> assigned;
        for (ULONG i = 0; i < count; ++i) {
            const auto& item = properties[i];
            if (item.ServerIndex >= list.size()) throw Error("DNS_PREPARATION_UNSUPPORTED", "DNS property index is outside the server list");
            if (item.Type != DnsServerDohProperty && item.Type != DnsServerDotProperty)
                throw Error("DNS_PREPARATION_UNSUPPORTED", "Unsupported DNS server property type");
            const auto kind = item.Type == DnsServerDohProperty ? Kind::doh : Kind::dot;
            const auto name = key({id, list[item.ServerIndex], profile, kind});
            if (!assigned.insert(name).second) throw Error("DNS_PREPARATION_UNSUPPORTED", "Duplicate OS DNS encryption property");
            result[name] = encode(property(item), kind);
        }
    }
    if (snapshot.value.Version == DNS_INTERFACE_SETTINGS_VERSION4)
        result[key({id, {}, false, Kind::ddr})] = encode({snapshot.value.EncryptedDnsAdapterFlags, 0, {}}, Kind::ddr);
    return result;
}
class NativeApi final : public detail::InterfaceDnsApi {
public:
    NativeApi() {
        module_ = LoadLibraryExW(L"iphlpapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module_) throw Error("DNS_PREPARATION_UNAVAILABLE", "Windows DNS settings API is unavailable");
        get_ = reinterpret_cast<decltype(get_)>(GetProcAddress(module_, "GetInterfaceDnsSettings"));
        free_ = reinterpret_cast<decltype(free_)>(GetProcAddress(module_, "FreeInterfaceDnsSettings"));
        set_ = reinterpret_cast<decltype(set_)>(GetProcAddress(module_, "SetInterfaceDnsSettings"));
        if (!get_ || !free_ || !set_) { FreeLibrary(module_); module_ = nullptr;
            throw Error("DNS_PREPARATION_UNAVAILABLE", "This Windows build does not expose DNS preparation APIs"); }
    }
    ~NativeApi() override { if (module_) FreeLibrary(module_); }
    DWORD get(GUID id, DNS_INTERFACE_SETTINGS* settings) override { return get_(id, settings); }
    void free(DNS_INTERFACE_SETTINGS* settings) override { free_(settings); }
    DWORD set(GUID id, const DNS_INTERFACE_SETTINGS* settings) override { return set_(id, settings); }
private:
    HMODULE module_ = nullptr;
    decltype(&GetInterfaceDnsSettings) get_ = nullptr;
    decltype(&FreeInterfaceDnsSettings) free_ = nullptr;
    decltype(&SetInterfaceDnsSettings) set_ = nullptr;
};
class WindowsNetworkBackend final : public NetworkPreparationBackend {
public:
    WindowsNetworkBackend(std::shared_ptr<detail::InterfaceDnsApi> api, detail::LoadNetworkJournal load,
                           detail::SaveNetworkJournal save)
        : api_(std::move(api)), load_(std::move(load)), save_(std::move(save)) {}
    NetworkPreparationScan scan(const NetworkSnapshot& network) override {
        NetworkPreparationScan result;
        for (const auto& info : network.interfaces) {
            if (!info.up || info.loopback || info.addresses.empty()) continue;
            try {
                const auto id = interface_id(guid(info.id));
                Snapshot snapshot(api_, guid(id));
                for (const auto& [name, bytes] : state(snapshot, id)) {
                    const auto target = parse_key(name);
                    const auto value = decode(bytes, target.kind);
                    const auto enabled = target.kind == Kind::ddr ? 1ull : target.kind == Kind::doh ? 19ull : 25ull;
                    if (value.flags & enabled) result.settings.push_back({name, bytes, off});
                }
            } catch (const std::exception& error) {
                const auto* detail = dynamic_cast<const Error*>(&error);
                const auto level = detail && detail->code == "DNS_PREPARATION_UNAVAILABLE" ? Level::normal : Level::errors_only;
                result.findings.push_back({level, "DNS_PREPARATION_UNAVAILABLE",
                    "interface=" + info.name + "; " + error.what()});
            }
        }
        return result;
    }
    std::optional<std::string> read(const std::string& name) override {
        const auto target = parse_key(name);
        Snapshot snapshot(api_, guid(target.id));
        if (target.kind == Kind::ddr && snapshot.value.Version != DNS_INTERFACE_SETTINGS_VERSION4)
            throw Error("DNS_PREPARATION_UNAVAILABLE", "Adapter DDR recovery requires Windows DNS settings version 4");
        const auto values = state(snapshot, target.id);
        const auto item = values.find(name);
        return item == values.end() ? std::nullopt : std::optional(item->second);
    }
    void replace(const std::string& name, const std::string& expected, const std::string& desired) override {
        const auto target = parse_key(name);
        const auto requested = decode(desired, target.kind);
        Snapshot before(api_, guid(target.id));
        auto values = state(before, target.id);
        const auto found = values.find(name);
        if (found == values.end() || found->second != expected)
            throw Error("DNS_PREPARATION_CONFLICT", "OS DNS setting changed before replacement");
        DNS_INTERFACE_SETTINGS4 settings{};
        settings.Version = target.kind == Kind::ddr ? DNS_INTERFACE_SETTINGS_VERSION4 : DNS_INTERFACE_SETTINGS_VERSION3;
        DNS_SERVER_PROPERTY item{};
        item.Version = DNS_SERVER_PROPERTY_VERSION1;
        auto server = widen(target.server), text = widen(requested.text);
        DNS_DOH_SERVER_SETTINGS doh{requested.text.empty() ? nullptr : text.data(), requested.flags};
        DNS_DOT_SERVER_SETTINGS dot{requested.text.empty() ? nullptr : text.data(), requested.flags, requested.port};
        if (target.kind == Kind::ddr) {
            settings.Flags = DNS_SETTING_ENCRYPTED_DNS_ADAPTER_FLAGS;
            settings.EncryptedDnsAdapterFlags = static_cast<ULONG>(requested.flags);
        } else {
            std::array<uint8_t, 16> address{}; bool ipv6 = false;
            if (!parse_ip(target.server, address, ipv6)) throw Error("DNS_PREPARATION_JOURNAL", "Invalid recovery DNS address");
            settings.Flags = ipv6 ? DNS_SETTING_IPV6 : 0;
            settings.Flags |= target.kind == Kind::doh
                ? (target.profile ? DNS_SETTING_DOH_PROFILE : DNS_SETTING_DOH)
                : (target.profile ? DNS_SETTING_DOT_PROFILE : DNS_SETTING_DOT);
            item.Type = target.kind == Kind::doh ? DnsServerDohProperty : DnsServerDotProperty;
            if (target.kind == Kind::doh) item.Property.DohSettings = &doh;
            else item.Property.DotSettings = &dot;
            // NameServer identifies this one property; no NAMESERVER flags are
            // set, so static/DHCP DNS addresses are never replaced.
            if (target.profile) { settings.ProfileNameServer = server.data(); settings.cProfileServerProperties = 1; settings.ProfileServerProperties = &item; }
            else { settings.NameServer = server.data(); settings.cServerProperties = 1; settings.ServerProperties = &item; }
        }
        const auto status = api_->set(guid(target.id), reinterpret_cast<const DNS_INTERFACE_SETTINGS*>(&settings));
        if (status != NO_ERROR) api_error("Cannot update DNS encryption property", status);
        Snapshot after(api_, guid(target.id));
        auto observed = state(after, target.id);
        values[name] = desired;
        if (observed != values || servers(before.value.NameServer) != servers(after.value.NameServer) ||
            servers(before.value.ProfileNameServer) != servers(after.value.ProfileNameServer))
            throw Error("DNS_PREPARATION_VERIFY", "OS DNS readback differs from the requested change; recovery data retained");
    }
    std::vector<PreparedNetworkSetting> load_journal() override {
        const auto bytes = load_();
        return bytes ? parse_network_journal(*bytes) : std::vector<PreparedNetworkSetting>{};
    }
    void save_journal(const std::vector<PreparedNetworkSetting>& settings) override {
        save_(settings.empty() ? std::nullopt : std::optional(serialize_network_journal(settings)));
    }
private:
    std::shared_ptr<detail::InterfaceDnsApi> api_;
    detail::LoadNetworkJournal load_;
    detail::SaveNetworkJournal save_;
};
} // namespace
namespace detail {
std::shared_ptr<InterfaceDnsApi> make_system_dns_api() { return std::make_shared<NativeApi>(); }
std::unique_ptr<NetworkPreparationBackend> make_windows_network_backend(
    std::shared_ptr<InterfaceDnsApi> api, LoadNetworkJournal load, SaveNetworkJournal save) {
    return std::make_unique<WindowsNetworkBackend>(std::move(api), std::move(load), std::move(save));
}
} // namespace detail
std::unique_ptr<NetworkPreparation> make_network_preparation() {
    auto api = detail::make_system_dns_api();
    auto journal = std::make_shared<detail::RecoveryFile>(detail::network_recovery_directory(), "system-dns");
    auto backend = detail::make_windows_network_backend(std::move(api), [journal] { return journal->load(); },
        [journal](const std::optional<std::string>& bytes) { if (bytes) journal->save(*bytes); else journal->clear(); });
    return std::make_unique<NetworkPreparation>(std::move(backend));
}
} // namespace nd::platform
