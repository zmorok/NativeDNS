#include <nativedns/config.hpp>
#include <nativedns/platform.hpp>
#include <charconv>
#include <fstream>
#include <set>
#include <sstream>
#include <random>
#include <cctype>

namespace nd {
namespace {
struct Node { std::string name; std::map<std::string,std::string> attrs; std::vector<Node> children; };

std::string decode_entity(const std::string& entity) {
    if(entity=="amp") return "&";
    if(entity=="lt") return "<";
    if(entity=="gt") return ">";
    if(entity=="quot") return "\"";
    if(entity=="apos") return "'";
    if(entity.size()>1&&entity[0]=='#') {
        uint32_t value=0; int base=10; size_t at=1;
        if(at<entity.size()&&(entity[at]=='x'||entity[at]=='X')) { base=16; ++at; }
        if(at==entity.size()) throw Error("XML","Empty numeric entity");
        for(;at<entity.size();++at) {
            const char c=entity[at]; unsigned digit=0;
            if(c>='0'&&c<='9') digit=static_cast<unsigned>(c-'0');
            else if(base==16&&c>='a'&&c<='f') digit=10u+static_cast<unsigned>(c-'a');
            else if(base==16&&c>='A'&&c<='F') digit=10u+static_cast<unsigned>(c-'A');
            else throw Error("XML","Invalid numeric entity");
            if(digit>=static_cast<unsigned>(base)||value>(0x10FFFFu-digit)/static_cast<unsigned>(base)) throw Error("XML","Numeric entity overflow");
            value=value*static_cast<unsigned>(base)+digit;
        }
        if(value==0||value>0x10FFFF||(value>=0xD800&&value<=0xDFFF)) throw Error("XML","Invalid Unicode entity");
        std::string out;
        if(value<=0x7F) out.push_back(static_cast<char>(value));
        else if(value<=0x7FF) { out.push_back(static_cast<char>(0xC0|(value>>6))); out.push_back(static_cast<char>(0x80|(value&63))); }
        else if(value<=0xFFFF) { out.push_back(static_cast<char>(0xE0|(value>>12))); out.push_back(static_cast<char>(0x80|((value>>6)&63))); out.push_back(static_cast<char>(0x80|(value&63))); }
        else { out.push_back(static_cast<char>(0xF0|(value>>18))); out.push_back(static_cast<char>(0x80|((value>>12)&63))); out.push_back(static_cast<char>(0x80|((value>>6)&63))); out.push_back(static_cast<char>(0x80|(value&63))); }
        return out;
    }
    throw Error("XML","Unknown XML entity: "+entity);
}

class XmlParser {
public:
    explicit XmlParser(std::string text):text_(std::move(text)) {}
    Node parse() {
        if(text_.size()>4*1024*1024) throw Error("CONFIG_IO","Config exceeds 4 MiB");
        if(text_.size()>=3&&static_cast<unsigned char>(text_[0])==0xEF&&static_cast<unsigned char>(text_[1])==0xBB&&static_cast<unsigned char>(text_[2])==0xBF) pos_=3;
        skip_misc(); Node root=parse_element(0); skip_misc(); skip_ws(); if(pos_!=text_.size()) throw Error("XML","Unexpected data after root element"); return root;
    }
private:
    std::string text_; size_t pos_=0; size_t nodes_=0;
    bool starts(const char* token) const { return text_.compare(pos_,std::char_traits<char>::length(token),token)==0; }
    void skip_ws(){ while(pos_<text_.size()&&std::isspace(static_cast<unsigned char>(text_[pos_]))) ++pos_; }
    void skip_until(const char* token){ const auto end=text_.find(token,pos_); if(end==std::string::npos) throw Error("XML","Unterminated XML section"); pos_=end+std::char_traits<char>::length(token); }
    void skip_misc(){
        for(;;){ skip_ws(); if(starts("<?")) { pos_+=2; skip_until("?>"); continue; } if(starts("<!--")) { pos_+=4; skip_until("-->"); continue; } if(starts("<!DOCTYPE")||starts("<!ENTITY")) throw Error("XML","DTD/entity declarations are prohibited"); break; }
    }
    std::string name(){
        const size_t begin=pos_; while(pos_<text_.size()) { const unsigned char c=static_cast<unsigned char>(text_[pos_]); if(std::isalnum(c)||c=='_'||c=='-'||c=='.') ++pos_; else break; }
        if(begin==pos_) throw Error("XML","Expected XML name");
        return text_.substr(begin,pos_-begin);
    }
    std::string quoted(){
        if(pos_>=text_.size()||(text_[pos_]!='\"'&&text_[pos_]!='\'')) throw Error("XML","Expected quoted attribute");
        const char quote=text_[pos_++];
        std::string out;
        while(pos_<text_.size()&&text_[pos_]!=quote) {
            if(text_[pos_]=='&') { const auto end=text_.find(';',pos_+1); if(end==std::string::npos) throw Error("XML","Unterminated XML entity"); out+=decode_entity(text_.substr(pos_+1,end-pos_-1)); pos_=end+1; }
            else { const unsigned char c=static_cast<unsigned char>(text_[pos_++]); if(c<0x20&&c!='\t'&&c!='\r'&&c!='\n') throw Error("XML","Control character in XML"); out.push_back(static_cast<char>(c)); }
        }
        if(pos_>=text_.size()) throw Error("XML","Unterminated attribute");
        ++pos_;
        return out;
    }
    Node parse_element(unsigned depth) {
        if(depth>16) throw Error("XML_LIMIT","XML nesting is too deep");
        if(++nodes_>200000) throw Error("XML_LIMIT","Too many XML nodes");
        skip_ws(); if(pos_>=text_.size()||text_[pos_]!='<'||starts("</")) throw Error("XML","Expected element"); ++pos_;
        if(pos_<text_.size()&&(text_[pos_]=='!'||text_[pos_]=='?')) throw Error("XML","Unexpected XML declaration");
        Node node; node.name=name();
        for(;;){ skip_ws(); if(starts("/>")){pos_+=2;return node;} if(pos_<text_.size()&&text_[pos_]=='>'){++pos_;break;} auto key=name(); skip_ws(); if(pos_>=text_.size()||text_[pos_]!='=') throw Error("XML","Expected '=' after attribute"); ++pos_; skip_ws(); auto value=quoted(); if(!node.attrs.emplace(std::move(key),std::move(value)).second) throw Error("XML","Duplicate attribute"); }
        for(;;){
            skip_ws(); if(starts("</")){pos_+=2;const auto close=name();skip_ws();if(pos_>=text_.size()||text_[pos_]!='>') throw Error("XML","Malformed closing tag");++pos_;if(close!=node.name) throw Error("XML","Mismatched closing tag");return node;}
            if(starts("<!--")){pos_+=4;skip_until("-->");continue;}
            if(starts("<![CDATA[")){ throw Error("XML","CDATA is unsupported in NativeDNS configuration"); }
            if(pos_<text_.size()&&text_[pos_]=='<') { node.children.push_back(parse_element(depth+1)); continue; }
            const auto next=text_.find('<',pos_); const auto end=next==std::string::npos?text_.size():next; for(size_t i=pos_;i<end;++i) if(!std::isspace(static_cast<unsigned char>(text_[i]))) throw Error("XML","Unexpected text content"); pos_=end; if(pos_==text_.size()) throw Error("XML","Unterminated element");
        }
    }
};
Node read_xml(const std::filesystem::path& path) {
    std::error_code ec; const auto size=std::filesystem::file_size(path,ec); if(ec||size>4*1024*1024) throw Error("CONFIG_IO","Cannot read config or config exceeds 4 MiB");
    std::ifstream in(path,std::ios::binary); if(!in) throw Error("CONFIG_IO","Cannot open configuration"); std::string text(static_cast<size_t>(size),'\0'); in.read(text.data(),static_cast<std::streamsize>(text.size())); if(!in&& !text.empty()) throw Error("CONFIG_IO","Cannot read configuration"); return XmlParser(std::move(text)).parse();
}
std::string attr(const Node& node, const std::string& key, const std::string& fallback = "") {
    const auto it = node.attrs.find(key); return it == node.attrs.end() ? fallback : it->second;
}
uint32_t number(const std::string& text) {
    uint32_t result = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || end != text.data() + text.size()) throw Error("CONFIG_NUMBER", "Invalid unsigned integer: " + text);
    return result;
}
uint32_t num(const Node& node, const std::string& key, uint32_t fallback) { return number(attr(node, key, std::to_string(fallback))); }
bool flag(const Node& node, const std::string& key, bool fallback) {
    auto value = attr(node, key, fallback ? "1" : "0");
    if (value != "0" && value != "1") throw Error("CONFIG_BOOL", "Invalid boolean: " + key);
    return value == "1";
}
Protocol protocol(const std::string& name) {
    for (auto p : {Protocol::udp, Protocol::tcp, Protocol::doh, Protocol::dot, Protocol::doh3, Protocol::doq, Protocol::dnscrypt, Protocol::anonymized_dnscrypt})
        if (name == protocol_name(p)) return p;
    if (name == "plain") return Protocol::udp;
    throw Error("PROTOCOL", "Unsupported protocol in config: " + name);
}
Action action(const std::string& name) {
    if (name == "process" || name == "process_server") return Action::process;
    if (name == "bypass") return Action::bypass;
    if (name == "block") return Action::block;
    throw Error("ACTION", "Unsupported action: " + name);
}
void known(const Node& node, std::initializer_list<const char*> keys) {
    for (const auto& [key, value] : node.attrs) {
        (void)value;
        bool found = false;
        for (auto allowed : keys) if (key == allowed) found = true;
        if (!found) throw Error("CONFIG_FIELD", "Unknown field " + node.name + "/" + key);
    }
}
std::string escape(const std::string& value) {
    (void)widen(value);
    std::string out;
    for (unsigned char c : value) {
        switch (c) {
        case '&': out += "&amp;"; break; case '<': out += "&lt;"; break; case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break; case '\n': out += "&#10;"; break; case '\r': out += "&#13;"; break; case '\t': out += "&#9;"; break;
        default: if (c < 32) throw Error("XML", "Control character cannot be serialized"); out += static_cast<char>(c);
        }
    }
    return out;
}
std::string field(const std::string& name, const std::string& value) { return " " + name + "=\"" + escape(value) + "\""; }
std::string field(const std::string& name, uint32_t value) { return field(name, std::to_string(value)); }
std::string join(const std::vector<std::string>& values) { std::string out; for (const auto& value : values) { if (!out.empty()) out += ';'; out += value; } return out; }
std::vector<std::string> split(const std::string& text) {
    std::vector<std::string> out; std::istringstream stream(text); std::string value;
    while (std::getline(stream, value, ';')) if (!value.empty()) out.push_back(value);
    return out;
}
std::string join_ids(const std::vector<uint32_t>& values) { std::string out;for(const auto value:values){if(!out.empty())out+=';';out+=std::to_string(value);}return out; }
std::vector<uint32_t> split_ids(const std::string& text) { std::vector<uint32_t> out;for(const auto& value:split(text))out.push_back(number(value));return out; }
void metadata(std::ostringstream& out, const std::map<std::string, std::string>& values) {
    for (const auto& [key, value] : values) out << "    <Meta" << field("key", key) << field("value", value) << "/>\n";
}
std::map<std::string, std::string> read_metadata(const Node& node) {
    std::map<std::string, std::string> result;
    for (const auto& item : node.children) {
        if (item.name != "Meta" || !item.children.empty()) throw Error("CONFIG_FIELD", "Unexpected child of " + node.name);
        known(item, {"key", "value"});
        if (!result.emplace(attr(item, "key"), attr(item, "value")).second) throw Error("CONFIG_FIELD", "Duplicate metadata key");
    }
    return result;
}
}
ImportResult import_yoga(const std::filesystem::path& path) {
    const auto root = read_xml(path);
    if (root.name != "YogaDnsProfile" || attr(root, "file_format") != "1") throw Error("YOGA_FORMAT", "Unsupported YogaDNS profile");
    ImportResult result;
    for (const auto& [key, value] : root.attrs) result.config.settings["yoga.root." + key] = value;
    uint32_t rule_id = 1;
    for (const auto& node : root.children) {
        if (node.name == "Settings") {
            for (const auto& [key, value] : node.attrs) {
                result.config.settings["yoga.settings." + key] = value;
                result.warnings.push_back("Preserved Yoga setting pending runtime support: " + key);
            }
            for (const auto& child : node.children) {
                if (child.name != "DnsChecker" || !child.children.empty()) throw Error("YOGA_FIELD", "Unsupported Settings child: " + child.name);
                result.config.test_target = attr(child, "testTarget", "iana.org");
                result.config.test_concurrency = num(child, "testsPerTime", 15);
                for (const auto& [key, value] : child.attrs) {
                    result.config.settings["yoga.checker." + key] = value;
                    if (key != "testTarget" && key != "testsPerTime") result.warnings.push_back("Preserved checker field: " + key);
                }
            }
        } else if (node.name == "DnsServer") {
            if (!node.children.empty()) throw Error("YOGA_FIELD", "Unexpected server children");
            Server server;
            server.id = num(node, "id", 0); server.name = attr(node, "name");
            server.protocol = protocol(attr(node, "protocol")); server.ip = attr(node, "ip");
            server.enabled = flag(node, "enabled", true); server.dnssec_supported = flag(node, "dnssec_supported", false);
            const auto port = num(node, "port", 0);
            if (port > 65535) throw Error("ENDPOINT", "Port out of range");
            server.port = static_cast<uint16_t>(port);
            if (server.protocol == Protocol::doh || server.protocol == Protocol::doh3) {
                server.hostname = attr(node, "doh_host_name");
                server.url = "https://" + server.hostname + (port ? ":" + std::to_string(port) : "") + attr(node, "doh_path", "/dns-query");
            } else if (server.protocol == Protocol::dot) server.hostname = attr(node, "dot_host_name");
            server.metadata = node.attrs;
            const std::set<std::string> mapped{"id","name","protocol","ip","af","port","enabled","dnssec_supported","dot_host_name","doh_host_name","doh_path"};
            for (const auto& [key, value] : node.attrs) { (void)value; if (!mapped.contains(key)) result.warnings.push_back("Unmapped server field retained: " + key); }
            result.config.servers.push_back(std::move(server));
        } else if (node.name == "Rule") {
            if (!node.children.empty()) throw Error("YOGA_FIELD", "Unexpected rule children");
            Rule rule; rule.id = rule_id++; rule.name = attr(node, "name");
            rule.enabled = flag(node, "enabled", true); rule.patterns = split_patterns(attr(node, "hostnames"));
            rule.is_default = rule.name == "Default";
            rule.action = action(attr(node, "action"));
            const uint32_t target = num(node, "action_id", 0);
            rule.server_id = rule.action == Action::process ? target : 0;
            if (rule.action != Action::process && target) result.warnings.push_back("Inactive action_id preserved in rule metadata: " + rule.name);
            rule.interface_id = attr(node, "interface_id");
            rule.dnssec_validate = flag(node, "dnssec_local_validation", false);
            rule.dnssec_reject_unsigned = flag(node, "dnssec_reject_unsigned", false);
            if (!rule.interface_id.empty() || rule.dnssec_validate || rule.dnssec_reject_unsigned)
                result.warnings.push_back("Rule needs runtime capability validation: " + rule.name);
            rule.metadata = node.attrs;
            const std::set<std::string> mapped{"name","enabled","hostnames","action","action_id","interface_id","interface_id_type","interface_name","dnssec_local_validation","dnssec_reject_unsigned"};
            for (const auto& [key, value] : node.attrs) { (void)value; if (!mapped.contains(key)) result.warnings.push_back("Unmapped rule field retained: " + key); }
            result.config.rules.push_back(std::move(rule));
        } else throw Error("YOGA_FIELD", "Unsupported Yoga element: " + node.name);
    }
    bool has_default = false;
    for (const auto& rule : result.config.rules) if (rule.is_default) has_default = true;
    if (!has_default) {
        Rule rule = default_config().rules.front(); rule.id = rule_id;
        result.config.rules.push_back(rule); result.warnings.push_back("Missing Default added as Process/original destination");
    }
    validate(result.config);
    return result;
}
std::string serialize_config(const Config& config) {
    validate(config);
    std::ostringstream out;
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<NativeDNS schemaVersion=\"1\""
        << field("testTarget", config.test_target) << field("testConcurrency", config.test_concurrency) << ">\n";
    out << "  <Settings>\n"; metadata(out, config.settings); out << "  </Settings>\n";
    out << "  <Logging" << field("screen", static_cast<uint32_t>(config.logging.screen)) << field("file", static_cast<uint32_t>(config.logging.file))
        << field("enabled", config.logging.file_enabled) << field("directory", config.logging.directory) << "/>\n";
    for (const auto& s : config.servers) {
        out << "  <Server" << field("id", s.id) << field("name", s.name) << field("enabled", s.enabled) << field("protocol", protocol_name(s.protocol))
            << field("ip", s.ip) << field("port", s.port) << field("hostname", s.hostname) << field("url", s.url)
            << field("dnssec", s.dnssec_supported) << field("timeout", s.timeout_ms) << field("fallbacks", join_ids(s.fallback_ids)) << field("bootstrap", join(s.bootstrap))
            << field("hashes", join(s.hashes)) << field("publicKey", s.public_key) << field("provider", s.provider_name) << field("relay", s.relay) << ">\n";
        metadata(out, s.metadata); out << "  </Server>\n";
    }
    for (const auto& r : config.rules) {
        out << "  <Rule" << field("id", r.id) << field("name", r.name) << field("enabled", r.enabled) << field("default", r.is_default)
            << field("patterns", join(r.patterns)) << field("action", action_name(r.action)) << field("server", r.server_id)
            << field("interface", r.interface_id) << field("validate", r.dnssec_validate) << field("rejectUnsigned", r.dnssec_reject_unsigned)
            << field("blockMode", static_cast<uint32_t>(r.block_mode)) << ">\n";
        metadata(out, r.metadata); out << "  </Rule>\n";
    }
    out << "</NativeDNS>\n";
    auto result = out.str();
    if (result.size() > 4 * 1024 * 1024) throw Error("CONFIG_LIMIT", "Serialized config exceeds 4 MiB");
    return result;
}
Config load_config(const std::filesystem::path& path) {
    const auto root = read_xml(path);
    if (root.name != "NativeDNS") throw Error("CONFIG", "Expected NativeDNS root");
    known(root, {"schemaVersion","testTarget","testConcurrency"});
    Config config;
    config.schema_version = num(root, "schemaVersion", 0);
    config.test_target = attr(root, "testTarget", "iana.org"); config.test_concurrency = num(root, "testConcurrency", 15);
    bool saw_settings = false, saw_logging = false;
    for (const auto& node : root.children) {
        if (node.name == "Settings") {
            known(node, {});
            if (saw_settings) throw Error("CONFIG", "Duplicate Settings");
            saw_settings = true; config.settings = read_metadata(node);
        } else if (node.name == "Logging") {
            if (saw_logging || !node.children.empty()) throw Error("CONFIG", "Invalid Logging element");
            saw_logging = true; known(node, {"screen","file","enabled","directory"});
            config.logging.screen = static_cast<Level>(num(node, "screen", 1));
            config.logging.file = static_cast<Level>(num(node, "file", 1));
            config.logging.file_enabled = flag(node, "enabled", true); config.logging.directory = attr(node, "directory", "logs");
        } else if (node.name == "Server") {
            known(node, {"id","name","enabled","protocol","ip","port","hostname","url","dnssec","timeout","fallbacks","bootstrap","hashes","publicKey","provider","relay"});
            Server s;
            s.id = num(node, "id", 0); s.name = attr(node, "name"); s.enabled = flag(node, "enabled", true);
            s.protocol = protocol(attr(node, "protocol")); s.ip = attr(node, "ip");
            const auto port = num(node, "port", 0); if (port > 65535) throw Error("ENDPOINT", "Port out of range");
            s.port = static_cast<uint16_t>(port); s.hostname = attr(node, "hostname"); s.url = attr(node, "url");
            s.dnssec_supported = flag(node, "dnssec", false); s.timeout_ms = num(node, "timeout", 3000);s.fallback_ids=split_ids(attr(node,"fallbacks"));
            s.bootstrap = split(attr(node, "bootstrap")); s.hashes = split(attr(node, "hashes"));
            s.public_key = attr(node, "publicKey"); s.provider_name = attr(node, "provider"); s.relay = attr(node, "relay");
            s.metadata = read_metadata(node); config.servers.push_back(std::move(s));
        } else if (node.name == "Rule") {
            known(node, {"id","name","enabled","default","patterns","action","server","interface","validate","rejectUnsigned","blockMode"});
            Rule r;
            r.id = num(node, "id", 0); r.name = attr(node, "name"); r.enabled = flag(node, "enabled", true); r.is_default = flag(node, "default", false);
            r.patterns = split(attr(node, "patterns")); r.action = action(attr(node, "action")); r.server_id = num(node, "server", 0);
            r.interface_id = attr(node, "interface"); r.dnssec_validate = flag(node, "validate", false); r.dnssec_reject_unsigned = flag(node, "rejectUnsigned", false);
            r.block_mode = static_cast<BlockMode>(num(node, "blockMode", 0)); r.metadata = read_metadata(node);
            config.rules.push_back(std::move(r));
        } else throw Error("CONFIG_FIELD", "Unknown element: " + node.name);
    }
    validate(config); return config;
}
void save_config(const Config& config,const std::filesystem::path& path) {
    const auto data=serialize_config(config);
    if(std::filesystem::exists(path)) (void)load_config(path);
    const auto parent=path.parent_path(); if(!parent.empty()) std::filesystem::create_directories(parent);
    auto temp=path; temp += "."+std::to_string(platform::secure_random_u32())+".tmp";
    auto backup=path; backup += ".bak";
    try {
        { std::ofstream out(temp,std::ios::binary|std::ios::trunc); if(!out) throw Error("CONFIG_IO","Cannot create sibling temporary config"); out.write(data.data(),static_cast<std::streamsize>(data.size())); out.flush(); if(!out) throw Error("CONFIG_IO","Cannot write/flush configuration"); }
        (void)load_config(temp);
        platform::atomic_publish_file(temp,path,backup);
    } catch(...) { std::error_code ec; std::filesystem::remove(temp,ec); throw; }
}
}
