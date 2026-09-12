#include <nativedns/dns.hpp>
#include <nativedns/platform.hpp>
#include <algorithm>
#include <map>
#include <set>

namespace nd {
namespace {
uint16_t word(std::span<const uint8_t> p, size_t offset) {
    if (offset > p.size() || p.size() - offset < 2) throw Error("DNS_MALFORMED", "Truncated DNS field");
    return static_cast<uint16_t>((p[offset] << 8) | p[offset + 1]);
}
std::string name(std::span<const uint8_t> p, size_t& offset) {
    std::string result;
    size_t at = offset; bool jumped = false; unsigned hops = 0;
    for (;;) {
        if (at >= p.size() || ++hops > 128) throw Error("DNS_MALFORMED", "Invalid DNS name/compression chain");
        uint8_t length = p[at++];
        if ((length & 0xc0) == 0xc0) {
            if (at >= p.size()) throw Error("DNS_MALFORMED", "Truncated compression pointer");
            const auto target = static_cast<size_t>(((length & 0x3f) << 8) | p[at++]);
            if (target >= at - 2 || target < 12) throw Error("DNS_MALFORMED", "Compression pointer must refer to earlier name data");
            if (!jumped) offset = at;
            jumped = true; at = target; continue;
        }
        if (length & 0xc0) throw Error("DNS_MALFORMED", "Unsupported DNS label encoding");
        if (!length) { if (!jumped) offset = at; return result; }
        if (length > p.size() - at) throw Error("DNS_MALFORMED", "Truncated DNS label");
        if (!result.empty()) result += '.';
        for (unsigned i = 0; i < length; ++i) {
            char c = static_cast<char>(p[at++]);
            if (static_cast<unsigned char>(c) <= 32 || static_cast<unsigned char>(c) >= 127 || c == '.')
                throw Error("DNS_MALFORMED", "Non-host label bytes are unsupported");
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            result += c;
        }
        if (result.size() > 253) throw Error("DNS_MALFORMED", "Expanded DNS name is too long");
    }
}
void append_word(Packet& p, uint16_t value) { p.push_back(static_cast<uint8_t>(value >> 8)); p.push_back(static_cast<uint8_t>(value)); }
}
std::string dns_type_name(uint16_t type) {
    switch(type) {
    case 1:return "A";
    case 2:return "NS";
    case 5:return "CNAME";
    case 6:return "SOA";
    case 12:return "PTR";
    case 15:return "MX";
    case 16:return "TXT";
    case 28:return "AAAA";
    case 33:return "SRV";
    case 64:return "SVCB";
    case 65:return "HTTPS";
    case 255:return "ANY";
    default:return "TYPE"+std::to_string(type);
    }
}
Packet make_query(const std::string& hostname, uint16_t type) {
    auto host = normalize_dns_name(hostname);
    const uint16_t id = platform::secure_random_u16();
    Packet result;
    append_word(result, id); append_word(result, 0x0100); append_word(result, 1);
    append_word(result, 0); append_word(result, 0); append_word(result, 0);
    size_t at = 0;
    while (at < host.size()) {
        const auto end = host.find('.', at); const auto count = end == std::string::npos ? host.size() - at : end - at;
        result.push_back(static_cast<uint8_t>(count));
        result.insert(result.end(), host.begin() + static_cast<ptrdiff_t>(at), host.begin() + static_cast<ptrdiff_t>(at + count));
        if (end == std::string::npos) break;
        at = end + 1;
    }
    result.push_back(0); append_word(result, type); append_word(result, 1);
    return result;
}

Packet make_error_response(const Packet& request,uint16_t rcode) {
    if(rcode>15) throw Error("DNS_MALFORMED","DNS response code is out of range");
    const auto question=parse_question(request);
    if(question.flags&0x8000) throw Error("DNS_MALFORMED","Expected query, not response");
    Packet response(request.begin(),request.begin()+static_cast<ptrdiff_t>(question.end));
    const uint16_t flags=static_cast<uint16_t>(0x8080|(question.flags&0x7910)|rcode);
    response[2]=static_cast<uint8_t>(flags>>8);response[3]=static_cast<uint8_t>(flags);
    response[4]=0;response[5]=1;
    for(size_t i=6;i<12;++i) response[i]=0;
    return response;
}
uint16_t client_udp_payload_size(std::span<const uint8_t> request) {
    constexpr uint16_t legacy_size=512,server_limit=1232;
    const auto question=parse_question(request);
    if(question.flags&0x8000) throw Error("DNS_MALFORMED","Expected query, not response");
    const uint32_t answers=word(request,6),authority=word(request,8),additional=word(request,10);
    if(answers+authority+additional>4096) throw Error("DNS_MALFORMED","Too many DNS records");
    size_t at=question.end;bool opt_seen=false;uint16_t advertised=legacy_size;
    for(uint32_t i=0;i<answers+authority+additional;++i) {
        const auto owner=name(request,at);
        const auto type=word(request,at),klass=word(request,at+2),length=word(request,at+8);
        if(request.size()-at<10||length>request.size()-(at+10)) throw Error("DNS_MALFORMED","Truncated DNS record");
        if(type==41) {
            if(opt_seen||!owner.empty()||i<answers+authority) throw Error("DNS_MALFORMED","Invalid OPT record");
            opt_seen=true;advertised=std::max<uint16_t>(legacy_size,klass);
        }
        at+=10+length;
    }
    if(at!=request.size()) throw Error("DNS_MALFORMED","Unexpected bytes after DNS records");
    return std::min<uint16_t>(advertised,server_limit);
}
Packet fit_udp_response(const Packet& request,const Packet& response) {
    const auto limit=client_udp_payload_size(request);
    if(response.size()<=limit) return response;
    const auto expected=parse_question(request),actual=parse_question(response);
    if(!(actual.flags&0x8000)||actual.id!=expected.id||actual.name!=expected.name||actual.type!=expected.type||actual.klass!=expected.klass)
        throw Error("DNS_MISMATCH","DNS response does not match request");
    Packet truncated(response.begin(),response.begin()+static_cast<ptrdiff_t>(actual.end));
    const uint16_t flags=static_cast<uint16_t>(word(response,2)|0x0200);
    truncated[2]=static_cast<uint8_t>(flags>>8);truncated[3]=static_cast<uint8_t>(flags);
    truncated[4]=0;truncated[5]=1;
    for(size_t i=6;i<12;++i) truncated[i]=0;
    return truncated;
}
Question parse_question(std::span<const uint8_t> packet) {
    if (packet.size() < 12 || packet.size() > 65535 || word(packet, 4) != 1) throw Error("DNS_MALFORMED", "Expected one DNS question and bounded header");
    Question q; q.id = word(packet, 0); q.flags = word(packet, 2);
    if (q.flags & 0x7800) throw Error("DNS_OPCODE", "Only standard DNS queries are supported");
    q.end = 12; q.name = name(packet, q.end); q.type = word(packet, q.end); q.klass = word(packet, q.end + 2); q.end += 4;
    return q;
}
DnsAnswer parse_response(std::span<const uint8_t> packet, const Question& expected) {
    const auto q = parse_question(packet);
    if (!(q.flags & 0x8000) || q.id != expected.id || q.name != expected.name || q.type != expected.type || q.klass != expected.klass)
        throw Error("DNS_MISMATCH", "DNS response does not match request");
    DnsAnswer answer;
    answer.rcode = q.flags & 15; answer.truncated = (q.flags & 0x0200) != 0; answer.authenticated_data = (q.flags & 0x0020) != 0;
    if (answer.truncated) return answer; // caller retries TCP; incomplete tail allowed only for TC
    struct Address { std::string owner, value; };
    std::vector<Address> addresses;
    std::map<std::string, std::string> aliases;
    size_t at = q.end;
    const uint32_t answers = word(packet, 6), authority = word(packet, 8), additional = word(packet, 10);
    if (answers + authority + additional > 4096) throw Error("DNS_MALFORMED", "Too many DNS records");
    bool opt_seen = false;
    for (uint32_t i = 0; i < answers + authority + additional; ++i) {
        const auto owner = name(packet, at);
        auto type = word(packet, at), klass = word(packet, at + 2), length = word(packet, at + 8);
        if (packet.size() - at < 10) throw Error("DNS_MALFORMED", "Short DNS record header");
        const size_t data = at + 10;
        if (length > packet.size() - data) throw Error("DNS_MALFORMED", "Short DNS record data");
        if ((type == 1 && length != 4) || (type == 28 && length != 16)) throw Error("DNS_MALFORMED", "Invalid address record length");
        if ((type == 1 || type == 28) && klass == 1 && i < answers && type == expected.type) {
            addresses.push_back({owner, platform::format_ip(packet.data() + data, type == 28)});
        } else if (type == 5 || type == 2 || type == 12) {
            size_t next = data; auto target = name(packet, next);
            if (next != data + length) throw Error("DNS_MALFORMED", "Invalid name record length");
            if (type == 5 && klass == 1 && i < answers) aliases[owner] = target;
        } else if (type == 41) {
            if (opt_seen || !owner.empty() || i < answers + authority) throw Error("DNS_MALFORMED", "Invalid OPT record");
            opt_seen = true; answer.rcode = static_cast<uint16_t>(answer.rcode | (packet[at + 4] << 4));
        }
        at = data + length;
    }
    if (at != packet.size()) throw Error("DNS_MALFORMED", "Unexpected bytes after DNS records");
    std::set<std::string> reachable{expected.name};
    auto current = expected.name;
    for (size_t i = 0; i <= aliases.size(); ++i) {
        const auto it = aliases.find(current); if (it == aliases.end()) break;
        current = it->second;
        if (!reachable.insert(current).second) throw Error("DNS_MALFORMED", "CNAME cycle");
    }
    for (const auto& address : addresses) if (reachable.contains(address.owner)) answer.addresses.push_back(address.value);
    return answer;
}
}
