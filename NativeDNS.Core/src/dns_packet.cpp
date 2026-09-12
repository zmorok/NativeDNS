#include <nativedns/dns.hpp>
#include <nativedns/platform.hpp>
#include <algorithm>
#include <map>
#include <set>
#include <limits>

namespace nd {
namespace {
uint16_t word(std::span<const uint8_t> p, size_t offset) {
    if (offset > p.size() || p.size() - offset < 2) throw Error("DNS_MALFORMED", "Truncated DNS field");
    return static_cast<uint16_t>((p[offset] << 8) | p[offset + 1]);
}
uint32_t dword(std::span<const uint8_t> p,size_t offset) {
    if(offset>p.size()||p.size()-offset<4)throw Error("DNS_MALFORMED","Truncated DNS field");
    return (static_cast<uint32_t>(p[offset])<<24)|(static_cast<uint32_t>(p[offset+1])<<16)|(static_cast<uint32_t>(p[offset+2])<<8)|p[offset+3];
}
void put_dword(Packet& p,size_t offset,uint32_t value){p[offset]=static_cast<uint8_t>(value>>24);p[offset+1]=static_cast<uint8_t>(value>>16);p[offset+2]=static_cast<uint8_t>(value>>8);p[offset+3]=static_cast<uint8_t>(value);}
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
struct EdnsRequest { bool present=false,do_bit=false;uint16_t payload=512; };
EdnsRequest edns_request(std::span<const uint8_t> request,const Question& question) {
    EdnsRequest result;
    const uint32_t answers=word(request,6),authority=word(request,8),additional=word(request,10);
    if(answers+authority+additional>4096)throw Error("DNS_MALFORMED","Too many DNS records");
    size_t at=question.end;
    for(uint32_t index=0;index<answers+authority+additional;++index) {
        const auto owner=name(request,at);
        const auto type=word(request,at),klass=word(request,at+2),length=word(request,at+8);
        if(request.size()-at<10||length>request.size()-(at+10))throw Error("DNS_MALFORMED","Truncated DNS record");
        if(type==41) {
            if(result.present||!owner.empty()||index<answers+authority)throw Error("DNS_MALFORMED","Invalid OPT record");
            result.present=true;result.payload=std::min<uint16_t>(std::max<uint16_t>(klass,512),1232);result.do_bit=(request[at+6]&0x80)!=0;
        }
        at+=10+length;
    }
    if(at!=request.size())throw Error("DNS_MALFORMED","Unexpected bytes after DNS records");
    return result;
}
Packet synthetic_response(const Packet& request,uint16_t rcode,bool zero) {
    if(rcode>15)throw Error("DNS_MALFORMED","DNS response code is out of range");
    const auto question=parse_question(request);if(question.flags&0x8000)throw Error("DNS_MALFORMED","Expected query, not response");
    const auto edns=edns_request(request,question);
    Packet response(request.begin(),request.begin()+static_cast<ptrdiff_t>(question.end));
    const uint16_t flags=static_cast<uint16_t>(0x8080|(question.flags&0x0110)|rcode);
    response[2]=static_cast<uint8_t>(flags>>8);response[3]=static_cast<uint8_t>(flags);
    response[4]=0;response[5]=1;for(size_t index=6;index<12;++index)response[index]=0;
    if(zero&&question.klass==1&&(question.type==1||question.type==28)) {
        response[7]=1;const uint8_t length=question.type==1?4:16;
        const Packet record{0xc0,0x0c,0,static_cast<uint8_t>(question.type),0,1,0,0,0,0,0,length};
        response.insert(response.end(),record.begin(),record.end());response.insert(response.end(),length,0);
    }
    if(edns.present) {
        response[11]=1;
        response.insert(response.end(),{0,0,41,static_cast<uint8_t>(edns.payload>>8),static_cast<uint8_t>(edns.payload),0,0,static_cast<uint8_t>(edns.do_bit?0x80:0),0,0,0});
    }
    return response;
}
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
    return synthetic_response(request,rcode,false);
}
Packet make_block_response(const Packet& request,BlockMode mode) {
    if(mode==BlockMode::silent_drop)throw Error("CONFIG","Silent-drop block mode has no DNS response");
    const uint16_t rcode=mode==BlockMode::nxdomain?3:mode==BlockMode::refused?5:0;
    return synthetic_response(request,rcode,mode==BlockMode::zero_address);
}
uint16_t client_udp_payload_size(std::span<const uint8_t> request) {
    constexpr uint16_t legacy_size=512;
    const auto question=parse_question(request);
    if(question.flags&0x8000) throw Error("DNS_MALFORMED","Expected query, not response");
    const auto edns=edns_request(request,question);
    return edns.present?edns.payload:legacy_size;
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
    constexpr auto no_ttl=std::numeric_limits<uint32_t>::max();
    bool opt_seen = false,requested_answer=false,transaction_signed=false;uint32_t positive_ttl=no_ttl,negative_ttl=no_ttl;
    for (uint32_t i = 0; i < answers + authority + additional; ++i) {
        const auto owner = name(packet, at);
        auto type = word(packet, at), klass = word(packet, at + 2), length = word(packet, at + 8);const uint32_t ttl=dword(packet,at+4);
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
        if(i<answers&&type!=41){positive_ttl=std::min(positive_ttl,ttl);if(type==expected.type&&klass==expected.klass)requested_answer=true;}
        if(type==249||type==250)transaction_signed=true;
        if(type==6&&i>=answers&&i<answers+authority&&klass==expected.klass) {
            size_t soa=data;(void)name(packet,soa);(void)name(packet,soa);
            if(soa>data+length||data+length-soa!=20)throw Error("DNS_MALFORMED","Invalid SOA record length");
            negative_ttl=std::min(negative_ttl,std::min(ttl,dword(packet,soa+16)));
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
    const bool negative=answer.rcode==3||(answer.rcode==0&&!requested_answer&&negative_ttl!=no_ttl);
    const uint32_t ttl=negative?negative_ttl:positive_ttl;
    if(!transaction_signed&&expected.type!=251&&expected.type!=252&&(answer.rcode==0||answer.rcode==3)&&ttl!=no_ttl&&ttl){answer.cacheable=true;answer.cache_ttl=ttl;}
    return answer;
}
Packet age_dns_response(const Packet& response,uint16_t transaction_id,uint32_t elapsed_seconds) {
    auto result=response;const auto question=parse_question(result);if(!(question.flags&0x8000))throw Error("DNS_MALFORMED","Expected cached response");
    result[0]=static_cast<uint8_t>(transaction_id>>8);result[1]=static_cast<uint8_t>(transaction_id);
    const uint32_t records=word(result,6)+word(result,8)+word(result,10);if(records>4096)throw Error("DNS_MALFORMED","Too many DNS records");
    size_t at=question.end;
    for(uint32_t index=0;index<records;++index){(void)name(result,at);const auto type=word(result,at),length=word(result,at+8);if(result.size()-at<10||length>result.size()-(at+10))throw Error("DNS_MALFORMED","Truncated cached record");if(type!=41){const auto ttl=dword(result,at+4);put_dword(result,at+4,ttl>elapsed_seconds?ttl-elapsed_seconds:0);}at+=10+length;}
    if(at!=result.size())throw Error("DNS_MALFORMED","Unexpected bytes after cached response");return result;
}
}
