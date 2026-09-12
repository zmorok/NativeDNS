#include <nativedns/dnscrypt.hpp>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <stdexcept>

namespace {
void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
nd::Packet hex(const std::string& text) {
    std::string clean;
    for (unsigned char c : text) if (!std::isspace(c)) clean.push_back(static_cast<char>(c));
    if (clean.size() % 2) throw std::runtime_error("odd hex fixture");
    nd::Packet result(clean.size() / 2);
    auto digit = [](char c) -> uint8_t { return static_cast<uint8_t>(c <= '9' ? c - '0' : (c | 32) - 'a' + 10); };
    for (size_t i = 0; i < result.size(); ++i) result[i] = static_cast<uint8_t>((digit(clean[i * 2]) << 4) | digit(clean[i * 2 + 1]));
    return result;
}
template<size_t N> std::array<uint8_t, N> array_hex(const std::string& text) {
    const auto bytes = hex(text); if (bytes.size() != N) throw std::runtime_error("fixture size");
    std::array<uint8_t, N> result{}; std::copy(bytes.begin(), bytes.end(), result.begin()); return result;
}
}

int main(int argc, char**) {
    try {
        const auto provider = nd::parse_dnscrypt_provider_key("03:A1:07:BF:F3:CE:10:BE:1D:70:DD:18:E7:4B:C0:99:67:E4:D6:30:9B:A5:0D:5F:1D:DC:86:64:12:55:31:B8");
        const auto certificate = hex(
            "444e5343000200003a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aab"
            "c173a6a49b7a49ca55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c"
            "4659cac45961400c358072d6365880d1aeea329adf9121383851ed21a28e3b75"
            "e965d0d2cd166254b1b2b3b4b5b6b7b8000000016800000068015180");
        const auto selected = nd::select_dnscrypt_certificate({certificate}, provider, 0x68000001);
        check(selected.encryption_system == 2 && selected.serial == 1 && selected.valid_from == 0x68000000 && selected.valid_until == 0x68015180, "certificate fields");
        auto tampered_certificate = certificate; tampered_certificate[80] ^= 1;
        try { (void)nd::select_dnscrypt_certificate({tampered_certificate}, provider, 0x68000001); check(false, "tampered certificate accepted"); }
        catch (const nd::Error& error) { check(error.code == "DNSCRYPT_CERT", "tampered certificate error"); }
        try { (void)nd::select_dnscrypt_certificate({certificate}, provider, 0x68015181); check(false, "expired certificate accepted"); }
        catch (const nd::Error& error) { check(error.code == "DNSCRYPT_CERT", "expired certificate error"); }
        const auto legacy_provider = nd::parse_dnscrypt_provider_key("d12b47f252dcf2c2bbf8991086eaf79ce4495d8b16c8a0c4322e52ca3f390873");
        const auto legacy_certificate = hex(
            "444e534300010000ffa8baa78437f87ca90038278f9050c4901340952d6ab7df"
            "811bfb0e1734d203829181c1a67a2ea2a323728d66a8667d1760e25ee09ad2e7"
            "ccd635457864800fa763b117085192fbf45f15e514cc58580d51d93bbe33623d"
            "20e898123a7b4b5d00000000000000006a9997db6a9997db6c7acb5b");
        const auto legacy = nd::select_dnscrypt_certificate({legacy_certificate}, legacy_provider, 0x6a9f20c4);
        check(legacy.encryption_system == 1 && legacy.serial == 0x6a9997db, "deployed 0x0001 certificate");

        const auto cert_response = hex(
            "abcd8180000100010000000001320d646e7363727970742d6365727407657861"
            "6d706c6503636f6d0000100001c00c0010000100015180007d7c444e53430002"
            "00003a570ea17f47b80217977fbb455840bfd50ab32f5fbf2aabc173a6a49b7a"
            "49ca55362a6c5dec47657cf515e9f99382a316dfecd964b94d1c4659cac45961"
            "400c358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd"
            "166254b1b2b3b4b5b6b7b8000000016800000068015180");
        const auto extracted = nd::extract_dnscrypt_certificates(cert_response);
        check(extracted.size() == 1 && extracted.front() == certificate, "TXT certificate reconstruction");

        const auto client_secret = array_hex<32>("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        const auto client_nonce = array_hex<12>("a0a1a2a3a4a5a6a7a8a9aaab");
        const auto shared = nd::dnscrypt_shared_key(client_secret, selected);
        check(shared == array_hex<32>("335d32f2d65e6623cbbd05b6539c9575fee16cb5405fe839ab4bd291fdf13262"), "shared key vector");
        const auto dns_query = hex("12340100000100000000000003777777076578616d706c6503636f6d0000010001");
        const auto expected_query = hex(
            "b1b2b3b4b5b6b7b879a631eede1bf9c98f12032cdeadd0e7a079398fc786b88c"
            "c846ec89af85a51aa0a1a2a3a4a5a6a7a8a9aaab2dae527c26386d5cd4e61152"
            "db6dd1812ff6aaf7644fc122afc70b1b580b18f10fbc26577abc759152cde31c"
            "d0afc5c5f452f8654815469723300819bed5a12015c044b94d63ec1f79e48a23"
            "968e437feb8bb8720cf4e60a0499746190c8b3eb83aeb0d858df77794270b861"
            "f86644502be0d22d6f0b2b132e9ca68538300c8d68b8e3c48190cbbf96d602f3"
            "8dfc3b4d642016ceeaf4bc2c2ded9483b9f9d4eed703a0bebc252add8822d4b9"
            "152e30670bcde9ea75a0e3e67ea576e9b1262bb2b25b4f9432311b75a2238b34"
            "bf4f868da182b85dccb1762a703bba31d04d77b4c57ec9039663959793677588"
            "b3a74ae409b0f16374dd64cbd6d47d801725b014ce9ddaf6f1aa30688c8efcbf"
            "de1d5d1d");
        check(nd::build_dnscrypt_query(dns_query, selected, client_secret, client_nonce, 324) == expected_query, "encrypted query vector");
        constexpr size_t dnscrypt_overhead=68;
        const auto udp_padded=nd::build_dnscrypt_query(dns_query,selected,client_secret,client_nonce,512);
        check(udp_padded.size()>=512&&(udp_padded.size()-dnscrypt_overhead)%64==0,"DNSCrypt UDP minimum and 64-byte plaintext padding");
        for(const size_t plaintext:{size_t{64},size_t{128},size_t{192},size_t{256}}) {
            const auto padded=nd::build_dnscrypt_query(dns_query,selected,client_secret,client_nonce,dnscrypt_overhead+plaintext);
            const auto padding=plaintext-dns_query.size();check(padded.size()==dnscrypt_overhead+plaintext&&padding>=1&&padding<=256,"DNSCrypt TCP padding candidates");
        }

        const auto encrypted_response = hex(
            "7236666e76576a38a0a1a2a3a4a5a6a7a8a9aaabc0c1c2c3c4c5c6c7c8c9cacb"
            "f2670995c6d37c2f8d2016029dd5970b893de83c02815ece9b48d9fd0b0dca87"
            "41674142fbd8e12c1120b111f366326aa71c89823a2931ac5c860dad49685ed6"
            "cc22cc13e829d2e51d1c00ea64d1d39d");
        const auto dns_response = hex(
            "12348180000100010000000003777777076578616d706c6503636f6d00000100"
            "01c00c0001000100000e1000045db8d822");
        check(nd::open_dnscrypt_response(encrypted_response, shared, client_nonce) == dns_response, "encrypted response vector");
        auto tampered_response = encrypted_response; tampered_response.back() ^= 1;
        try { (void)nd::open_dnscrypt_response(tampered_response, shared, client_nonce); check(false, "tampered response accepted"); }
        catch (const nd::Error& error) { check(error.code == "DNSCRYPT_AUTH", "tampered response error"); }
        auto wrong_nonce = client_nonce; wrong_nonce[0] ^= 1;
        try { (void)nd::open_dnscrypt_response(encrypted_response, shared, wrong_nonce); check(false, "wrong nonce accepted"); }
        catch (const nd::Error& error) { check(error.code == "DNSCRYPT_NONCE", "wrong nonce error"); }
        nd::Config config = nd::default_config();
        nd::Server configured; configured.id = 1; configured.name = "DNSCrypt"; configured.protocol = nd::Protocol::dnscrypt;
        configured.ip = "94.140.14.14"; configured.port = 5443;
        configured.public_key = "d1:2b:47:f2:52:dc:f2:c2:bb:f8:99:10:86:ea:f7:9c:e4:49:5d:8b:16:c8:a0:c4:32:2e:52:ca:3f:39:08:73";
        configured.provider_name = "2.dnscrypt.default.ns1.adguard.com";
        auto anonymous=configured;anonymous.protocol=nd::Protocol::anonymized_dnscrypt;anonymous.ip="192.0.2.2";anonymous.relay="192.0.2.3:444";
        const auto certificate_query=nd::make_query(anonymous.provider_name,16);
        const auto relayed_certificate=nd::build_anonymized_dnscrypt_certificate_packet(certificate_query,anonymous);
        check(relayed_certificate.size()==540&&std::all_of(relayed_certificate.begin(),relayed_certificate.begin()+8,[](uint8_t byte){return byte==0xff;}),"Anonymized certificate relay envelope");
        check(relayed_certificate[20]==0xff&&relayed_certificate[21]==0xff&&relayed_certificate[22]==192&&relayed_certificate[25]==2&&relayed_certificate[26]==0x15&&relayed_certificate[27]==0x43,"Anonymized certificate target endpoint");
        nd::Packet inner(relayed_certificate.begin()+28,relayed_certificate.end());check(nd::parse_question(inner).name==anonymous.provider_name&&nd::client_udp_payload_size(inner)==1232,"Padded certificate DNS query remains parseable");
        config.servers.push_back(configured); config.rules.front().server_id = 1; nd::validate(config);
        config.servers.front().public_key = "00";
        try { nd::validate(config); check(false, "short provider key accepted"); }
        catch (const nd::Error& error) { check(error.code == "DNSCRYPT_KEY", "provider key validation error"); }
        config.servers.front() = configured; config.servers.front().protocol = nd::Protocol::anonymized_dnscrypt;
        config.servers.front().relay = "relay.example:443";
        try { nd::validate(config); check(false, "hostname relay accepted"); }
        catch (const nd::Error& error) { check(error.code == "ENDPOINT", "relay validation error"); }
        config.servers.front()=configured;config.servers.front().allow_direct_certificate_fallback=true;
        try{nd::validate(config);check(false,"direct certificate fallback accepted for non-anonymized server");}
        catch(const nd::Error& error){check(error.code=="CONFIG","direct certificate fallback validation error");}
        if (argc > 1) {
            configured.timeout_ms = 5000;
            const auto direct = nd::test_server(configured);
            std::cout << "direct " << direct.success << " " << direct.rtt_ms << " " << direct.error_code << " " << direct.message << '\n';
            check(direct.success, "live DNSCrypt request failed");
            configured.protocol = nd::Protocol::anonymized_dnscrypt;
            configured.relay = "94.198.41.235:443";
            const auto anonymized = nd::test_server(configured);
            std::cout << "anonymized " << anonymized.success << " " << anonymized.rtt_ms << " " << anonymized.error_code << " " << anonymized.message << '\n';
            check(anonymized.success, "live Anonymized DNSCrypt request failed");
        }
        std::cout << "DNSCrypt official vectors passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
