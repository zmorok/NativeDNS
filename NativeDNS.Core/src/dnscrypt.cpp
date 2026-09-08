#include <nativedns/dnscrypt.hpp>
#include <nativedns/dns_network.hpp>
#include <sodium.h>
#include <nativedns/platform.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <charconv>
#include <cstring>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace nd {
namespace {
constexpr std::array<uint8_t, 4> cert_magic{'D','N','S','C'};
constexpr std::array<uint8_t, 8> resolver_magic{'r','6','f','n','v','W','j','8'};
constexpr size_t classical_certificate_size = 124;
constexpr size_t query_overhead = 8 + 32 + 12 + crypto_box_curve25519xchacha20poly1305_MACBYTES;

void sodium_ready() {
    static const bool initialized = [] {
        if (sodium_init() < 0) throw Error("CRYPTO_INIT", "libsodium initialization failed");
        return true;
    }();
    (void)initialized;
}
uint16_t be16(std::span<const uint8_t> bytes, size_t at) {
    if (at + 2 > bytes.size()) throw Error("DNS_MALFORMED", "Truncated DNS field");
    return static_cast<uint16_t>((bytes[at] << 8) | bytes[at + 1]);
}
uint32_t be32(std::span<const uint8_t> bytes, size_t at) {
    if (at + 4 > bytes.size()) throw Error("DNSCRYPT_CERT", "Truncated DNSCrypt certificate");
    return (static_cast<uint32_t>(bytes[at]) << 24) | (static_cast<uint32_t>(bytes[at + 1]) << 16) |
           (static_cast<uint32_t>(bytes[at + 2]) << 8) | bytes[at + 3];
}
size_t skip_name(std::span<const uint8_t> packet, size_t at) {
    for (size_t labels = 0; labels <= 127; ++labels) {
        if (at >= packet.size()) throw Error("DNS_MALFORMED", "Truncated DNS name");
        const uint8_t length = packet[at++];
        if ((length & 0xc0) == 0xc0) {
            if (at >= packet.size()) throw Error("DNS_MALFORMED", "Truncated DNS compression pointer");
            const size_t pointer = static_cast<size_t>((length & 0x3f) << 8) | packet[at];
            if (pointer < 12 || pointer >= at - 1) throw Error("DNS_MALFORMED", "Invalid DNS compression pointer");
            return at + 1;
        }
        if (length & 0xc0) throw Error("DNS_MALFORMED", "Invalid DNS label encoding");
        if (!length) return at;
        if (length > 63 || at + length > packet.size()) throw Error("DNS_MALFORMED", "Invalid DNS label length");
        at += length;
    }
    throw Error("DNS_MALFORMED", "Too many DNS labels");
}
bool retryable(const Error& error) {
    return error.code == "TIMEOUT" || error.code == "SOCKET" || error.code == "DNS_EOF";
}
Server endpoint(const Server& server) {
    Server result = server;
    result.protocol = Protocol::udp;
    if (!result.port) result.port = 443;
    return result;
}
Server relay_endpoint(const Server& server) {
    Server relay;
    relay.enabled = true;
    relay.protocol = Protocol::udp;
    relay.timeout_ms = server.timeout_ms;
    relay.port = 443;
    auto value = server.relay;
    const auto parse_port = [](const std::string& text) {
        uint32_t port = 0;
        const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
        if (error != std::errc{} || end != text.data() + text.size() || !port || port > 65535)
            throw Error("ENDPOINT", "Invalid relay port");
        return static_cast<uint16_t>(port);
    };
    if (value.empty()) throw Error("ENDPOINT", "Anonymized DNSCrypt requires a relay endpoint");
    if (value.front() == '[') {
        const auto close = value.find(']');
        if (close == std::string::npos) throw Error("ENDPOINT", "Invalid relay IPv6 endpoint");
        relay.ip = value.substr(1, close - 1);
        if (close + 1 < value.size()) {
            if (value[close + 1] != ':') throw Error("ENDPOINT", "Invalid relay endpoint");
            relay.port = parse_port(value.substr(close + 2));
        }
    } else {
        const auto colon = value.rfind(':');
        if (colon != std::string::npos && value.find(':') == colon) {
            relay.port = parse_port(value.substr(colon + 1));
            relay.ip = value.substr(0, colon);
        } else relay.ip = std::move(value);
    }
    if (!platform::is_numeric_ip(relay.ip))
        throw Error("ENDPOINT", "DNSCrypt relay requires a numeric IP");
    return relay;
}
Packet anonymize(const Packet& encrypted, const Server& server) {
    static constexpr uint8_t magic[10]{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0,0};
    Packet result(std::begin(magic), std::end(magic));
    std::array<uint8_t, 16> address{}; bool ipv6=false;
    if (!platform::parse_ip(server.ip,address,ipv6)) throw Error("ENDPOINT", "Anonymized DNSCrypt target requires a numeric IP");
    if (!ipv6) { address[10]=0xff; address[11]=0xff; }
    result.insert(result.end(), address.begin(), address.end());
    const uint16_t port = server.port ? server.port : 443;
    result.push_back(static_cast<uint8_t>(port >> 8)); result.push_back(static_cast<uint8_t>(port));
    result.insert(result.end(), encrypted.begin(), encrypted.end());
    return result;
}
std::vector<Packet> fetch_certificates(const Server& server, const Packet& request, const Question& question,
                                       detail::NetworkClock::time_point deadline) {
    auto target = endpoint(server);
    Packet response;
    try { response = detail::exchange_network(request, target, false, deadline); }
    catch (const Error& error) { if (!retryable(error)) throw; response = detail::exchange_network(request, target, true, deadline); }
    auto parsed = parse_response(response, question);
    if (parsed.truncated) {
        response = detail::exchange_network(request, target, true, deadline);
        parsed = parse_response(response, question);
    }
    if (parsed.rcode) throw Error("DNSCRYPT_CERT", "Certificate lookup failed with RCODE " + std::to_string(parsed.rcode));
    return extract_dnscrypt_certificates(response);
}
DnsCryptCertificate load_certificate(const Server& server, detail::NetworkClock::time_point deadline) {
    struct Entry { DnsCryptCertificate certificate; uint64_t refresh_at = 0; };
    static std::mutex mutex;
    static std::unordered_map<std::string, Entry> cache;
    const uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    const std::string key = server.ip + ":" + std::to_string(server.port ? server.port : 443) + "|" +
                            server.provider_name + "|" + server.public_key;
    std::optional<Entry> current;
    {
        const std::lock_guard lock(mutex);
        const auto found = cache.find(key);
        if (found != cache.end() && now <= found->second.certificate.valid_until) {
            current = found->second;
            if (now < found->second.refresh_at) return found->second.certificate;
        }
    }
    DnsCryptCertificate certificate;
    try {
        auto request = make_query(server.provider_name, 16);
        certificate = select_dnscrypt_certificate(fetch_certificates(server, request, parse_question(request), deadline),
                                                   parse_dnscrypt_provider_key(server.public_key), now);
    } catch (const Error&) {
        if (current) return current->certificate;
        throw;
    }
    {
        const std::lock_guard lock(mutex);
        cache[key] = Entry{certificate, std::min<uint64_t>(certificate.valid_until, now + 3600)};
    }
    return certificate;
}
class DnsCryptTransport final : public IDnsTransport {
public:
    explicit DnsCryptTransport(bool anonymized) : anonymized_(anonymized) {}
    Packet exchange(const Packet& request, const Server& server) override {
        if (!server.enabled) throw Error("SERVER_DISABLED", "DNS server is disabled");
        if (!server.timeout_ms || server.timeout_ms > 120000) throw Error("CONFIG", "Invalid request timeout");
        validate_dnscrypt_server(server);
        const auto expected = parse_question(request);
        if (expected.flags & 0x8000) throw Error("DNS_MALFORMED", "Expected query, not response");
        const auto deadline = detail::NetworkClock::now() + std::chrono::milliseconds(server.timeout_ms);
        const auto cert = load_certificate(server, deadline);
        sodium_ready();
        std::array<uint8_t, 32> client_public{}, client_secret{};
        struct Wipe { void* bytes; size_t size; ~Wipe() { sodium_memzero(bytes, size); } } wipe_secret{client_secret.data(),client_secret.size()};
        if (crypto_box_curve25519xchacha20poly1305_keypair(client_public.data(), client_secret.data()) != 0)
            throw Error("CRYPTO_INIT", "Cannot generate DNSCrypt client key");
        auto shared = dnscrypt_shared_key(client_secret, cert);
        Wipe wipe_shared{shared.data(),shared.size()};
        auto perform = [&](bool tcp) {
            std::array<uint8_t, 12> nonce{}; randombytes_buf(nonce.data(), nonce.size());
            size_t target = 512;
            if (tcp) target += static_cast<size_t>(randombytes_uniform(4)) * 64;
            auto encrypted = build_dnscrypt_query(request, cert, client_secret, nonce, target);
            Packet outgoing = anonymized_ ? anonymize(encrypted, server) : encrypted;
            auto destination = anonymized_ ? relay_endpoint(server) : endpoint(server);
            auto response = detail::exchange_network(outgoing, destination, tcp, deadline);
            return open_dnscrypt_response(response, shared, nonce, cert.encryption_system);
        };
        Packet response;
        try { response = perform(false); }
        catch (const Error& error) { if (!retryable(error)) throw; response = perform(true); }
        auto parsed = parse_response(response, expected);
        if (parsed.truncated) { response = perform(true); parsed = parse_response(response, expected); }
        if (parsed.truncated) throw Error("DNS_TRUNCATED", "Truncated DNSCrypt response over TCP");
        return response;
    }
private:
    bool anonymized_;
};
}

std::array<uint8_t, 32> parse_dnscrypt_provider_key(const std::string& text) {
    std::string hex;
    for (unsigned char c : text) {
        if (c == ':' || c == '-' || c == ' ' || c == '\t') continue;
        if (!std::isxdigit(c)) throw Error("DNSCRYPT_KEY", "Provider key contains a non-hexadecimal character");
        hex.push_back(static_cast<char>(c));
    }
    if (hex.size() != 64) throw Error("DNSCRYPT_KEY", "Provider public key must contain 32 bytes");
    std::array<uint8_t, 32> result{};
    for (size_t i = 0; i < result.size(); ++i) {
        const auto digit = [](char c) -> uint8_t { return static_cast<uint8_t>(c <= '9' ? c - '0' : (c | 32) - 'a' + 10); };
        result[i] = static_cast<uint8_t>((digit(hex[i * 2]) << 4) | digit(hex[i * 2 + 1]));
    }
    return result;
}

void validate_dnscrypt_server(const Server& server) {
    if (server.protocol != Protocol::dnscrypt && server.protocol != Protocol::anonymized_dnscrypt)
        throw Error("PROTOCOL", "Expected a DNSCrypt server");
    if (server.ip.empty()) throw Error("ENDPOINT", "DNSCrypt server requires a numeric IP");
    (void)normalize_host(server.provider_name);
    (void)parse_dnscrypt_provider_key(server.public_key);
    if (server.protocol == Protocol::anonymized_dnscrypt) (void)relay_endpoint(server);
}

DnsCryptCertificate select_dnscrypt_certificate(const std::vector<Packet>& blobs,
    std::span<const uint8_t, 32> provider_key, uint64_t unix_time) {
    sodium_ready();
    bool found = false;
    DnsCryptCertificate selected;
    for (const auto& blob : blobs) {
        if (blob.size() < classical_certificate_size || !std::equal(cert_magic.begin(), cert_magic.end(), blob.begin())) continue;
        if (blob[4] != 0 || (blob[5] != 1 && blob[5] != 2) || blob[6] != 0 || blob[7] != 0) continue;
        if (crypto_sign_verify_detached(blob.data() + 8, blob.data() + 72,
                static_cast<unsigned long long>(blob.size() - 72), provider_key.data()) != 0) continue;
        DnsCryptCertificate candidate;
        candidate.encryption_system = blob[5];
        std::copy_n(blob.begin() + 72, 32, candidate.resolver_public_key.begin());
        std::copy_n(blob.begin() + 104, 8, candidate.client_magic.begin());
        candidate.serial = be32(blob, 112); candidate.valid_from = be32(blob, 116); candidate.valid_until = be32(blob, 120);
        if (candidate.encryption_system == 2 && std::all_of(candidate.client_magic.begin(), candidate.client_magic.begin() + 7,
                                                            [](uint8_t byte) { return byte == 0; })) continue;
        if (candidate.valid_from >= candidate.valid_until || unix_time < candidate.valid_from || unix_time > candidate.valid_until) continue;
        if (!found || candidate.serial > selected.serial) { selected = candidate; found = true; }
    }
    if (!found) throw Error("DNSCRYPT_CERT", "No valid supported DNSCrypt certificate");
    return selected;
}

std::vector<Packet> extract_dnscrypt_certificates(const Packet& response) {
    if (response.size() < 12) throw Error("DNS_MALFORMED", "Short DNS certificate response");
    size_t at = 12;
    const auto questions = be16(response, 4), answers = be16(response, 6);
    for (uint16_t i = 0; i < questions; ++i) { at = skip_name(response, at); if (at + 4 > response.size()) throw Error("DNS_MALFORMED", "Truncated DNS question"); at += 4; }
    std::vector<Packet> result;
    for (uint16_t i = 0; i < answers; ++i) {
        at = skip_name(response, at);
        if (at + 10 > response.size()) throw Error("DNS_MALFORMED", "Truncated DNS answer");
        const auto type = be16(response, at), klass = be16(response, at + 2), length = be16(response, at + 8); at += 10;
        if (at + length > response.size()) throw Error("DNS_MALFORMED", "Truncated DNS RDATA");
        if (type == 16 && klass == 1) {
            Packet certificate; size_t part = at;
            while (part < at + length) {
                const size_t chunk = response[part++];
                if (part + chunk > at + length) throw Error("DNS_MALFORMED", "Invalid TXT character-string");
                certificate.insert(certificate.end(), response.begin() + static_cast<std::ptrdiff_t>(part),
                                   response.begin() + static_cast<std::ptrdiff_t>(part + chunk));
                part += chunk;
            }
            result.push_back(std::move(certificate));
        }
        at += length;
    }
    if (result.empty()) throw Error("DNSCRYPT_CERT", "Certificate response contains no TXT certificate");
    return result;
}

std::array<uint8_t, 32> dnscrypt_shared_key(std::span<const uint8_t, 32> client_secret,
    const DnsCryptCertificate& certificate) {
    sodium_ready();
    std::array<uint8_t, 32> shared{};
    const int result = certificate.encryption_system == 1
        ? crypto_box_curve25519xsalsa20poly1305_beforenm(shared.data(), certificate.resolver_public_key.data(), client_secret.data())
        : crypto_box_curve25519xchacha20poly1305_beforenm(shared.data(), certificate.resolver_public_key.data(), client_secret.data());
    if (result != 0)
        throw Error("DNSCRYPT_KEY", "Resolver uses a weak X25519 public key");
    return shared;
}

Packet build_dnscrypt_query(const Packet& request, const DnsCryptCertificate& certificate,
    std::span<const uint8_t, 32> client_secret, std::span<const uint8_t, 12> client_nonce,
    size_t minimum_wire_size) {
    sodium_ready();
    if (request.size() < 12 || request.size() > 4000 || minimum_wire_size > 4096)
        throw Error("DNSCRYPT_SIZE", "DNSCrypt query size is outside protocol bounds");
    const size_t needed = std::max(request.size() + 1, minimum_wire_size > query_overhead ? minimum_wire_size - query_overhead : size_t{1});
    const size_t padded_size = (needed + 63) / 64 * 64;
    if (padded_size + query_overhead > 4096) throw Error("DNSCRYPT_SIZE", "Encrypted DNSCrypt query exceeds 4096 bytes");
    Packet padded(padded_size); std::copy(request.begin(), request.end(), padded.begin()); padded[request.size()] = 0x80;
    std::array<uint8_t, 32> client_public{};
    if (crypto_scalarmult_curve25519_base(client_public.data(), client_secret.data()) != 0)
        throw Error("CRYPTO_INIT", "Cannot derive DNSCrypt client public key");
    const auto shared = dnscrypt_shared_key(client_secret, certificate);
    std::array<uint8_t, 24> nonce{}; std::copy(client_nonce.begin(), client_nonce.end(), nonce.begin());
    Packet result; result.reserve(query_overhead + padded.size());
    result.insert(result.end(), certificate.client_magic.begin(), certificate.client_magic.end());
    result.insert(result.end(), client_public.begin(), client_public.end());
    result.insert(result.end(), client_nonce.begin(), client_nonce.end());
    const size_t encrypted_at = result.size(); result.resize(result.size() + padded.size() + crypto_box_curve25519xchacha20poly1305_MACBYTES);
    const int encrypted = certificate.encryption_system == 1
        ? crypto_box_easy_afternm(result.data() + encrypted_at, padded.data(),
            static_cast<unsigned long long>(padded.size()), nonce.data(), shared.data())
        : crypto_box_curve25519xchacha20poly1305_easy_afternm(result.data() + encrypted_at, padded.data(),
            static_cast<unsigned long long>(padded.size()), nonce.data(), shared.data());
    if (encrypted != 0)
        throw Error("DNSCRYPT_CRYPTO", "DNSCrypt query encryption failed");
    return result;
}

Packet open_dnscrypt_response(const Packet& response, std::span<const uint8_t, 32> shared_key,
    std::span<const uint8_t, 12> client_nonce, uint16_t encryption_system) {
    sodium_ready();
    if (response.size() < 32 + crypto_box_curve25519xchacha20poly1305_MACBYTES + 1 ||
        !std::equal(resolver_magic.begin(), resolver_magic.end(), response.begin()))
        throw Error("DNSCRYPT_RESPONSE", "Invalid DNSCrypt response header");
    if (!std::equal(client_nonce.begin(), client_nonce.end(), response.begin() + 8))
        throw Error("DNSCRYPT_NONCE", "DNSCrypt response nonce does not match the query");
    std::array<uint8_t, 24> nonce{}; std::copy_n(response.begin() + 8, 24, nonce.begin());
    Packet plain(response.size() - 32 - crypto_box_curve25519xchacha20poly1305_MACBYTES);
    if (encryption_system != 1 && encryption_system != 2) throw Error("DNSCRYPT_CERT", "Unsupported DNSCrypt encryption system");
    const int opened = encryption_system == 1
        ? crypto_box_open_easy_afternm(plain.data(), response.data() + 32,
            static_cast<unsigned long long>(response.size() - 32), nonce.data(), shared_key.data())
        : crypto_box_curve25519xchacha20poly1305_open_easy_afternm(plain.data(), response.data() + 32,
            static_cast<unsigned long long>(response.size() - 32), nonce.data(), shared_key.data());
    if (opened != 0)
        throw Error("DNSCRYPT_AUTH", "DNSCrypt response authentication failed");
    size_t end = plain.size(); while (end && plain[end - 1] == 0) --end;
    if (!end || plain[end - 1] != 0x80) throw Error("DNSCRYPT_PADDING", "Invalid DNSCrypt response padding");
    plain.resize(end - 1);
    if (plain.size() < 12) throw Error("DNS_MALFORMED", "Decrypted DNSCrypt response is too short");
    return plain;
}

std::unique_ptr<IDnsTransport> make_dnscrypt_transport(Protocol protocol) {
    return std::make_unique<DnsCryptTransport>(protocol == Protocol::anonymized_dnscrypt);
}
}
