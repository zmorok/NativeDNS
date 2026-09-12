#include <nativedns/dns.hpp>
#include <nativedns/platform.hpp>
#include <curl/curl.h>
#include <algorithm>
#include <charconv>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>

namespace nd {
namespace {
using Clock = std::chrono::steady_clock;
void curl_check(CURLcode code) {
    if (code == CURLE_OK) return;
    std::string category = "TLS_HTTP";
    if (code == CURLE_OPERATION_TIMEDOUT) category = "TIMEOUT";
    if (code == CURLE_PEER_FAILED_VERIFICATION || code == CURLE_SSL_CACERT_BADFILE) category = "TLS_CERTIFICATE";
    if (code == CURLE_SSL_PINNEDPUBKEYNOTMATCH) category = "TLS_PIN";
    if (code == CURLE_COULDNT_RESOLVE_HOST) category = "BOOTSTRAP";
    throw Error(category, std::string(curl_easy_strerror(code)) + " (curl " + std::to_string(code) + ")");
}
struct CurlGlobal {
    CurlGlobal() { curl_check(curl_global_init(CURL_GLOBAL_DEFAULT)); }
    ~CurlGlobal() { curl_global_cleanup(); }
};
struct CurlHandle {
    CURL* value;
    char error_buffer[CURL_ERROR_SIZE]{};
    CurlHandle() { static CurlGlobal global; value = curl_easy_init(); if (!value) throw Error("MEMORY", "Cannot initialize TLS/HTTP handle"); set(CURLOPT_ERRORBUFFER,error_buffer); }
    ~CurlHandle() { curl_easy_cleanup(value); }
    template<typename T> void set(CURLoption option, T v) { curl_check(curl_easy_setopt(value, option, v)); }
    void perform() {
        const auto code = curl_easy_perform(value);
        try { curl_check(code); }
        catch (const Error& error) {
            const std::string detail = error_buffer;
            const bool cert = detail.find("SEC_E_CERT_EXPIRED") != std::string::npos || detail.find("SEC_E_WRONG_PRINCIPAL") != std::string::npos || detail.find("CERT_E_") != std::string::npos;
            throw Error(cert ? "TLS_CERTIFICATE" : error.code,std::string(error.what()) + ": " + detail);
        }
    }
    void reset() noexcept {
        curl_easy_reset(value);
        std::fill(std::begin(error_buffer),std::end(error_buffer),'\0');
        (void)curl_easy_setopt(value,CURLOPT_ERRORBUFFER,error_buffer);
    }
};
struct List {
    curl_slist* value = nullptr;
    ~List() { curl_slist_free_all(value); }
    void add(const std::string& text) { auto* next = curl_slist_append(value,text.c_str()); if (!next) throw Error("MEMORY","Cannot allocate curl list"); value = next; }
};
struct Url {
    CURLU* value = curl_url();
    explicit Url(const std::string& url) {
        if (!value) throw Error("MEMORY", "Cannot parse URL");
        if (curl_url_set(value,CURLUPART_URL,url.c_str(),0) != CURLUE_OK) { curl_url_cleanup(value); value = nullptr; throw Error("ENDPOINT","Invalid HTTPS URL"); }
    }
    ~Url() { curl_url_cleanup(value); }
    std::string get(CURLUPart part, unsigned flags = 0) const {
        char* text = nullptr; const auto code = curl_url_get(value,part,&text,flags);
        if (code != CURLUE_OK) return {};
        std::string result(text); curl_free(text); return result;
    }
};
uint32_t remaining(Clock::time_point deadline) {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    if (ms <= 0) throw Error("TIMEOUT", "Secure DNS deadline exceeded");
    return static_cast<uint32_t>(ms);
}

int configure_curl_socket(void*, curl_socket_t socket, curlsocktype) noexcept {
    try { platform::configure_upstream_socket(static_cast<std::intptr_t>(socket)); return CURL_SOCKOPT_OK; }
    catch (...) { return CURL_SOCKOPT_ERROR; }
}

size_t receive_body(char* data, size_t size, size_t count, void* context) noexcept {
    auto* packet = static_cast<Packet*>(context);
    if (size && count > 65535 / size) return 0;
    const size_t bytes = size * count;
    if (bytes > 65535 - packet->size()) return 0;
    try { packet->insert(packet->end(), reinterpret_cast<uint8_t*>(data), reinterpret_cast<uint8_t*>(data) + bytes); }
    catch (...) { return 0; }
    return bytes;
}
void transfer(CURL* curl, uint8_t* buffer, size_t size, bool writing, Clock::time_point deadline) {
    curl_socket_t socket = CURL_SOCKET_BAD;
    curl_check(curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &socket));
    if (socket == CURL_SOCKET_BAD) throw Error("TLS", "TLS connection has no socket");
    size_t at = 0;
    while (at < size) {
        const auto timeout_ms = remaining(deadline);
        size_t amount = 0;
        const auto code = writing ? curl_easy_send(curl,buffer + at,size - at,&amount) : curl_easy_recv(curl,buffer + at,size - at,&amount);
        if (code == CURLE_AGAIN) {
            (void)timeout_ms;
            platform::wait_socket(static_cast<std::intptr_t>(socket),writing,deadline);
            continue;
        }
        curl_check(code);
        if (!amount) throw Error("DNS_EOF", "TLS connection closed before complete DNS frame");
        at += amount;
    }
}
class SecureTransport final : public IDnsTransport {
public:
    explicit SecureTransport(bool dot) : dot_(dot) {}
    Packet exchange(const Packet& request, const Server& server) override {
        if (!server.enabled) throw Error("SERVER_DISABLED","DNS server is disabled");
        if (!server.timeout_ms || server.timeout_ms > 120000) throw Error("CONFIG","Invalid timeout");
        const auto question = parse_question(request);
        if (question.flags & 0x8000) throw Error("DNS_MALFORMED","Expected query");
        const auto deadline = Clock::now() + std::chrono::milliseconds(server.timeout_ms);
        std::unique_ptr<CurlHandle> local_handle;
        std::unique_ptr<Lease> lease;
        if(dot_) local_handle=std::make_unique<CurlHandle>();
        else lease=acquire(server,deadline);
        auto& handle=dot_?*local_handle:*lease->entry->handle;
        const std::string url = dot_ ? "https://" + normalize_host(server.hostname) + ":" + std::to_string(server.port ? server.port : 853) + "/" : server.url;
        Url parsed(url);
        if (parsed.get(CURLUPART_SCHEME) != "https" || !parsed.get(CURLUPART_USER).empty() || !parsed.get(CURLUPART_PASSWORD).empty() || !parsed.get(CURLUPART_FRAGMENT).empty())
            throw Error("ENDPOINT", "Secure DNS URL must be HTTPS without credentials or fragment");
        const auto host = parsed.get(CURLUPART_HOST);
        const auto port = parsed.get(CURLUPART_PORT,CURLU_DEFAULT_PORT);
        if (host.empty() || port.empty()) throw Error("ENDPOINT","Missing HTTPS host/port");
        handle.set(CURLOPT_URL,url.c_str());
        handle.set(CURLOPT_SOCKOPTFUNCTION,&configure_curl_socket);
        handle.set(CURLOPT_PROTOCOLS_STR,"https");
        handle.set(CURLOPT_SSL_VERIFYPEER,1L); handle.set(CURLOPT_SSL_VERIFYHOST,2L);
        handle.set(CURLOPT_SSLVERSION,static_cast<long>(CURL_SSLVERSION_TLSv1_2));
        handle.set(CURLOPT_FOLLOWLOCATION,0L); handle.set(CURLOPT_NOSIGNAL,1L);
        handle.set(CURLOPT_HTTP_VERSION,static_cast<long>(dot_?CURL_HTTP_VERSION_1_1:CURL_HTTP_VERSION_2TLS));
        if(!dot_) {
            handle.set(CURLOPT_PIPEWAIT,1L);
            handle.set(CURLOPT_MAXAGE_CONN,30L);
            handle.set(CURLOPT_MAXLIFETIME_CONN,300L);
        }
        handle.set(CURLOPT_SSL_ENABLE_ALPN,dot_ ? 0L : 1L);
        // Never use environment proxy, user credentials, or .netrc (also disabled in build).
        std::string endpoint = server.ip;
        if (endpoint.empty() && !server.bootstrap.empty()) {
            std::string failure;
            for (const auto& bootstrap : server.bootstrap) {
                Server plain; plain.ip = bootstrap; plain.name = "bootstrap"; plain.timeout_ms = remaining(deadline);
                for (uint16_t type : {uint16_t{1},uint16_t{28}}) {
                    plain.timeout_ms = remaining(deadline);
                    auto result = test_server(plain,host,type);
                    if (result.success) { endpoint = result.addresses.front(); break; }
                    failure = result.error_code + ": " + result.message;
                }
                if (!endpoint.empty()) break;
            }
            if (endpoint.empty()) throw Error("BOOTSTRAP","Explicit bootstrap failed: " + failure);
        }
        List resolve;
        if (!endpoint.empty()) {
            // Numeric endpoint validation is independent of certificate identity.
            Server numeric; numeric.id = 1; numeric.name = "endpoint"; numeric.ip = endpoint;
            auto config = default_config(); config.servers.push_back(numeric); validate(config);
            resolve.add(host + ":" + port + ":" + (endpoint.find(':') == std::string::npos ? endpoint : "[" + endpoint + "]"));
            handle.set(CURLOPT_RESOLVE,resolve.value);
        }
        std::string pins;
        for (const auto& pin : server.hashes) {
            if (!pin.starts_with("sha256//") || pin.size() != 52) throw Error("TLS_PIN","Only sha256// base64 SPKI pins are supported");
            if (!pins.empty()) pins += ';';
            pins += pin;
        }
        if (!pins.empty()) handle.set(CURLOPT_PINNEDPUBLICKEY,pins.c_str());
        handle.set(CURLOPT_TIMEOUT_MS,static_cast<long>(remaining(deadline)));
        handle.set(CURLOPT_CONNECTTIMEOUT_MS,static_cast<long>(remaining(deadline)));
        Packet response;
        if (dot_) {
            handle.set(CURLOPT_CONNECT_ONLY,1L);
            handle.perform();
            Packet framed{static_cast<uint8_t>(request.size() >> 8),static_cast<uint8_t>(request.size())};
            framed.insert(framed.end(),request.begin(),request.end());
            transfer(handle.value,framed.data(),framed.size(),true,deadline);
            uint8_t prefix[2]{}; transfer(handle.value,prefix,2,false,deadline);
            const size_t length = static_cast<size_t>((prefix[0] << 8) | prefix[1]);
            if (length < 12) throw Error("DNS_MALFORMED","Invalid DoT DNS length");
            response.resize(length); transfer(handle.value,response.data(),response.size(),false,deadline);
        } else {
            List headers; headers.add("Content-Type: application/dns-message"); headers.add("Accept: application/dns-message");
            handle.set(CURLOPT_HTTPHEADER,headers.value); handle.set(CURLOPT_POST,1L);
            handle.set(CURLOPT_POSTFIELDS,reinterpret_cast<const char*>(request.data()));
            handle.set(CURLOPT_POSTFIELDSIZE,static_cast<long>(request.size()));
            handle.set(CURLOPT_WRITEFUNCTION,&receive_body); handle.set(CURLOPT_WRITEDATA,&response);
            handle.perform();
            long status = 0; curl_check(curl_easy_getinfo(handle.value,CURLINFO_RESPONSE_CODE,&status));
            if (status != 200) throw Error("HTTP_STATUS","DoH HTTP status " + std::to_string(status));
            char* content_type = nullptr; curl_check(curl_easy_getinfo(handle.value,CURLINFO_CONTENT_TYPE,&content_type));
            std::string mime = content_type ? content_type : "";
            std::transform(mime.begin(),mime.end(),mime.begin(),[](unsigned char c) { return static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c); });
            if (mime != "application/dns-message") throw Error("HTTP_CONTENT_TYPE","DoH response must be application/dns-message");
        }
        if (parse_response(response,question).truncated) throw Error("DNS_TRUNCATED","Truncated secure DNS response");
        return response;
    }
private: bool dot_;
    struct Entry { bool busy=false;std::unique_ptr<CurlHandle> handle=std::make_unique<CurlHandle>(); };
    struct Lease {
        SecureTransport& owner;std::shared_ptr<Entry> entry;
        Lease(SecureTransport& value,std::shared_ptr<Entry> selected):owner(value),entry(std::move(selected)){}
        Lease(const Lease&)=delete;Lease& operator=(const Lease&)=delete;
        ~Lease(){entry->handle->reset();std::lock_guard lock(owner.pool_mutex_);entry->busy=false;owner.pool_changed_.notify_one();}
    };
    std::unique_ptr<Lease> acquire(const Server& server,Clock::time_point deadline) {
        std::string key=server.url+'|'+server.ip+'|'+std::to_string(server.port)+'|'+server.hostname;
        for(const auto& bootstrap:server.bootstrap) key+='|'+bootstrap;
        for(const auto& hash:server.hashes) key+='|'+hash;
        std::unique_lock lock(pool_mutex_);auto& entries=pool_[key];
        for(;;) {
            const auto found=std::find_if(entries.begin(),entries.end(),[](const auto& entry){return !entry->busy;});
            if(found!=entries.end()){(*found)->busy=true;return std::make_unique<Lease>(*this,*found);}
            if(entries.size()<8){auto entry=std::make_shared<Entry>();entry->busy=true;entries.push_back(entry);return std::make_unique<Lease>(*this,std::move(entry));}
            if(pool_changed_.wait_until(lock,deadline)==std::cv_status::timeout) throw Error("TIMEOUT","DoH connection pool is busy");
        }
    }
    std::mutex pool_mutex_;std::condition_variable pool_changed_;
    std::map<std::string,std::vector<std::shared_ptr<Entry>>> pool_;
};
}
std::unique_ptr<IDnsTransport> make_secure_transport(Protocol protocol) { return std::make_unique<SecureTransport>(protocol == Protocol::dot); }
}
