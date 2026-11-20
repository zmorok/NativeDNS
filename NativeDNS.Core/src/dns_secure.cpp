#include <nativedns/dns.hpp>
#include <nativedns/dns_network.hpp>
#include <nativedns/detail/cancellation.hpp>
#include <nativedns/detail/bootstrap.hpp>
#include <nativedns/detail/fault_injection.hpp>
#include "pool_limits.hpp"
#include <nativedns/platform.hpp>
#include <curl/curl.h>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <stop_token>
#include <thread>
#include <unordered_map>

namespace nd {
namespace {
using Clock = std::chrono::steady_clock;

class SecureAttemptError final : public Error {
public:
    bool retryable = false;
    SecureAttemptError(std::string code, std::string message, bool can_retry)
        : Error(std::move(code), std::move(message)), retryable(can_retry) {
    }
};

bool is_stale_doh_curl_error(CURLcode code) noexcept {
    switch (code) {
        case CURLE_RECV_ERROR:
        case CURLE_SEND_ERROR:
        case CURLE_GOT_NOTHING:
        case CURLE_HTTP2:
        case CURLE_HTTP2_STREAM:
            return true;
        default:
            return false;
    }
}

void curl_check(CURLcode code) {
    if (code == CURLE_OK)
        return;
    std::string category = "TLS_HTTP";
    if (code == CURLE_OPERATION_TIMEDOUT)
        category = "TIMEOUT";
    if (code == CURLE_PEER_FAILED_VERIFICATION || code == CURLE_SSL_CACERT_BADFILE)
        category = "TLS_CERTIFICATE";
    if (code == CURLE_SSL_PINNEDPUBKEYNOTMATCH)
        category = "TLS_PIN";
    if (code == CURLE_COULDNT_RESOLVE_HOST)
        category = "BOOTSTRAP";
    if (code == CURLE_COULDNT_CONNECT)
        category = "CONNECT";
    throw Error(category,
                std::string(curl_easy_strerror(code)) + " (curl " + std::to_string(code) + ")");
}

void throw_classified_curl_error(CURL* easy,
                                 CURLcode code,
                                 const char* error_buffer,
                                 const std::string& diagnostic_endpoint,
                                 const NetworkRoute& route,
                                 const std::exception_ptr& socket_failure,
                                 bool doh_stale_retryable = false) {
    if (code != CURLE_OK && socket_failure)
        std::rethrow_exception(socket_failure);
    try {
        curl_check(code);
    } catch (const Error& error) {
        const std::string detail = error_buffer ? error_buffer : "";
        char* remote = nullptr;
        (void)curl_easy_getinfo(easy, CURLINFO_PRIMARY_IP, &remote);
        const bool revocation =
            detail.find("CRYPT_E_REVOCATION_OFFLINE") != std::string::npos ||
            detail.find("SEC_E_REVOCATION_OFFLINE") != std::string::npos ||
            detail.find("0x80092013") != std::string::npos;
        const bool cert = detail.find("SEC_E_CERT_EXPIRED") != std::string::npos ||
                          detail.find("SEC_E_WRONG_PRINCIPAL") != std::string::npos ||
                          detail.find("CERT_E_") != std::string::npos;
        std::string final_code = revocation ? "TLS_REVOCATION_OFFLINE"
                                 : cert     ? "TLS_CERTIFICATE"
                                            : error.code;
        std::string message = std::string(error.what()) + ": " + detail + " endpoint=" +
                              (remote && *remote ? remote : diagnostic_endpoint) + " interface=" +
                              (route.interface_id.empty() ? "automatic" : route.interface_id) +
                              " generation=" + std::to_string(route.generation);
        const bool retryable = doh_stale_retryable && !revocation && !cert &&
                               is_stale_doh_curl_error(code);
        throw SecureAttemptError(std::move(final_code), std::move(message), retryable);
    }
}

struct CurlGlobal {
    CurlGlobal() {
        curl_check(curl_global_init(CURL_GLOBAL_DEFAULT));
    }
    ~CurlGlobal() {
        curl_global_cleanup();
    }
};

void ensure_curl_global() {
    static CurlGlobal global;
}

void apply_test_ca_if_configured(CURL* easy) {
    const auto ca = detail::test_ca_file_for_testing();
    if (ca.empty())
        return;
    curl_check(curl_easy_setopt(easy, CURLOPT_CAINFO, ca.c_str()));
#ifdef _WIN32
    curl_check(curl_easy_setopt(easy, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NO_REVOKE)));
#endif
}

struct CurlHandle {
    CURL* value = nullptr;
    CURLM* multi = nullptr;
    bool attached = false;
    char error_buffer[CURL_ERROR_SIZE]{};
    std::map<curl_socket_t, std::unique_ptr<detail::NetworkUpstreamGuard>> upstream_sockets;
    NetworkRoute route;
    std::string diagnostic_endpoint;
    std::exception_ptr socket_failure;
    CurlHandle() {
        ensure_curl_global();
        value = curl_easy_init();
        if (!value)
            throw Error("MEMORY", "Cannot initialize TLS/HTTP handle");
        multi = curl_multi_init();
        if (!multi) {
            curl_easy_cleanup(value);
            throw Error("MEMORY", "Cannot initialize TLS/HTTP event loop");
        }
        set_callbacks();
    }
    ~CurlHandle() {
        if (attached)
            curl_multi_remove_handle(multi, value);
        curl_multi_cleanup(multi);
        curl_easy_cleanup(value);
    }
    template <typename T> void set(CURLoption option, T v) {
        curl_check(curl_easy_setopt(value, option, v));
    }
    void perform() {
        detail::check_cancelled();
        const auto check_multi = [](CURLMcode result) {
            if (result != CURLM_OK)
                throw Error("TLS_HTTP", curl_multi_strerror(result));
        };
        check_multi(curl_multi_add_handle(multi, value));
        attached = true;
        int running = 0;
        do {
            detail::check_cancelled();
            check_multi(curl_multi_perform(multi, &running));
            if (running)
                check_multi(curl_multi_poll(multi, nullptr, 0, 100, nullptr));
        } while (running);
        CURLcode code = CURLE_RECV_ERROR;
        int messages = 0;
        while (const auto message = curl_multi_info_read(multi, &messages))
            if (message->msg == CURLMSG_DONE && message->easy_handle == value)
                code = message->data.result;
        if (code != CURLE_OK)
            throw_classified_curl_error(
                value, code, error_buffer, diagnostic_endpoint, route, socket_failure, false);
    }
    void reset() noexcept {
        if (attached) {
            curl_multi_remove_handle(multi, value);
            attached = false;
        }
        curl_easy_reset(value);
        socket_failure = nullptr;
        diagnostic_endpoint.clear();
        std::fill(std::begin(error_buffer), std::end(error_buffer), '\0');
        set_callbacks_noexcept();
    }

private:
    static int
    configure_socket(void* context, curl_socket_t socket, curlsocktype purpose) noexcept {
        auto& self = *static_cast<CurlHandle*>(context);
        try {
            platform::bind_upstream_interface(static_cast<std::intptr_t>(socket), self.route);
            const uint16_t port = platform::prepare_upstream_socket(
                static_cast<std::intptr_t>(socket), purpose == CURLSOCKTYPE_IPCXN);
            if (port && !self.upstream_sockets.contains(socket))
                self.upstream_sockets.emplace(
                    socket,
                    std::make_unique<detail::NetworkUpstreamGuard>(
                        true, port, platform::socket_is_ipv6(static_cast<std::intptr_t>(socket))));
            return CURL_SOCKOPT_OK;
        } catch (...) {
            self.socket_failure = std::current_exception();
            return CURL_SOCKOPT_ERROR;
        }
    }
    static int close_socket(void* context, curl_socket_t socket) noexcept {
        auto& self = *static_cast<CurlHandle*>(context);
        const int result = platform::close_upstream_socket(static_cast<std::intptr_t>(socket));
        self.upstream_sockets.erase(socket);
        return result;
    }
    void set_callbacks() {
        set(CURLOPT_ERRORBUFFER, error_buffer);
        set(CURLOPT_SOCKOPTFUNCTION, &CurlHandle::configure_socket);
        set(CURLOPT_SOCKOPTDATA, this);
        set(CURLOPT_CLOSESOCKETFUNCTION, &CurlHandle::close_socket);
        set(CURLOPT_CLOSESOCKETDATA, this);
    }
    void set_callbacks_noexcept() noexcept {
        (void)curl_easy_setopt(value, CURLOPT_ERRORBUFFER, error_buffer);
        (void)curl_easy_setopt(value, CURLOPT_SOCKOPTFUNCTION, &CurlHandle::configure_socket);
        (void)curl_easy_setopt(value, CURLOPT_SOCKOPTDATA, this);
        (void)curl_easy_setopt(value, CURLOPT_CLOSESOCKETFUNCTION, &CurlHandle::close_socket);
        (void)curl_easy_setopt(value, CURLOPT_CLOSESOCKETDATA, this);
    }
};

struct List {
    curl_slist* value = nullptr;
    ~List() {
        curl_slist_free_all(value);
    }
    List() = default;
    List(const List&) = delete;
    List& operator=(const List&) = delete;
    void add(const std::string& text) {
        auto* next = curl_slist_append(value, text.c_str());
        if (!next)
            throw Error("MEMORY", "Cannot allocate curl list");
        value = next;
    }
};

struct Url {
    CURLU* value = curl_url();
    explicit Url(const std::string& url) {
        if (!value)
            throw Error("MEMORY", "Cannot parse URL");
        if (curl_url_set(value, CURLUPART_URL, url.c_str(), 0) != CURLUE_OK) {
            curl_url_cleanup(value);
            value = nullptr;
            throw Error("ENDPOINT", "Invalid HTTPS URL");
        }
    }
    ~Url() {
        curl_url_cleanup(value);
    }
    std::string get(CURLUPart part, unsigned flags = 0) const {
        char* text = nullptr;
        const auto code = curl_url_get(value, part, &text, flags);
        if (code != CURLUE_OK)
            return {};
        std::string result(text);
        curl_free(text);
        return result;
    }
};

uint32_t remaining(Clock::time_point deadline) {
    detail::check_cancelled();
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    if (ms <= 0)
        throw Error("TIMEOUT", "Secure DNS deadline exceeded");
    return static_cast<uint32_t>(ms);
}

size_t receive_body(char* data, size_t size, size_t count, void* context) noexcept {
    auto* packet = static_cast<Packet*>(context);
    if (size && count > 65535 / size)
        return 0;
    const size_t bytes = size * count;
    if (bytes > 65535 - packet->size())
        return 0;
    try {
        packet->insert(packet->end(),
                       reinterpret_cast<uint8_t*>(data),
                       reinterpret_cast<uint8_t*>(data) + bytes);
    } catch (...) {
        return 0;
    }
    return bytes;
}

void transfer(CURL* curl, uint8_t* buffer, size_t size, bool writing, Clock::time_point deadline) {
    curl_socket_t socket = CURL_SOCKET_BAD;
    curl_check(curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &socket));
    if (socket == CURL_SOCKET_BAD)
        throw Error("TLS", "TLS connection has no socket");
    size_t at = 0;
    while (at < size) {
        const auto timeout_ms = remaining(deadline);
        size_t amount = 0;
        const auto code = writing ? curl_easy_send(curl, buffer + at, size - at, &amount)
                                  : curl_easy_recv(curl, buffer + at, size - at, &amount);
        if (code == CURLE_AGAIN) {
            (void)timeout_ms;
            platform::wait_socket(static_cast<std::intptr_t>(socket), writing, deadline);
            continue;
        }
        curl_check(code);
        if (!amount)
            throw Error("DNS_EOF", "TLS connection closed before complete DNS frame");
        at += amount;
    }
}

// Single shared CURLM event loop for DoH HTTP/2 multiplexing per network route/generation.
// Connection sockets are tracked on the dispatcher thread so pooled connections can safely
// outlive individual easy handles.
class DohMultiDispatcher final {
public:
    static constexpr size_t max_concurrent_requests = 64;

    struct Job {
        DohMultiDispatcher* owner = nullptr;
        CURL* easy = nullptr;
        NetworkRoute route;
        char error_buffer[CURL_ERROR_SIZE]{};
        std::exception_ptr socket_failure;
        std::atomic_bool cancelled{false};
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        CURLcode result = CURLE_RECV_ERROR;
        std::string multi_error;
        ~Job() {
            if (easy)
                curl_easy_cleanup(easy);
        }
    };

    explicit DohMultiDispatcher(uint64_t generation) : generation_(generation) {
        ensure_curl_global();
        std::mutex init_mutex;
        std::condition_variable init_cv;
        bool initialized = false;
        std::string init_error;
        loop_ = std::jthread([this, &init_mutex, &init_cv, &initialized, &init_error] {
            run(init_mutex, init_cv, initialized, init_error);
        });
        std::unique_lock lock(init_mutex);
        init_cv.wait(lock, [&] { return initialized; });
        if (!init_error.empty()) {
            stop();
            throw Error("TLS_HTTP", init_error);
        }
    }

    ~DohMultiDispatcher() {
        stop();
    }

    uint64_t generation() const noexcept {
        return generation_;
    }

    bool idle() const {
        std::lock_guard lock(mutex_);
        return in_flight_ == 0;
    }

    bool try_acquire_slot(Clock::time_point deadline) {
        std::unique_lock lock(mutex_);
        while (in_flight_ >= max_concurrent_requests && !stopping_) {
            if (detail::wait_until_change(slot_cv_, lock, deadline) == std::cv_status::timeout)
                return false;
        }
        if (stopping_)
            return false;
        ++in_flight_;
        return true;
    }

    void release_slot() {
        {
            std::lock_guard lock(mutex_);
            if (in_flight_)
                --in_flight_;
        }
        slot_cv_.notify_one();
    }

    void attach_callbacks(Job& job) {
        job.owner = this;
        curl_check(curl_easy_setopt(job.easy, CURLOPT_ERRORBUFFER, job.error_buffer));
        curl_check(curl_easy_setopt(job.easy, CURLOPT_SOCKOPTFUNCTION, &DohMultiDispatcher::configure_socket));
        curl_check(curl_easy_setopt(job.easy, CURLOPT_SOCKOPTDATA, &job));
        curl_check(curl_easy_setopt(job.easy, CURLOPT_CLOSESOCKETFUNCTION, &DohMultiDispatcher::close_socket));
        curl_check(curl_easy_setopt(job.easy, CURLOPT_CLOSESOCKETDATA, this));
    }

    void execute(const std::shared_ptr<Job>& job) {
        detail::check_cancelled();
        {
            std::lock_guard lock(mutex_);
            if (stopping_)
                throw Error("CANCELLED", "DoH dispatcher is shutting down");
            pending_.push_back(job);
        }
        wake();
        std::stop_callback on_cancel(detail::request_cancellation, [this, job] {
            job->cancelled.store(true, std::memory_order_release);
            wake();
        });
        if (detail::request_cancellation.stop_requested()) {
            job->cancelled.store(true, std::memory_order_release);
            wake();
        }
        std::unique_lock lock(job->mutex);
        job->cv.wait(lock, [&] { return job->done; });
        if (job->cancelled.load(std::memory_order_acquire) ||
            detail::request_cancellation.stop_requested())
            throw Error("CANCELLED", "DNS request cancelled");
        if (!job->multi_error.empty())
            throw Error("TLS_HTTP", job->multi_error);
    }

    void wake() noexcept {
        std::lock_guard lock(multi_wake_mutex_);
        if (multi_)
            (void)curl_multi_wakeup(multi_);
    }

private:
    void stop() noexcept {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        slot_cv_.notify_all();
        wake();
        if (loop_.joinable())
            loop_.join();
    }

    static int configure_socket(void* context, curl_socket_t socket, curlsocktype purpose) noexcept {
        auto& job = *static_cast<Job*>(context);
        try {
            platform::bind_upstream_interface(static_cast<std::intptr_t>(socket), job.route);
            const uint16_t port = platform::prepare_upstream_socket(
                static_cast<std::intptr_t>(socket), purpose == CURLSOCKTYPE_IPCXN);
            if (port && !job.owner->upstream_sockets_.contains(socket))
                job.owner->upstream_sockets_.emplace(
                    socket,
                    std::make_unique<detail::NetworkUpstreamGuard>(
                        true, port, platform::socket_is_ipv6(static_cast<std::intptr_t>(socket))));
            return CURL_SOCKOPT_OK;
        } catch (...) {
            job.socket_failure = std::current_exception();
            return CURL_SOCKOPT_ERROR;
        }
    }

    static int close_socket(void* context, curl_socket_t socket) noexcept {
        auto& self = *static_cast<DohMultiDispatcher*>(context);
        const int result = platform::close_upstream_socket(static_cast<std::intptr_t>(socket));
        self.upstream_sockets_.erase(socket);
        return result;
    }

    static void complete_job(const std::shared_ptr<Job>& job,
                             CURLcode result,
                             std::string multi_error = {}) {
        {
            std::lock_guard lock(job->mutex);
            job->result = result;
            job->multi_error = std::move(multi_error);
            job->done = true;
        }
        job->cv.notify_one();
    }

    void run(std::mutex& init_mutex,
             std::condition_variable& init_cv,
             bool& initialized,
             std::string& init_error) {
        CURLM* multi = curl_multi_init();
        if (!multi) {
            std::lock_guard lock(init_mutex);
            init_error = "Cannot initialize DoH HTTP/2 multi handle";
            initialized = true;
            init_cv.notify_one();
            return;
        }
        (void)curl_multi_setopt(multi, CURLMOPT_PIPELINING, static_cast<long>(CURLPIPE_MULTIPLEX));
        (void)curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, 2L);
        (void)curl_multi_setopt(multi, CURLMOPT_MAX_CONCURRENT_STREAMS, 100L);
        (void)curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, 32L);
        {
            std::lock_guard lock(multi_wake_mutex_);
            multi_ = multi;
        }
        {
            std::lock_guard lock(init_mutex);
            initialized = true;
            init_cv.notify_one();
        }

        std::unordered_map<CURL*, std::shared_ptr<Job>> active;
        for (;;) {
            std::deque<std::shared_ptr<Job>> incoming;
            bool should_stop = false;
            {
                std::lock_guard lock(mutex_);
                incoming.swap(pending_);
                should_stop = stopping_;
            }
            for (auto& job : incoming) {
                if (should_stop || job->cancelled.load(std::memory_order_acquire)) {
                    complete_job(job, CURLE_ABORTED_BY_CALLBACK);
                    continue;
                }
                const CURLMcode added = curl_multi_add_handle(multi, job->easy);
                if (added != CURLM_OK) {
                    complete_job(job, CURLE_FAILED_INIT, curl_multi_strerror(added));
                    continue;
                }
                active.emplace(job->easy, std::move(job));
            }

            if (should_stop) {
                for (auto& [easy, job] : active) {
                    (void)curl_multi_remove_handle(multi, easy);
                    complete_job(job, CURLE_ABORTED_BY_CALLBACK);
                }
                active.clear();
                break;
            }

            for (auto it = active.begin(); it != active.end();) {
                if (it->second->cancelled.load(std::memory_order_acquire)) {
                    (void)curl_multi_remove_handle(multi, it->first);
                    complete_job(it->second, CURLE_ABORTED_BY_CALLBACK);
                    it = active.erase(it);
                } else {
                    ++it;
                }
            }

            int running = 0;
            const CURLMcode performed = curl_multi_perform(multi, &running);
            if (performed != CURLM_OK) {
                const std::string err = curl_multi_strerror(performed);
                for (auto& [easy, job] : active) {
                    (void)curl_multi_remove_handle(multi, easy);
                    complete_job(job, CURLE_RECV_ERROR, err);
                }
                active.clear();
            } else {
                int messages = 0;
                while (const auto* msg = curl_multi_info_read(multi, &messages)) {
                    if (msg->msg != CURLMSG_DONE)
                        continue;
                    CURL* easy = msg->easy_handle;
                    const CURLcode code = msg->data.result;
                    (void)curl_multi_remove_handle(multi, easy);
                    if (const auto found = active.find(easy); found != active.end()) {
                        auto job = std::move(found->second);
                        active.erase(found);
                        complete_job(job, code);
                    }
                }
            }

            const int poll_ms = active.empty() ? 250 : 50;
            (void)curl_multi_poll(multi, nullptr, 0, poll_ms, nullptr);
        }

        {
            std::lock_guard lock(multi_wake_mutex_);
            multi_ = nullptr;
        }
        curl_multi_cleanup(multi);
        upstream_sockets_.clear();
    }

    uint64_t generation_;
    mutable std::mutex mutex_;
    std::condition_variable slot_cv_;
    size_t in_flight_ = 0;
    bool stopping_ = false;
    std::deque<std::shared_ptr<Job>> pending_;
    std::mutex multi_wake_mutex_;
    CURLM* multi_ = nullptr;
    std::map<curl_socket_t, std::unique_ptr<detail::NetworkUpstreamGuard>> upstream_sockets_;
    std::jthread loop_;
};

class SecureTransport final : public IDnsTransport {
public:
    explicit SecureTransport(bool dot) : dot_(dot) {
    }
    Packet exchange(const Packet& request, const Server& configured_server) override {
        const auto server = with_network_context(configured_server);
        if (!server.enabled)
            throw Error("SERVER_DISABLED", "DNS server is disabled");
        if (!server.timeout_ms || server.timeout_ms > 120000)
            throw Error("CONFIG", "Invalid timeout");
        const auto deadline = Clock::now() + std::chrono::milliseconds(server.timeout_ms);
        try {
            return exchange_attempt(request, server, deadline);
        } catch (const SecureAttemptError& error) {
            if (Clock::now() >= deadline)
                throw;
            detail::check_cancelled();
            if (!dot_) {
                if (!error.retryable)
                    throw;
                return exchange_attempt(request, server, deadline);
            }
            if (error.code != "TLS" && error.code != "TLS_HTTP" && error.code != "CONNECT" &&
                error.code != "DNS_EOF")
                throw;
            return exchange_attempt(request, server, deadline);
        } catch (const Error& error) {
            if (!dot_ || Clock::now() >= deadline)
                throw;
            detail::check_cancelled();
            if (error.code != "TLS" && error.code != "TLS_HTTP" && error.code != "CONNECT" &&
                error.code != "DNS_EOF")
                throw;
            return exchange_attempt(request, server, deadline);
        }
    }

private:
    static std::string build_resolve_entry(const std::string& host,
                                           const std::string& port,
                                           const std::vector<std::string>& endpoints,
                                           uint32_t& out_scope6,
                                           std::string& out_diagnostic_endpoint) {
        std::string addresses;
        for (const auto& raw : endpoints) {
            const auto parsed = parse_numeric_endpoint(raw);
            if (!out_scope6 && parsed.scope6)
                out_scope6 = parsed.scope6;
            if (out_diagnostic_endpoint.empty())
                out_diagnostic_endpoint = parsed.address + ':' + port;
            if (!addresses.empty())
                addresses += ',';
            addresses += parsed.address.find(':') == std::string::npos
                             ? parsed.address
                             : "[" + parsed.address + "]";
        }
        return host + ":" + port + ":" + addresses;
    }

    std::vector<std::string> resolve_endpoints(const Server& server,
                                               const std::string& host,
                                               Clock::time_point deadline) {
        if (!server.ip.empty())
            return {server.ip};
        if (platform::is_numeric_ip(host))
            return {host};
        auto bootstrap_servers = server.bootstrap;
        if (bootstrap_servers.empty() && server.use_system_bootstrap) {
            if (server.route.interface_id.empty())
                bootstrap_servers = platform::system_dns_servers();
            else {
                const auto network = NetworkMonitor::shared().snapshot();
                const auto* info = find_interface(*network, server.route.interface_id);
                if (!info || !info->up)
                    throw Error("INTERFACE_DOWN", "Bootstrap interface is unavailable");
                bootstrap_servers = select_bootstrap_dns_servers({*info});
            }
        }
        if (!bootstrap_servers.empty())
            return bootstrap_endpoints(server, host, bootstrap_servers, deadline);
        throw Error("BOOTSTRAP",
                    "Secure upstream requires a numeric endpoint prepared before interception "
                    "or an explicit bootstrap resolver");
    }

    static std::string build_pins(const Server& server) {
        std::string pins;
        for (const auto& pin : server.hashes) {
            if (!pin.starts_with("sha256//") || pin.size() != 52)
                throw Error("TLS_PIN", "Only sha256// base64 SPKI pins are supported");
            if (!pins.empty())
                pins += ';';
            pins += pin;
        }
        return pins;
    }

    Packet
    exchange_attempt(const Packet& request, const Server& server, Clock::time_point deadline) {
        const auto question = parse_question(request);
        if (question.flags & 0x8000)
            throw Error("DNS_MALFORMED", "Expected query");
        const std::string url = dot_ ? "https://" + normalize_host(server.hostname) + ":" +
                                           std::to_string(server.port ? server.port : 853) + "/"
                                     : server.url;
        Url parsed(url);
        if (parsed.get(CURLUPART_SCHEME) != "https" || !parsed.get(CURLUPART_USER).empty() ||
            !parsed.get(CURLUPART_PASSWORD).empty() || !parsed.get(CURLUPART_FRAGMENT).empty())
            throw Error("ENDPOINT", "Secure DNS URL must be HTTPS without credentials or fragment");
        const auto host = parsed.get(CURLUPART_HOST);
        const auto port = parsed.get(CURLUPART_PORT, CURLU_DEFAULT_PORT);
        if (host.empty() || port.empty())
            throw Error("ENDPOINT", "Missing HTTPS host/port");
        const std::string pins = build_pins(server);
        const auto endpoints = resolve_endpoints(server, host, deadline);
        uint32_t scope6 = 0;
        std::string diagnostic_endpoint;
        const std::string resolve_spec =
            build_resolve_entry(host, port, endpoints, scope6, diagnostic_endpoint);
        List resolve;
        resolve.add(resolve_spec);

        if (dot_)
            return exchange_dot(
                request, question, server, url, pins, resolve, scope6, diagnostic_endpoint, deadline);
        return exchange_doh(
            request, question, server, url, pins, resolve, scope6, diagnostic_endpoint, deadline);
    }

    Packet exchange_dot(const Packet& request,
                        const Question& question,
                        const Server& server,
                        const std::string& url,
                        const std::string& pins,
                        const List& resolve,
                        uint32_t scope6,
                        const std::string& diagnostic_endpoint,
                        Clock::time_point deadline) {
        auto lease = acquire_dot(server, deadline);
        auto& handle = *lease->entry->handle;
        handle.route = server.route;
        handle.diagnostic_endpoint = diagnostic_endpoint;
        handle.set(CURLOPT_URL, url.c_str());
        handle.set(CURLOPT_PROTOCOLS_STR, "https");
        handle.set(CURLOPT_SSL_VERIFYPEER, 1L);
        handle.set(CURLOPT_SSL_VERIFYHOST, 2L);
        handle.set(CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
        handle.set(CURLOPT_FOLLOWLOCATION, 0L);
        handle.set(CURLOPT_NOSIGNAL, 1L);
        handle.set(CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_1_1));
        handle.set(CURLOPT_MAXAGE_CONN, 30L);
        handle.set(CURLOPT_MAXLIFETIME_CONN, 300L);
        handle.set(CURLOPT_SSL_ENABLE_ALPN, 0L);
        handle.set(CURLOPT_ADDRESS_SCOPE,
                   static_cast<long>(scope6 ? scope6 : server.route.scope6));
        handle.set(CURLOPT_RESOLVE, resolve.value);
        if (!pins.empty())
            handle.set(CURLOPT_PINNEDPUBLICKEY, pins.c_str());
        apply_test_ca_if_configured(handle.value);
        const long timeout_ms = static_cast<long>(remaining(deadline));
        handle.set(CURLOPT_TIMEOUT_MS, timeout_ms);
        handle.set(CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
        handle.set(CURLOPT_CONNECT_ONLY, 1L);
        handle.perform();
        Packet framed{static_cast<uint8_t>(request.size() >> 8),
                      static_cast<uint8_t>(request.size())};
        framed.insert(framed.end(), request.begin(), request.end());
        transfer(handle.value, framed.data(), framed.size(), true, deadline);
        uint8_t prefix[2]{};
        transfer(handle.value, prefix, 2, false, deadline);
        const size_t length = static_cast<size_t>((prefix[0] << 8) | prefix[1]);
        if (length < 12)
            throw Error("DNS_MALFORMED", "Invalid DoT DNS length");
        Packet response(length);
        transfer(handle.value, response.data(), response.size(), false, deadline);
        if (parse_response(response, question).truncated)
            throw Error("DNS_TRUNCATED", "Truncated secure DNS response");
        return response;
    }

    Packet exchange_doh(const Packet& request,
                        const Question& question,
                        const Server& server,
                        const std::string& url,
                        const std::string& pins,
                        const List& resolve,
                        uint32_t scope6,
                        const std::string& diagnostic_endpoint,
                        Clock::time_point deadline) {
        auto dispatcher = acquire_doh_dispatcher(server.route);
        if (!dispatcher->try_acquire_slot(deadline))
            throw Error("TIMEOUT", "DoH connection pool is busy");
        struct SlotRelease {
            std::shared_ptr<DohMultiDispatcher> owner;
            ~SlotRelease() {
                owner->release_slot();
            }
        } slot_guard{dispatcher};

        auto job = std::make_shared<DohMultiDispatcher::Job>();
        job->route = server.route;
        job->easy = curl_easy_init();
        if (!job->easy)
            throw Error("MEMORY", "Cannot initialize DoH request handle");
        dispatcher->attach_callbacks(*job);

        auto set = [&](CURLoption option, auto v) {
            curl_check(curl_easy_setopt(job->easy, option, v));
        };
        set(CURLOPT_URL, url.c_str());
        set(CURLOPT_PROTOCOLS_STR, "https");
        set(CURLOPT_SSL_VERIFYPEER, 1L);
        set(CURLOPT_SSL_VERIFYHOST, 2L);
        set(CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
        set(CURLOPT_FOLLOWLOCATION, 0L);
        set(CURLOPT_NOSIGNAL, 1L);
        set(CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_2TLS));
        set(CURLOPT_PIPEWAIT, 1L);
        set(CURLOPT_MAXAGE_CONN, 30L);
        set(CURLOPT_MAXLIFETIME_CONN, 300L);
        set(CURLOPT_SSL_ENABLE_ALPN, 1L);
        set(CURLOPT_ADDRESS_SCOPE, static_cast<long>(scope6 ? scope6 : server.route.scope6));
        set(CURLOPT_RESOLVE, resolve.value);
        if (!pins.empty())
            set(CURLOPT_PINNEDPUBLICKEY, pins.c_str());
        apply_test_ca_if_configured(job->easy);

        List headers;
        headers.add("Content-Type: application/dns-message");
        headers.add("Accept: application/dns-message");
        Packet response;
        set(CURLOPT_HTTPHEADER, headers.value);
        set(CURLOPT_POST, 1L);
        set(CURLOPT_POSTFIELDS, reinterpret_cast<const char*>(request.data()));
        set(CURLOPT_POSTFIELDSIZE, static_cast<long>(request.size()));
        set(CURLOPT_WRITEFUNCTION, &receive_body);
        set(CURLOPT_WRITEDATA, &response);
        const long timeout_ms = static_cast<long>(remaining(deadline));
        set(CURLOPT_TIMEOUT_MS, timeout_ms);
        set(CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);

        dispatcher->execute(job);
        if (job->result != CURLE_OK)
            throw_classified_curl_error(job->easy,
                                        job->result,
                                        job->error_buffer,
                                        diagnostic_endpoint,
                                        server.route,
                                        job->socket_failure,
                                        true);

        long status = 0;
        curl_check(curl_easy_getinfo(job->easy, CURLINFO_RESPONSE_CODE, &status));
        if (status != 200)
            throw Error("HTTP_STATUS", "DoH HTTP status " + std::to_string(status));
        char* content_type = nullptr;
        curl_check(curl_easy_getinfo(job->easy, CURLINFO_CONTENT_TYPE, &content_type));
        const std::string_view raw_mime = content_type ? std::string_view(content_type) : "";
        if (!detail::is_dns_message_content_type(raw_mime))
            throw Error("HTTP_CONTENT_TYPE",
                        "DoH response Content-Type must be application/dns-message (received: \"" +
                            std::string(raw_mime) + "\" from " + url + ")");
        if (parse_response(response, question).truncated)
            throw Error("DNS_TRUNCATED", "Truncated secure DNS response");
        return response;
    }

    std::shared_ptr<DohMultiDispatcher> acquire_doh_dispatcher(const NetworkRoute& route) {
        const auto key = network_route_key(route);
        std::lock_guard lock(doh_mutex_);
        for (auto it = doh_dispatchers_.begin(); it != doh_dispatchers_.end();) {
            if (it->first != key && it->second->generation() != route.generation &&
                it->second->idle())
                it = doh_dispatchers_.erase(it);
            else
                ++it;
        }
        if (const auto found = doh_dispatchers_.find(key); found != doh_dispatchers_.end())
            return found->second;
        while (doh_dispatchers_.size() >= 16) {
            const auto idle_it = std::find_if(
                doh_dispatchers_.begin(), doh_dispatchers_.end(), [](const auto& item) {
                    return item.second->idle();
                });
            if (idle_it == doh_dispatchers_.end())
                break;
            doh_dispatchers_.erase(idle_it);
        }
        auto dispatcher = std::make_shared<DohMultiDispatcher>(route.generation);
        doh_dispatchers_.emplace(key, dispatcher);
        return dispatcher;
    }

    struct BootstrapState {
        bool refreshing = false;
        std::vector<std::string> endpoints;
        std::exception_ptr failure;
        Clock::time_point expires{}, retry_after{};
        std::condition_variable changed;
    };
    std::vector<std::string> bootstrap_endpoints(const Server& server,
                                                 const std::string& host,
                                                 const std::vector<std::string>& resolvers,
                                                 Clock::time_point deadline) {
        auto key = host + '|' + network_route_key(server.route);
        for (const auto& resolver : resolvers)
            key += '|' + resolver;
        std::shared_ptr<BootstrapState> state;
        {
            std::unique_lock lock(bootstrap_mutex_);
            for (auto item = bootstrap_.begin(); item != bootstrap_.end();) {
                if (item->second.use_count() == 1 && !item->second->refreshing &&
                    item->second->expires <= Clock::now() &&
                    item->second->retry_after <= Clock::now())
                    item = bootstrap_.erase(item);
                else
                    ++item;
            }
            if (bootstrap_.size() >= 128 && !bootstrap_.contains(key))
                throw Error("BOOTSTRAP_BUSY", "Bootstrap cache is at capacity");
            auto& slot = bootstrap_[key];
            if (!slot)
                slot = std::make_shared<BootstrapState>();
            state = slot;
            for (;;) {
                if (!state->endpoints.empty() && state->expires > Clock::now())
                    return state->endpoints;
                if (state->failure && state->retry_after > Clock::now())
                    std::rethrow_exception(state->failure);
                if (!state->refreshing) {
                    state->refreshing = true;
                    break;
                }
                if (detail::wait_until_change(state->changed, lock, deadline) ==
                    std::cv_status::timeout)
                    throw Error("TIMEOUT", "Bootstrap refresh is busy");
            }
        }
        try {
            auto transport = make_transport(Protocol::udp);
            const auto resolved =
                detail::resolve_bootstrap(server, host, resolvers, deadline, *transport);
            auto endpoints = resolved.endpoints.empty()
                                 ? std::vector<std::string>{resolved.endpoint}
                                 : resolved.endpoints;
            {
                std::lock_guard lock(bootstrap_mutex_);
                state->endpoints = endpoints;
                state->failure = nullptr;
                state->expires = Clock::now() + std::chrono::seconds(resolved.ttl);
                state->refreshing = false;
            }
            state->changed.notify_all();
            return endpoints;
        } catch (const Error& error) {
            const bool cancelled = error.code == "CANCELLED";
            {
                std::lock_guard lock(bootstrap_mutex_);
                state->refreshing = false;
                if (!cancelled) {
                    state->failure = std::current_exception();
                    state->retry_after = Clock::now() + std::chrono::seconds(1);
                }
            }
            state->changed.notify_all();
            throw;
        } catch (...) {
            {
                std::lock_guard lock(bootstrap_mutex_);
                state->refreshing = false;
                state->failure = std::current_exception();
                state->retry_after = Clock::now() + std::chrono::seconds(1);
            }
            state->changed.notify_all();
            throw;
        }
    }

    std::mutex bootstrap_mutex_;
    std::map<std::string, std::shared_ptr<BootstrapState>> bootstrap_;
    bool dot_;

    std::mutex doh_mutex_;
    std::map<std::string, std::shared_ptr<DohMultiDispatcher>> doh_dispatchers_;

    struct Entry {
        bool busy = false;
        uint64_t generation = 0;
        std::unique_ptr<CurlHandle> handle = std::make_unique<CurlHandle>();
    };
    struct Lease {
        SecureTransport& owner;
        std::shared_ptr<Entry> entry;
        Lease(SecureTransport& value, std::shared_ptr<Entry> selected)
            : owner(value), entry(std::move(selected)) {
        }
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        ~Lease() {
            entry->handle->reset();
            std::lock_guard lock(owner.pool_mutex_);
            entry->busy = false;
            owner.pool_changed_.notify_one();
        }
    };
    std::unique_ptr<Lease> acquire_dot(const Server& server, Clock::time_point deadline) {
        std::string key = server.url + '|' + server.ip + '|' + std::to_string(server.port) + '|' +
                          server.hostname;
        key += '|' + network_route_key(server.route);
        for (const auto& bootstrap : server.bootstrap)
            key += '|' + bootstrap;
        for (const auto& hash : server.hashes)
            key += '|' + hash;
        std::unique_lock lock(pool_mutex_);
        for (auto item = pool_.begin(); item != pool_.end();) {
            const bool stale =
                std::all_of(item->second.begin(), item->second.end(), [&](const auto& entry) {
                    return !entry->busy && entry->generation != server.route.generation;
                });
            if (stale)
                item = pool_.erase(item);
            else
                ++item;
        }
        for (;;) {
            detail::limit_idle_pool(pool_, key);
            auto& entries = pool_[key];
            const auto found = std::find_if(
                entries.begin(), entries.end(), [](const auto& entry) { return !entry->busy; });
            if (found != entries.end()) {
                (*found)->busy = true;
                return std::make_unique<Lease>(*this, *found);
            }
            if (entries.size() < 4) {
                auto entry = std::make_shared<Entry>();
                entry->generation = server.route.generation;
                entry->busy = true;
                entries.push_back(entry);
                return std::make_unique<Lease>(*this, std::move(entry));
            }
            if (detail::wait_until_change(pool_changed_, lock, deadline) == std::cv_status::timeout)
                throw Error("TIMEOUT", "DoT connection pool is busy");
        }
    }
    std::mutex pool_mutex_;
    std::condition_variable pool_changed_;
    std::map<std::string, std::vector<std::shared_ptr<Entry>>> pool_;
};
} // namespace

bool detail::is_dns_message_content_type(std::string_view header) {
    const auto semicolon = header.find(';');
    if (semicolon != std::string_view::npos)
        header = header.substr(0, semicolon);
    while (!header.empty() &&
           (header.front() == ' ' || header.front() == '\t' || header.front() == '\r' ||
            header.front() == '\n'))
        header.remove_prefix(1);
    while (!header.empty() &&
           (header.back() == ' ' || header.back() == '\t' || header.back() == '\r' ||
            header.back() == '\n'))
        header.remove_suffix(1);
    constexpr std::string_view expected = "application/dns-message";
    if (header.size() != expected.size())
        return false;
    for (size_t i = 0; i < expected.size(); ++i) {
        char c = header[i];
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + 32);
        if (c != expected[i])
            return false;
    }
    return true;
}

detail::BootstrapResult detail::resolve_bootstrap(const Server& server,
                                                  const std::string& host,
                                                  const std::vector<std::string>& resolvers,
                                                  Clock::time_point deadline,
                                                  IDnsTransport& transport) {
    std::string failure = "no usable resolver";
    size_t attempts_left = resolvers.size() * 2;
    // Try every resolver for A before starting AAAA. A dead first resolver must
    // not spend the entire request deadline before a working fallback is tried.
    for (uint16_t type : {uint16_t{1}, uint16_t{28}}) {
        for (const auto& resolver : resolvers) {
            Server plain;
            plain.ip = resolver;
            plain.name = "bootstrap";
            plain.route = server.route;
            try {
                const auto budget = remaining(deadline);
                const size_t share = std::max<size_t>(1, budget / attempts_left);
                plain.timeout_ms = static_cast<uint32_t>(
                    std::min<size_t>(budget, std::min<size_t>(1000, std::max<size_t>(250, share))));
                --attempts_left;
                const auto request = make_query(host, type);
                const auto response = transport.exchange(request, plain);
                const auto answer = parse_response(response, parse_question(request));
                if (!answer.rcode && !answer.addresses.empty()) {
                    std::vector<std::string> unique;
                    for (const auto& address : answer.addresses) {
                        if (std::find(unique.begin(), unique.end(), address) == unique.end())
                            unique.push_back(address);
                        if (unique.size() >= 8)
                            break;
                    }
                    return {unique.front(), std::min<uint32_t>(answer.cache_ttl, 60), std::move(unique)};
                }
                failure = "resolver=" + resolver + " type=" + dns_type_name(type) +
                          " RCODE=" + std::to_string(answer.rcode) + " no usable address";
            } catch (const Error& error) {
                if (error.code == "CANCELLED")
                    throw;
                failure = "resolver=" + resolver + " type=" + dns_type_name(type) +
                          " error=" + error.code + ": " + error.what();
                if (Clock::now() >= deadline)
                    break;
            }
        }
        if (Clock::now() >= deadline)
            break;
    }
    throw Error("BOOTSTRAP",
                "host=" + host + " context=" + network_route_key(server.route) +
                    " upstream bootstrap failed: " + failure);
}

void prepare_secure_endpoints(Config& config, uint32_t retry_ms) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(retry_ms);
    std::map<std::string, std::string> resolved;

    for (auto& server : config.servers) {
        if (!server.enabled ||
            (server.protocol != Protocol::doh && server.protocol != Protocol::dot) ||
            !server.ip.empty() || !server.bootstrap.empty())
            continue;
        std::string hostname;
        if (server.protocol == Protocol::dot)
            hostname = normalize_host(server.hostname);
        else {
            Url parsed(server.url);
            if (parsed.get(CURLUPART_SCHEME) != "https")
                throw Error("ENDPOINT", "Secure DNS URL must use HTTPS");
            hostname = parsed.get(CURLUPART_HOST);
        }
        if (hostname.empty())
            throw Error("ENDPOINT", "Secure DNS endpoint hostname is empty");
        if (hostname.size() > 2 && hostname.front() == '[' && hostname.back() == ']')
            hostname = hostname.substr(1, hostname.size() - 2);

        if (platform::is_numeric_ip(hostname)) {
            server.ip = hostname;
            continue;
        }

        if (const auto cached = resolved.find(hostname); cached != resolved.end()) {
            server.ip = cached->second;
            continue;
        }

        for (;;) {
            try {
                const auto addresses = platform::resolve_host(hostname);
                if (addresses.empty())
                    throw Error("BOOTSTRAP",
                                "Secure upstream hostname has no usable address: " + hostname);
                server.ip = addresses.front();
                resolved.emplace(hostname, server.ip);
                break;
            } catch (const Error& error) {
                if (error.code != "BOOTSTRAP" || !retry_ms || Clock::now() >= deadline)
                    throw;
                const auto remaining =
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
                if (remaining.count() <= 0)
                    throw;
                std::this_thread::sleep_for(std::min(std::chrono::milliseconds(1000), remaining));
            }
        }
    }
}

std::unique_ptr<IDnsTransport> make_secure_transport(Protocol protocol) {
    return std::make_unique<SecureTransport>(protocol == Protocol::dot);
}
} // namespace nd
