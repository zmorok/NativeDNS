#include <nativedns/tcp_dns_proxy.hpp>
#include "../../bounded_executor.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <atomic>
#include <map>
#include <set>
#include <thread>

namespace nd::detail {
namespace {
struct Socket {
    SOCKET value = INVALID_SOCKET;
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket() = default;
    explicit Socket(SOCKET socket) : value(socket) {}
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};

void set_timeout(SOCKET socket) {
    constexpr DWORD timeout_ms = 5000;
    if (setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout_ms),sizeof(timeout_ms)) ||
        setsockopt(socket,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout_ms),sizeof(timeout_ms)))
        throw Error("TCP_PROXY_IO","Cannot set client timeout: "+std::to_string(WSAGetLastError()));
}

bool receive_exact(SOCKET socket,uint8_t* bytes,size_t size,bool allow_clean_eof) {
    size_t at=0;
    while(at<size) {
        const int received=recv(socket,reinterpret_cast<char*>(bytes+at),static_cast<int>(size-at),0);
        if(!received&&allow_clean_eof&&at==0) return false;
        if(received<=0) throw Error(received?"TCP_PROXY_IO":"DNS_EOF",received?"TCP proxy receive failed: "+std::to_string(WSAGetLastError()):"Client TCP frame incomplete");
        at+=static_cast<size_t>(received);
    }
    return true;
}

void send_exact(SOCKET socket,const uint8_t* bytes,size_t size) {
    size_t at=0;
    while(at<size) {
        const int sent=send(socket,reinterpret_cast<const char*>(bytes+at),static_cast<int>(size-at),0);
        if(sent<=0) throw Error("TCP_PROXY_IO","TCP proxy send failed: "+std::to_string(WSAGetLastError()));
        at+=static_cast<size_t>(sent);
    }
}

std::string peer_ip(const sockaddr_storage& peer) {
    char text[INET6_ADDRSTRLEN]{};
    const int family=peer.ss_family;
    const void* address=family==AF_INET
        ? static_cast<const void*>(&reinterpret_cast<const sockaddr_in*>(&peer)->sin_addr)
        : static_cast<const void*>(&reinterpret_cast<const sockaddr_in6*>(&peer)->sin6_addr);
    if((family!=AF_INET&&family!=AF_INET6)||!InetNtopA(family,address,text,sizeof(text)))
        throw Error("TCP_PROXY_IO","Cannot read reflected DNS destination");
    return text;
}
}

struct TcpDnsProxy::Impl {
    const Router& router;
    Logger& logger;
    uint16_t intercepted_port;
    std::atomic<bool> running=false;
    SOCKET ipv4=INVALID_SOCKET,ipv6=INVALID_SOCKET;
    uint16_t port=0;
    bool winsock=false;
    std::jthread accept4,accept6;
    std::mutex clients_mutex;
    std::set<SOCKET> clients;
    BoundedExecutor handlers;
    std::mutex expected_mutex;
    std::map<std::pair<std::string,uint16_t>,std::chrono::steady_clock::time_point> expected;

    void prune_expected(std::chrono::steady_clock::time_point now) {
        for(auto item=expected.begin();item!=expected.end();) {
            if(item->second<=now) item=expected.erase(item); else ++item;
        }
    }

    Impl(const Router& value,Logger& output,uint16_t target):router(value),logger(output),intercepted_port(target) {
        if(!intercepted_port) throw Error("PORT","Intercepted TCP DNS port must be 1..65535");
    }

    Packet process(const Packet& request,const Server& original) {
        auto result=router.route(request,original);
        if(result.disposition==Disposition::silent_drop) return {};
        if(result.disposition==Disposition::forward_original) {
            logger.write(Level::normal,"DNS_BYPASS","Forwarding TCP request to original destination "+original.ip);
            return router.exchange(request,original);
        }
        return result.packet;
    }

    bool consume_expected(const std::string& address,uint16_t client_port) {
        const auto now=std::chrono::steady_clock::now();
        std::lock_guard lock(expected_mutex);
        prune_expected(now);
        const auto found=expected.find({address,client_port});
        if(found==expected.end()) return false;
        expected.erase(found);
        return true;
    }

    void handle(std::shared_ptr<Socket> owned,sockaddr_storage peer) {
        const SOCKET client=owned->value;
        try {
            set_timeout(client);
            Server original;
            original.name="Original intercepted TCP resolver";
            original.protocol=Protocol::tcp;
            original.ip=peer_ip(peer);
            original.port=intercepted_port;
            const uint16_t client_port=ntohs(peer.ss_family==AF_INET
                ? reinterpret_cast<const sockaddr_in*>(&peer)->sin_port
                : reinterpret_cast<const sockaddr_in6*>(&peer)->sin6_port);
            if(!consume_expected(original.ip,client_port)) {
                logger.write(Level::errors_only,"TCP_PROXY_REJECT","Rejected connection without a captured SYN");
                return;
            }
            logger.write(Level::debug,"TCP_PROXY_ACCEPT","destination="+original.ip+":"+std::to_string(intercepted_port));
            for(;;) {
                uint8_t prefix[2]{};
                if(!receive_exact(client,prefix,sizeof(prefix),true)) break;
                const size_t length=static_cast<size_t>((prefix[0]<<8)|prefix[1]);
                if(length<12) throw Error("DNS_MALFORMED","Client TCP DNS frame too short");
                Packet request(length);
                receive_exact(client,request.data(),request.size(),false);
                const auto response=process(request,original);
                if(response.empty()) continue;
                if(response.size()>65535) throw Error("DNS_MALFORMED","TCP DNS response is too large");
                const uint8_t response_prefix[]{static_cast<uint8_t>(response.size()>>8),static_cast<uint8_t>(response.size())};
                send_exact(client,response_prefix,sizeof(response_prefix));
                send_exact(client,response.data(),response.size());
            }
        } catch(const Error& error) {
            if(running) logger.write(Level::errors_only,error.code,error.what());
        } catch(const std::exception& error) {
            if(running) logger.write(Level::errors_only,"TCP_PROXY_IO",error.what());
        }
        std::lock_guard lock(clients_mutex);
        clients.erase(client);
    }

    void accept_loop(SOCKET listener) {
        try {
            while(running) {
                sockaddr_storage peer{};
                int peer_size=sizeof(peer);
                const SOCKET client=accept(listener,reinterpret_cast<sockaddr*>(&peer),&peer_size);
                if(client==INVALID_SOCKET) {
                    if(!running) break;
                    logger.write(Level::errors_only,"TCP_PROXY_IO","TCP proxy accept failed: "+std::to_string(WSAGetLastError()));
                    continue;
                }
                auto owned=std::make_shared<Socket>(client);
                { std::lock_guard lock(clients_mutex); clients.insert(client); }
                if(!handlers.submit([this,owned=std::move(owned),peer]{handle(owned,peer);})) {
                    { std::lock_guard lock(clients_mutex); clients.erase(client); }
                    logger.write(Level::errors_only,"TCP_PROXY_BUSY","Transparent TCP proxy connection limit reached");
                }
            }
        } catch(const std::exception& error) {
            if(running) logger.write(Level::errors_only,"TCP_PROXY_IO",error.what());
        }
    }

    void close_listeners() {
        if(ipv4!=INVALID_SOCKET) { shutdown(ipv4,SD_BOTH); closesocket(ipv4); ipv4=INVALID_SOCKET; }
        if(ipv6!=INVALID_SOCKET) { shutdown(ipv6,SD_BOTH); closesocket(ipv6); ipv6=INVALID_SOCKET; }
    }
};

TcpDnsProxy::TcpDnsProxy(const Router& router,Logger& logger,uint16_t intercepted_port)
    :impl_(std::make_unique<Impl>(router,logger,intercepted_port)) {}
TcpDnsProxy::~TcpDnsProxy() { stop(); }

uint16_t TcpDnsProxy::start() {
    auto& p=*impl_;
    if(p.running.exchange(true)) throw Error("LIFECYCLE","TCP DNS proxy already running");
    try {
        WSADATA data{};
        if(WSAStartup(MAKEWORD(2,2),&data)) throw Error("SOCKET_INIT","TCP proxy WSAStartup failed");
        p.winsock=true;
        int last_error=0;
        for(unsigned attempt=0;attempt<128;++attempt) {
            uint32_t random=0;
            if(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&random),sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)
                throw Error("TCP_PROXY_IO","Cannot choose TCP proxy port");
            const uint16_t candidate=static_cast<uint16_t>(20000+(random%28000));
            p.ipv4=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
            p.ipv6=socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP);
            if(p.ipv4==INVALID_SOCKET||p.ipv6==INVALID_SOCKET) throw Error("TCP_PROXY_IO","Cannot create TCP proxy listeners");
            BOOL exclusive=TRUE,ipv6_only=TRUE;
            if(setsockopt(p.ipv4,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive)) ||
               setsockopt(p.ipv6,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive)) ||
               setsockopt(p.ipv6,IPPROTO_IPV6,IPV6_V6ONLY,reinterpret_cast<const char*>(&ipv6_only),sizeof(ipv6_only)))
                throw Error("TCP_PROXY_IO","Cannot secure TCP proxy listener");
            // Reflection preserves the original resolver address, so the local
            // stack cannot reach this listener through a loopback-only bind.
            // Exposure is constrained by the per-run firewall rule and every
            // accepted tuple must also have a recently captured SYN.
            sockaddr_in address4{}; address4.sin_family=AF_INET; address4.sin_port=htons(candidate); address4.sin_addr.s_addr=htonl(INADDR_ANY);
            sockaddr_in6 address6{}; address6.sin6_family=AF_INET6; address6.sin6_port=htons(candidate); address6.sin6_addr=in6addr_any;
            if(!bind(p.ipv4,reinterpret_cast<sockaddr*>(&address4),sizeof(address4)) &&
               !bind(p.ipv6,reinterpret_cast<sockaddr*>(&address6),sizeof(address6)) &&
               !listen(p.ipv4,64) && !listen(p.ipv6,64)) { p.port=candidate; break; }
            last_error=WSAGetLastError();
            p.close_listeners();
        }
        if(!p.port) throw Error("TCP_PROXY_BIND","Cannot bind TCP proxy listener pair: "+std::to_string(last_error));
        p.handlers.start(32,128);
        p.accept4=std::jthread([&p]{p.accept_loop(p.ipv4);});
        p.accept6=std::jthread([&p]{p.accept_loop(p.ipv6);});
        return p.port;
    } catch(...) {
        p.running=false;
        p.close_listeners();
        if(p.accept4.joinable()) p.accept4.join();
        if(p.accept6.joinable()) p.accept6.join();
        p.handlers.stop();
        if(p.winsock) { WSACleanup(); p.winsock=false; }
        p.port=0;
        throw;
    }
}

void TcpDnsProxy::stop() {
    auto& p=*impl_;
    if(!p.running.exchange(false)) return;
    p.close_listeners();
    if(p.accept4.joinable()) p.accept4.join();
    if(p.accept6.joinable()) p.accept6.join();
    {
        std::lock_guard lock(p.clients_mutex);
        for(const auto client:p.clients) shutdown(client,SD_BOTH);
    }
    p.handlers.stop();
    { std::lock_guard lock(p.clients_mutex); p.clients.clear(); }
    { std::lock_guard lock(p.expected_mutex); p.expected.clear(); }
    if(p.winsock) { WSACleanup(); p.winsock=false; }
    p.port=0;
}

void TcpDnsProxy::expect_connection(std::string original_ip,uint16_t client_port) {
    if(original_ip.empty()||!client_port) throw Error("TCP_PROXY_IO","Invalid expected TCP connection");
    auto& p=*impl_;
    std::lock_guard lock(p.expected_mutex);
    p.prune_expected(std::chrono::steady_clock::now());
    p.expected[{std::move(original_ip),client_port}]=std::chrono::steady_clock::now()+std::chrono::seconds(5);
}

void TcpDnsProxy::forget_connection(const std::string& original_ip,uint16_t client_port) {
    if(original_ip.empty()||!client_port) return;
    auto& p=*impl_;
    std::lock_guard lock(p.expected_mutex);
    p.expected.erase({original_ip,client_port});
}

}
