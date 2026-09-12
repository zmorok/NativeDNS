#include <nativedns/interception.hpp>
#include "../../bounded_executor.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <thread>
#include <atomic>

namespace nd {
struct LocalProxy::Impl {
    std::shared_ptr<const Router> router;
    Server original;
    Logger& logger;
    uint16_t requested_port, bound_port = 0;
    std::atomic<State> state = State::stopped;
    mutable std::mutex lifecycle;
    HANDLE stop_event = nullptr;
    SOCKET udp = INVALID_SOCKET, tcp = INVALID_SOCKET;
    WSAEVENT udp_event = WSA_INVALID_EVENT, tcp_event = WSA_INVALID_EVENT;
    std::jthread udp_worker, tcp_worker;
    detail::BoundedExecutor udp_handlers, tcp_handlers;
    bool winsock = false;
    Impl(std::shared_ptr<const Router> r, Server o, Logger& l, uint16_t p) : router(std::move(r)),original(std::move(o)),logger(l),requested_port(p) {
        if (!router) throw Error("CONFIG","Local proxy requires a router");
        if (original.protocol != Protocol::udp && original.protocol != Protocol::tcp) throw Error("CONFIG","Original fallback path must be plain DNS");
        auto cfg = default_config(); auto server = original; server.id = 1; cfg.servers.push_back(server); validate(cfg);
    }
    void cleanup() {
        if (udp != INVALID_SOCKET) { closesocket(udp); udp = INVALID_SOCKET; }
        if (tcp != INVALID_SOCKET) { closesocket(tcp); tcp = INVALID_SOCKET; }
        if (udp_event != WSA_INVALID_EVENT) { WSACloseEvent(udp_event); udp_event = WSA_INVALID_EVENT; }
        if (tcp_event != WSA_INVALID_EVENT) { WSACloseEvent(tcp_event); tcp_event = WSA_INVALID_EVENT; }
        if (stop_event) { CloseHandle(stop_event); stop_event = nullptr; }
        if (winsock) { WSACleanup(); winsock = false; }
        bound_port = 0;
    }
    bool stopping() const { return WaitForSingleObject(stop_event,0) == WAIT_OBJECT_0; }
    bool wait(HANDLE event) const {
        const HANDLE events[]{stop_event,event};
        const DWORD result = WaitForMultipleObjects(2,events,FALSE,INFINITE);
        if (result == WAIT_OBJECT_0) return false;
        if (result != WAIT_OBJECT_0 + 1) throw Error("PROXY_IO","Socket event wait failed");
        return true;
    }
    Packet process(const Packet& request) {
        auto result = router->route(request,original);
        if (result.disposition == Disposition::silent_drop) return {};
        if (result.disposition == Disposition::forward_original) {
            logger.write(Level::normal,"DNS_BYPASS","Forwarding intact request to original fallback " + original.ip);
            return router->exchange(request,original);
        }
        return result.packet;
    }
    void handle_udp(Packet packet,sockaddr_storage client,int size) {
        try {
            const auto response = fit_udp_response(packet,process(packet));
            if (!response.empty() && sendto(udp,reinterpret_cast<const char*>(response.data()),static_cast<int>(response.size()),0,reinterpret_cast<sockaddr*>(&client),size) != static_cast<int>(response.size()))
                throw Error("PROXY_IO","UDP reply send failed");
        } catch (const Error& error) { logger.write(Level::errors_only,error.code,error.what()); }
        catch (const std::exception& error) { logger.write(Level::errors_only,"PROXY_IO",error.what()); }
    }
    void udp_loop() {
        try {
            while (wait(udp_event)) {
                WSANETWORKEVENTS events{};
                if (WSAEnumNetworkEvents(udp,udp_event,&events)) throw Error("PROXY_IO","UDP event enumeration failed");
                if (!(events.lNetworkEvents & FD_READ)) continue;
                Packet packet(65535); sockaddr_storage client{}; int size = sizeof(client);
                const int n = recvfrom(udp,reinterpret_cast<char*>(packet.data()),static_cast<int>(packet.size()),0,reinterpret_cast<sockaddr*>(&client),&size);
                if (n == SOCKET_ERROR) { if (WSAGetLastError() == WSAEWOULDBLOCK) continue; throw Error("PROXY_IO","UDP receive failed"); }
                packet.resize(static_cast<size_t>(n));
                if(!udp_handlers.submit([this,packet=std::move(packet),client,size]() mutable { handle_udp(std::move(packet),client,size); }))
                    logger.write(Level::errors_only,"PROXY_BUSY","Local UDP proxy queue is full; query dropped");
            }
        } catch (const std::exception& error) { logger.write(Level::errors_only,"PROXY_IO",error.what()); state = State::error; SetEvent(stop_event); }
    }
    void transfer(SOCKET socket, uint8_t* bytes, size_t length, bool send_bytes, std::chrono::steady_clock::time_point deadline) {
        size_t at = 0;
        while (at < length) {
            if (stopping()) throw Error("STOPPED","Proxy stopping");
            const auto left = std::chrono::duration_cast<std::chrono::microseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0) throw Error("TIMEOUT","Client TCP frame deadline");
            fd_set fds; FD_ZERO(&fds); FD_SET(socket,&fds);
            timeval timeout{static_cast<long>(left / 1000000),static_cast<long>(left % 1000000)};
            const auto ready = select(0,send_bytes ? nullptr : &fds,send_bytes ? &fds : nullptr,nullptr,&timeout);
            if (!ready) throw Error("TIMEOUT","Client TCP frame timeout");
            if (ready < 0) throw Error("PROXY_IO","Client TCP select failed");
            const int n = send_bytes ? send(socket,reinterpret_cast<const char*>(bytes + at),static_cast<int>(length - at),0)
                                     : recv(socket,reinterpret_cast<char*>(bytes + at),static_cast<int>(length - at),0);
            if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
            if (n <= 0) throw Error("DNS_EOF","Client TCP frame incomplete");
            at += static_cast<size_t>(n);
        }
    }
    void handle_client(SOCKET client) {
        struct ClientGuard { SOCKET value; ~ClientGuard() { closesocket(value); } } guard{client};
        try {
            if (WSAEventSelect(client,nullptr,0)) throw Error("PROXY_IO","Client event reset failed");
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            uint8_t prefix[2]{}; transfer(client,prefix,2,false,deadline);
            const auto length = static_cast<size_t>((prefix[0] << 8) | prefix[1]);
            if (length < 12) throw Error("DNS_MALFORMED","Client DNS frame too short");
            Packet request(length); transfer(client,request.data(),request.size(),false,deadline);
            auto response = process(request);
            if (!response.empty()) {
                Packet frame{static_cast<uint8_t>(response.size() >> 8),static_cast<uint8_t>(response.size())};
                frame.insert(frame.end(),response.begin(),response.end());
                transfer(client,frame.data(),frame.size(),true,std::chrono::steady_clock::now() + std::chrono::seconds(2));
            }
        } catch (const Error& error) { if(!stopping()) logger.write(Level::errors_only,error.code,error.what()); }
        catch (const std::exception& error) { if(!stopping()) logger.write(Level::errors_only,"PROXY_IO",error.what()); }
    }
    void tcp_loop() {
        try {
            while (wait(tcp_event)) {
                WSANETWORKEVENTS events{};
                if (WSAEnumNetworkEvents(tcp,tcp_event,&events)) throw Error("PROXY_IO","TCP event enumeration failed");
                if (!(events.lNetworkEvents & FD_ACCEPT)) continue;
                SOCKET client = accept(tcp,nullptr,nullptr);
                if (client == INVALID_SOCKET) { if (WSAGetLastError() == WSAEWOULDBLOCK) continue; throw Error("PROXY_IO","Accept failed"); }
                if(!tcp_handlers.submit([this,client] { handle_client(client); })) {
                    closesocket(client);
                    logger.write(Level::errors_only,"PROXY_BUSY","Local TCP proxy connection limit reached");
                }
            }
        } catch (const std::exception& error) { logger.write(Level::errors_only,"PROXY_IO",error.what()); state = State::error; SetEvent(stop_event); }
    }
};
LocalProxy::LocalProxy(std::shared_ptr<const Router> router, Server original, Logger& logger, uint16_t port)
    : impl_(std::make_unique<Impl>(std::move(router),std::move(original),logger,port)) {}
LocalProxy::~LocalProxy() { stop(); }
void LocalProxy::start() {
    auto& p = *impl_; std::lock_guard lock(p.lifecycle);
    if (p.state != State::stopped) throw Error("LIFECYCLE","Proxy is not stopped");
    p.state = State::starting;
    try {
        WSADATA data{}; if (WSAStartup(MAKEWORD(2,2),&data)) throw Error("SOCKET_INIT","Proxy WSAStartup failed"); p.winsock = true;
        p.stop_event = CreateEventW(nullptr,TRUE,FALSE,nullptr); p.udp_event = WSACreateEvent(); p.tcp_event = WSACreateEvent();
        if (!p.stop_event || p.udp_event == WSA_INVALID_EVENT || p.tcp_event == WSA_INVALID_EVENT) throw Error("PROXY_IO","Cannot create proxy events");
        int last_bind_error=0;
        const unsigned attempts=p.requested_port?1u:128u;
        for(unsigned attempt=0;attempt<attempts;++attempt) {
            p.udp=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); p.tcp=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
            if(p.udp==INVALID_SOCKET||p.tcp==INVALID_SOCKET) throw Error("PROXY_IO","Cannot create listeners");
            BOOL exclusive=TRUE;
            if(setsockopt(p.udp,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))||
               setsockopt(p.tcp,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive)))
                throw Error("PROXY_IO","Cannot secure listener binding");
            uint32_t random_port=0;
            if(!p.requested_port && BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&random_port),sizeof(random_port),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)
                throw Error("PROXY_IO","Cannot choose a secure random listener port");
            const uint16_t chosen=p.requested_port?p.requested_port:static_cast<uint16_t>(20000+(random_port%28000));
            sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(chosen);
            if(bind(p.tcp,reinterpret_cast<sockaddr*>(&address),sizeof(address))) {
                last_bind_error=WSAGetLastError(); closesocket(p.udp); closesocket(p.tcp); p.udp=INVALID_SOCKET; p.tcp=INVALID_SOCKET;
                if(p.requested_port) throw Error("PROXY_BIND","TCP bind failed: "+std::to_string(last_bind_error));
                continue;
            }
            int size=sizeof(address);
            if(getsockname(p.tcp,reinterpret_cast<sockaddr*>(&address),&size)) throw Error("PROXY_IO","Cannot inspect local port");
            const auto candidate=ntohs(address.sin_port);
            if((p.original.ip=="127.0.0.1"||p.original.ip=="::1")&&(p.original.port?p.original.port:53)==candidate) {
                closesocket(p.udp); closesocket(p.tcp); p.udp=INVALID_SOCKET; p.tcp=INVALID_SOCKET;
                if(p.requested_port) throw Error("LOOP","Original resolver points to local proxy");
                continue;
            }
            if(!listen(p.tcp,16)&&!bind(p.udp,reinterpret_cast<sockaddr*>(&address),sizeof(address))) { p.bound_port=candidate; break; }
            last_bind_error=WSAGetLastError(); closesocket(p.udp); closesocket(p.tcp); p.udp=INVALID_SOCKET; p.tcp=INVALID_SOCKET;
        }
        if(p.udp==INVALID_SOCKET||p.tcp==INVALID_SOCKET) throw Error("PROXY_BIND","Cannot bind UDP/TCP listener pair: "+std::to_string(last_bind_error));
        if (WSAEventSelect(p.udp,p.udp_event,FD_READ) || WSAEventSelect(p.tcp,p.tcp_event,FD_ACCEPT)) throw Error("PROXY_IO","Cannot register socket events");
        p.udp_handlers.start(8,1024); p.tcp_handlers.start(16,128);
        p.state = State::running;
        p.udp_worker = std::jthread([&p] { p.udp_loop(); }); p.tcp_worker = std::jthread([&p] { p.tcp_loop(); });
    } catch (...) {
        if (p.stop_event) SetEvent(p.stop_event);
        if (p.udp_worker.joinable()) p.udp_worker.join(); if (p.tcp_worker.joinable()) p.tcp_worker.join();
        p.udp_handlers.stop(); p.tcp_handlers.stop();
        p.cleanup(); p.state = State::error; throw;
    }
}
void LocalProxy::stop() {
    auto& p = *impl_; std::lock_guard lock(p.lifecycle);
    if (p.state == State::stopped) return;
    p.state = State::stopping; if (p.stop_event) SetEvent(p.stop_event);
    if (p.udp_worker.joinable()) p.udp_worker.join(); if (p.tcp_worker.joinable()) p.tcp_worker.join();
    p.udp_handlers.stop(); p.tcp_handlers.stop();
    p.cleanup(); p.state = State::stopped;
}
InterceptionStatus LocalProxy::status() const { std::lock_guard lock(impl_->lifecycle); return {impl_->state.load(),impl_->bound_port,false,true,true}; }
}
