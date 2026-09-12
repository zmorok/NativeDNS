#include <nativedns/interception.hpp>
#include <nativedns/platform.hpp>
#include "../../bounded_executor.hpp"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <thread>
#include <atomic>
#include <array>

namespace nd {
namespace {
class Fd {
public:
    int value=-1;
    Fd()=default; explicit Fd(int fd):value(fd){}
    ~Fd(){ reset(); }
    Fd(const Fd&)=delete; Fd& operator=(const Fd&)=delete;
    Fd(Fd&& other) noexcept:value(other.value){other.value=-1;}
    Fd& operator=(Fd&& other) noexcept { if(this!=&other){reset();value=other.value;other.value=-1;}return *this; }
    void reset(int fd=-1){if(value>=0)::close(value);value=fd;}
};
void sys_error(const char* what){ throw Error("PROXY_IO",std::string(what)+": "+std::strerror(errno)); }
void set_timeout(int fd,int seconds=2){ timeval tv{seconds,0}; if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv))<0||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv))<0) sys_error("setsockopt timeout"); }
bool recv_exact(int fd,uint8_t* data,size_t size,bool clean_eof=false){ size_t at=0; while(at<size){ const auto n=recv(fd,data+at,size-at,0); if(n==0){if(clean_eof&&at==0)return false;throw Error("DNS_EOF","Client TCP frame incomplete");} if(n<0){if(errno==EINTR)continue;sys_error("recv");} at+=static_cast<size_t>(n);} return true; }
void send_exact(int fd,const uint8_t* data,size_t size){ size_t at=0; while(at<size){const auto n=send(fd,data+at,size-at,MSG_NOSIGNAL);if(n<0){if(errno==EINTR)continue;sys_error("send");}if(!n)throw Error("DNS_EOF","Client connection closed");at+=static_cast<size_t>(n);} }
void reuse(int fd){int yes=1;if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes))<0)sys_error("SO_REUSEADDR");}
void v6_only(int fd){int yes=1;if(setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&yes,sizeof(yes))<0)sys_error("IPV6_V6ONLY");}
}

struct LocalProxy::Impl {
    std::shared_ptr<const Router> router;
    Server original;
    Logger& logger;
    uint16_t requested_port=0,bound_port=0;
    std::atomic<State> state=State::stopped;
    std::atomic_bool running=false;
    mutable std::mutex lifecycle;
    Fd udp4,tcp4,udp6,tcp6;
    std::jthread udp4_worker,tcp4_worker,udp6_worker,tcp6_worker;
    detail::BoundedExecutor udp_handlers,tcp_handlers;

    Impl(std::shared_ptr<const Router> r,Server o,Logger& l,uint16_t p):router(std::move(r)),original(std::move(o)),logger(l),requested_port(p){
        if(!router) throw Error("CONFIG","Local proxy requires a router");
        if(original.protocol!=Protocol::udp&&original.protocol!=Protocol::tcp) throw Error("CONFIG","Original fallback path must be plain DNS");
        auto cfg=default_config();auto server=original;server.id=1;cfg.servers.push_back(server);validate(cfg);
    }
    Packet process(const Packet& request){
        auto result=router->route(request,original);
        if(result.disposition==Disposition::silent_drop) return {};
        if(result.disposition==Disposition::forward_original){logger.write(Level::normal,"DNS_BYPASS","Forwarding intact request to original fallback "+original.ip);return router->exchange(request,original);}
        return result.packet;
    }
    void handle_udp(int fd,Packet packet,sockaddr_storage client,socklen_t size){
        try{const auto response=fit_udp_response(packet,process(packet));if(!response.empty()){const auto sent=sendto(fd,response.data(),response.size(),MSG_NOSIGNAL,reinterpret_cast<sockaddr*>(&client),size);if(sent!=static_cast<ssize_t>(response.size()))sys_error("UDP reply send");}}
        catch(const Error& e){logger.write(Level::errors_only,e.code,e.what());}
        catch(const std::exception& e){logger.write(Level::errors_only,"PROXY_IO",e.what());}
    }
    void udp_loop(int fd){
        while(running){
            sockaddr_storage client{};socklen_t size=sizeof(client);Packet packet(65535);
            const auto n=recvfrom(fd,packet.data(),packet.size(),0,reinterpret_cast<sockaddr*>(&client),&size);
            if(n<0){if(!running)break;if(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)continue;logger.write(Level::errors_only,"PROXY_IO",std::strerror(errno));state=State::error;break;}
            packet.resize(static_cast<size_t>(n));
            if(!udp_handlers.submit([this,fd,packet=std::move(packet),client,size]() mutable {handle_udp(fd,std::move(packet),client,size);}))
                logger.write(Level::errors_only,"PROXY_BUSY","Local UDP proxy queue is full; query dropped");
        }
    }
    void handle_client(int fd){
        Fd client(fd);set_timeout(fd);
        try{
            for(;;){uint8_t prefix[2]{};if(!recv_exact(fd,prefix,2,true))break;const size_t length=(static_cast<size_t>(prefix[0])<<8)|prefix[1];if(length<12)throw Error("DNS_MALFORMED","Client DNS frame too short");Packet request(length);recv_exact(fd,request.data(),request.size());auto response=process(request);if(response.empty())continue;uint8_t out[]{static_cast<uint8_t>(response.size()>>8),static_cast<uint8_t>(response.size())};send_exact(fd,out,2);send_exact(fd,response.data(),response.size());}
        } catch(const Error& e){if(running)logger.write(Level::errors_only,e.code,e.what());}
    }
    void tcp_loop(int fd){
        while(running){const int client=accept(fd,nullptr,nullptr);if(client<0){if(!running)break;if(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)continue;logger.write(Level::errors_only,"PROXY_IO",std::strerror(errno));state=State::error;break;}if(!tcp_handlers.submit([this,client]{handle_client(client);})) {::close(client);logger.write(Level::errors_only,"PROXY_BUSY","Local TCP proxy connection limit reached");}}
    }
    void close_listeners(){
        for(Fd* fd:{&udp4,&tcp4,&udp6,&tcp6}){if(fd->value>=0)::shutdown(fd->value,SHUT_RDWR);fd->reset();}
    }
};

LocalProxy::LocalProxy(std::shared_ptr<const Router> router,Server original,Logger& logger,uint16_t port):impl_(std::make_unique<Impl>(std::move(router),std::move(original),logger,port)){}
LocalProxy::~LocalProxy(){stop();}
void LocalProxy::start(){
    auto& p=*impl_;std::lock_guard lock(p.lifecycle);if(p.state!=State::stopped)throw Error("LIFECYCLE","Proxy is not stopped");p.state=State::starting;
    try{
        int last=0;const unsigned attempts=p.requested_port?1u:128u;
        for(unsigned attempt=0;attempt<attempts;++attempt){
            p.udp4.reset(socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP));p.tcp4.reset(socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
            p.udp6.reset(socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP));p.tcp6.reset(socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP));
            if(p.udp4.value<0||p.tcp4.value<0||p.udp6.value<0||p.tcp6.value<0)sys_error("socket");
            reuse(p.udp4.value);reuse(p.tcp4.value);reuse(p.udp6.value);reuse(p.tcp6.value);v6_only(p.udp6.value);v6_only(p.tcp6.value);
            const uint16_t chosen=p.requested_port?p.requested_port:static_cast<uint16_t>(20000+(platform::secure_random_u32()%28000));
            sockaddr_in a4{};a4.sin_family=AF_INET;a4.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a4.sin_port=htons(chosen);
            sockaddr_in6 a6{};a6.sin6_family=AF_INET6;a6.sin6_addr=in6addr_loopback;a6.sin6_port=htons(chosen);
            const bool ok4=bind(p.tcp4.value,reinterpret_cast<sockaddr*>(&a4),sizeof(a4))==0&&listen(p.tcp4.value,16)==0&&bind(p.udp4.value,reinterpret_cast<sockaddr*>(&a4),sizeof(a4))==0;
            const bool ok6=ok4&&bind(p.tcp6.value,reinterpret_cast<sockaddr*>(&a6),sizeof(a6))==0&&listen(p.tcp6.value,16)==0&&bind(p.udp6.value,reinterpret_cast<sockaddr*>(&a6),sizeof(a6))==0;
            if(ok6){p.bound_port=chosen;break;}
            last=errno;p.close_listeners();if(p.requested_port)break;
        }
        if(!p.bound_port)throw Error("PROXY_BIND","Cannot bind IPv4/IPv6 UDP/TCP loopback listeners: "+std::string(std::strerror(last)));
        p.udp_handlers.start(8,1024);p.tcp_handlers.start(16,128);
        p.running=true;p.state=State::running;
        p.udp4_worker=std::jthread([&p]{p.udp_loop(p.udp4.value);});p.tcp4_worker=std::jthread([&p]{p.tcp_loop(p.tcp4.value);});
        p.udp6_worker=std::jthread([&p]{p.udp_loop(p.udp6.value);});p.tcp6_worker=std::jthread([&p]{p.tcp_loop(p.tcp6.value);});
    }catch(...){p.running=false;p.close_listeners();p.udp_handlers.stop();p.tcp_handlers.stop();p.bound_port=0;p.state=State::error;throw;}
}
void LocalProxy::stop(){
    auto& p=*impl_;std::lock_guard lock(p.lifecycle);if(p.state==State::stopped)return;p.state=State::stopping;p.running=false;p.close_listeners();
    for(std::jthread* thread:{&p.udp4_worker,&p.tcp4_worker,&p.udp6_worker,&p.tcp6_worker})if(thread->joinable())thread->join();
    p.udp_handlers.stop();p.tcp_handlers.stop();
    p.bound_port=0;p.state=State::stopped;
}
InterceptionStatus LocalProxy::status() const{std::lock_guard lock(impl_->lifecycle);return {impl_->state.load(),impl_->bound_port,false,true,true,{},{}};}
}
