#include <nativedns/interception.hpp>
#include <nativedns/platform.hpp>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <unistd.h>

namespace nd {
namespace {
constexpr uint32_t upstream_mark=0x4e444e53u;
int command(const std::string& cmd){ return std::system(cmd.c_str()); }
Server read_resolver_file(const char* path,bool allow_loopback){
    std::ifstream in(path); std::string line;
    while(std::getline(in,line)){
        std::istringstream row(line);std::string key,value;row>>key>>value;
        if(key!="nameserver"||!platform::is_numeric_ip(value))continue;
        const bool loopback=value=="127.0.0.1"||value=="127.0.0.53"||value=="::1";
        if(loopback&&!allow_loopback)continue;
        Server server;server.id=1;server.name=std::string("System resolver from ")+path;server.protocol=Protocol::udp;server.ip=value;server.port=53;server.timeout_ms=3000;return server;
    }
    return {};
}
Server system_resolver(){
    // Prefer the real upstream list over systemd-resolved's 127.0.0.53 stub.
    // Redirecting the stub's own unmarked upstream DNS back into NativeDNS would
    // otherwise create a loop on Default/Bypass routes.
    for(const char* path:{"/run/systemd/resolve/resolv.conf","/run/NetworkManager/no-stub-resolv.conf","/etc/resolv.conf"}){
        auto server=read_resolver_file(path,false);if(!server.ip.empty())return server;
    }
    Server fallback;fallback.id=1;fallback.name="Fallback resolver";fallback.protocol=Protocol::udp;fallback.ip="1.1.1.1";fallback.port=53;fallback.timeout_ms=3000;return fallback;
}

class LinuxNftInterception final : public IInterceptionProvider {
public:
    LinuxNftInterception(Config config,Logger& logger,uint16_t intercepted):config_(std::move(config)),logger_(logger),intercepted_(intercepted){
        router_=std::make_shared<Router>(config_,logger_); original_=system_resolver(); proxy_=std::make_unique<LocalProxy>(router_,original_,logger_,0);
        logger_.write(Level::verbose,"SYSTEM_RESOLVER","Selected original resolver "+original_.ip+":"+std::to_string(original_.port)+" source="+original_.name);
    }
    ~LinuxNftInterception() override { stop(); }
    void start() override {
        std::lock_guard lock(mutex_); if(status_.state!=State::stopped) throw Error("LIFECYCLE","Linux interception is not stopped"); status_.state=State::starting;
        try {
            if(::geteuid()!=0) throw Error("ELEVATION_REQUIRED","Linux transparent interception requires root/CAP_NET_ADMIN CoreHost privileges");
            logger_.write(Level::verbose,"LINUX_PRIVILEGES","Transparent interception privilege check passed");
            if(command("command -v nft >/dev/null 2>&1")!=0) throw Error("NFT_NOT_FOUND","nftables command is required for transparent Linux interception");
            logger_.write(Level::verbose,"NFT_AVAILABLE","nftables executable found");
            proxy_->start(); const auto p=proxy_->status(); if(!p.port) throw Error("INTERCEPTION","Local proxy did not expose a port");
            (void)command("nft delete table inet nativedns >/dev/null 2>&1");
            const std::string script=
                "nft 'add table inet nativedns' && "
                "nft 'add chain inet nativedns output { type nat hook output priority -100; policy accept; }' && "
                "nft 'add rule inet nativedns output meta mark "+std::to_string(upstream_mark)+" return' && "
                "nft 'add rule inet nativedns output meta l4proto udp udp dport "+std::to_string(intercepted_)+" redirect to :"+std::to_string(p.port)+"' && "
                "nft 'add rule inet nativedns output meta l4proto tcp tcp dport "+std::to_string(intercepted_)+" redirect to :"+std::to_string(p.port)+"'";
            if(command(script)!=0){ proxy_->stop();(void)command("nft delete table inet nativedns >/dev/null 2>&1");throw Error("NFT_SETUP","Failed to install NativeDNS nftables redirect rules"); }
            status_={State::running,p.port,true,true,true,{},{}};
            logger_.write(Level::normal,"LINUX_INTERCEPTION","nftables redirect active; local_port="+std::to_string(p.port));
        } catch(const Error& e){ status_.state=State::error;status_.error_code=e.code;status_.error_message=e.what();throw; }
    }
    void stop() override {
        std::lock_guard lock(mutex_); if(status_.state==State::stopped)return;status_.state=State::stopping;(void)command("nft delete table inet nativedns >/dev/null 2>&1");if(proxy_)proxy_->stop();status_={};
    }
    InterceptionStatus status() const override { std::lock_guard lock(mutex_); return status_; }
private:
    Config config_;Logger& logger_;uint16_t intercepted_;Server original_;std::shared_ptr<Router> router_;std::unique_ptr<LocalProxy> proxy_;mutable std::mutex mutex_;InterceptionStatus status_;
};
}
std::unique_ptr<IInterceptionProvider> make_platform_interception(Config config,Logger& logger,uint16_t port){ return std::make_unique<LinuxNftInterception>(std::move(config),logger,port); }
}
