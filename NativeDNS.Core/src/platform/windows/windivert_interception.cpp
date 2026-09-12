#include <nativedns/interception.hpp>
#include <nativedns/dns_network.hpp>
#include <nativedns/firewall.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/tcp_dns_proxy.hpp>
#include <windivert.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <thread>
#include <cwctype>

namespace nd {
namespace {
std::wstring normalized_driver_path(std::wstring path){
    if(path.starts_with(L"\\??\\"))path.erase(0,4);
    std::replace(path.begin(),path.end(),L'/',L'\\');
    std::transform(path.begin(),path.end(),path.begin(),[](wchar_t value){return static_cast<wchar_t>(std::towlower(value));});
    return path;
}
bool windivert_service_belongs_to_application(){
    const SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if(!manager)return false;
    const SC_HANDLE service=OpenServiceW(manager,L"WinDivert",SERVICE_QUERY_CONFIG);
    if(!service){const bool missing=GetLastError()==ERROR_SERVICE_DOES_NOT_EXIST;CloseServiceHandle(manager);return missing;}
    DWORD required=0;
    (void)QueryServiceConfigW(service,nullptr,0,&required);
    std::vector<uint8_t> storage(required);
    const auto config=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
    const bool queried=required&&QueryServiceConfigW(service,config,required,&required);
    bool owned=false;
    if(queried&&config->lpBinaryPathName){
        const auto expected=(platform::executable_path().parent_path()/L"WinDivert64.sys").wstring();
        owned=normalized_driver_path(config->lpBinaryPathName)==normalized_driver_path(expected);
    }
    CloseServiceHandle(service);CloseServiceHandle(manager);
    return owned;
}
bool stop_windivert_service() noexcept{
    const SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if(!manager)return false;
    const SC_HANDLE service=OpenServiceW(manager,L"WinDivert",SERVICE_STOP|SERVICE_QUERY_STATUS);
    if(!service){const bool gone=GetLastError()==ERROR_SERVICE_DOES_NOT_EXIST;CloseServiceHandle(manager);return gone;}
    SERVICE_STATUS status{};
    bool stopped=ControlService(service,SERVICE_CONTROL_STOP,&status)!=FALSE||GetLastError()==ERROR_SERVICE_NOT_ACTIVE;
    for(unsigned attempt=0;stopped&&status.dwCurrentState!=SERVICE_STOPPED&&attempt<40;++attempt){
        Sleep(50);
        stopped=QueryServiceStatus(service,&status)!=FALSE;
    }
    stopped=stopped&&(status.dwCurrentState==SERVICE_STOPPED||status.dwCurrentState==0);
    CloseServiceHandle(service);CloseServiceHandle(manager);
    return stopped;
}
uint16_t read16(const uint8_t* bytes) { return static_cast<uint16_t>((bytes[0] << 8) | bytes[1]); }
void write16(uint8_t* bytes,uint16_t value) { bytes[0]=static_cast<uint8_t>(value>>8); bytes[1]=static_cast<uint8_t>(value); }
uint32_t checksum_add(uint32_t sum,const uint8_t* bytes,size_t size) {
    while(size>=2) { sum+=read16(bytes); bytes+=2; size-=2; }
    if(size) sum+=static_cast<uint16_t>(bytes[0]<<8);
    return sum;
}
uint16_t checksum_finish(uint32_t sum) {
    while(sum>>16) sum=(sum&0xffff)+(sum>>16);
    const auto result=static_cast<uint16_t>(~sum);
    return result?result:0xffff;
}
struct UdpView { size_t udp=0,payload=0; bool ipv6=false; };
struct TcpView { size_t tcp=0,payload=0; bool ipv6=false; };
struct Ipv6Transport { uint8_t protocol=0;size_t offset=40; };
Ipv6Transport ipv6_transport(const Packet& packet) {
    if(packet.size()<40||static_cast<size_t>(read16(packet.data()+4))+40!=packet.size())
        throw Error("INTERCEPT_PACKET","Invalid IPv6 packet length");
    uint8_t next=packet[6];size_t at=40;
    for(unsigned headers=0;headers<16;++headers) {
        if(next==IPPROTO_UDP||next==IPPROTO_TCP) return{next,at};
        if(next==0||next==43||next==60) {
            if(at+2>packet.size()) throw Error("INTERCEPT_PACKET","Truncated IPv6 extension header");
            const size_t length=static_cast<size_t>(packet[at+1]+1)*8;
            if(at+length>packet.size()) throw Error("INTERCEPT_PACKET","Invalid IPv6 extension header length");
            next=packet[at];at+=length;continue;
        }
        if(next==44) {
            if(at+8>packet.size()) throw Error("INTERCEPT_PACKET","Truncated IPv6 fragment header");
            if((read16(packet.data()+at+2)&0xfff9)!=0) throw Error("INTERCEPT_PACKET","Fragmented IPv6 DNS packet is unsupported");
            next=packet[at];at+=8;continue;
        }
        if(next==51) {
            if(at+2>packet.size()) throw Error("INTERCEPT_PACKET","Truncated IPv6 authentication header");
            const size_t length=static_cast<size_t>(packet[at+1]+2)*4;
            if(at+length>packet.size()) throw Error("INTERCEPT_PACKET","Invalid IPv6 authentication header length");
            next=packet[at];at+=length;continue;
        }
        throw Error("INTERCEPT_PACKET","Unsupported IPv6 next header "+std::to_string(next));
    }
    throw Error("INTERCEPT_PACKET","Too many IPv6 extension headers");
}
UdpView udp_view(const Packet& packet) {
    if(packet.size()<28) throw Error("INTERCEPT_PACKET","Captured packet is too short");
    const auto version=packet[0]>>4;
    UdpView view;
    if(version==4) {
        const size_t header=static_cast<size_t>(packet[0]&0x0f)*4;
        if(header<20||header+8>packet.size()||packet[9]!=IPPROTO_UDP||read16(packet.data()+2)!=packet.size())
            throw Error("INTERCEPT_PACKET","Invalid IPv4 UDP packet");
        if((read16(packet.data()+6)&0x3fff)!=0) throw Error("INTERCEPT_PACKET","Fragmented DNS packet is unsupported");
        view.udp=header;
    } else if(version==6) {
        const auto transport=ipv6_transport(packet);
        if(transport.protocol!=IPPROTO_UDP||transport.offset+8>packet.size()) throw Error("INTERCEPT_PACKET","IPv6 packet is not UDP");
        view.udp=transport.offset; view.ipv6=true;
    } else throw Error("INTERCEPT_PACKET","Unsupported IP version");
    view.payload=view.udp+8;
    if(read16(packet.data()+view.udp+2)!=53||read16(packet.data()+view.udp+4)!=packet.size()-view.udp)
        throw Error("INTERCEPT_PACKET","Packet is not a complete UDP DNS query");
    if(packet.size()-view.payload<12) throw Error("INTERCEPT_PACKET","DNS payload is too short");
    return view;
}
Server original_server(const Packet& packet,const UdpView& view) {
    char address[INET6_ADDRSTRLEN]{};
    const void* source=view.ipv6?static_cast<const void*>(packet.data()+24):static_cast<const void*>(packet.data()+16);
    if(!InetNtopA(view.ipv6?AF_INET6:AF_INET,source,address,sizeof(address))) throw Error("INTERCEPT_PACKET","Cannot format original DNS address");
    Server server; server.name="Original intercepted resolver"; server.protocol=Protocol::udp;
    server.ip=address; server.port=read16(packet.data()+view.udp+2); return server;
}
std::string destination_ip(const Packet& packet,bool ipv6) {
    char address[INET6_ADDRSTRLEN]{};
    const void* destination=ipv6?static_cast<const void*>(packet.data()+24):static_cast<const void*>(packet.data()+16);
    if(!InetNtopA(ipv6?AF_INET6:AF_INET,destination,address,sizeof(address)))
        throw Error("INTERCEPT_PACKET","Cannot format TCP DNS destination");
    return address;
}
TcpView tcp_view(const Packet& packet) {
    if(packet.size()<40) throw Error("INTERCEPT_PACKET","Captured TCP packet is too short");
    const auto version=packet[0]>>4;
    TcpView view;
    if(version==4) {
        const size_t header=static_cast<size_t>(packet[0]&0x0f)*4;
        if(header<20||header+20>packet.size()||packet[9]!=IPPROTO_TCP||read16(packet.data()+2)!=packet.size())
            throw Error("INTERCEPT_PACKET","Invalid IPv4 TCP packet");
        if((read16(packet.data()+6)&0x3fff)!=0) throw Error("INTERCEPT_PACKET","Fragmented TCP packet is unsupported");
        view.tcp=header;
    } else if(version==6) {
        const auto transport=ipv6_transport(packet);
        if(transport.protocol!=IPPROTO_TCP||transport.offset+20>packet.size()) throw Error("INTERCEPT_PACKET","IPv6 packet is not TCP");
        view.tcp=transport.offset; view.ipv6=true;
    } else throw Error("INTERCEPT_PACKET","Unsupported IP version");
    const size_t tcp_header=static_cast<size_t>(packet[view.tcp+12]>>4)*4;
    if(tcp_header<20||view.tcp+tcp_header>packet.size()) throw Error("INTERCEPT_PACKET","Invalid TCP header length");
    view.payload=view.tcp+tcp_header;
    return view;
}
bool is_tcp_packet(const Packet& packet) {
    if(packet.empty()) return false;
    const auto version=packet[0]>>4;
    if(version==4) return packet.size()>9&&packet[9]==IPPROTO_TCP;
    if(version!=6) return false;
    return ipv6_transport(packet).protocol==IPPROTO_TCP;
}
}

Packet make_intercepted_udp_response(const Packet& captured,const Packet& dns_response) {
    const auto view=udp_view(captured);
    if(dns_response.size()<12||dns_response.size()>65507||view.payload+dns_response.size()>65535)
        throw Error("INTERCEPT_PACKET","Invalid DNS response size");
    Packet result(captured.begin(),captured.begin()+static_cast<ptrdiff_t>(view.payload));
    result.insert(result.end(),dns_response.begin(),dns_response.end());
    if(view.ipv6) {
        write16(result.data()+4,static_cast<uint16_t>(result.size()-40));
        for(size_t i=0;i<16;++i) std::swap(result[8+i],result[24+i]);
    } else {
        write16(result.data()+2,static_cast<uint16_t>(result.size()));
        std::swap_ranges(result.begin()+12,result.begin()+16,result.begin()+16);
    }
    std::swap(result[view.udp],result[view.udp+2]); std::swap(result[view.udp+1],result[view.udp+3]);
    write16(result.data()+view.udp+4,static_cast<uint16_t>(8+dns_response.size()));
    write16(result.data()+view.udp+6,0);
    uint32_t udp_sum=0;
    if(view.ipv6) {
        udp_sum=checksum_add(udp_sum,result.data()+8,32);
        const std::array<uint8_t,8> suffix{0,0,static_cast<uint8_t>((8+dns_response.size())>>8),static_cast<uint8_t>(8+dns_response.size()),0,0,0,IPPROTO_UDP};
        udp_sum=checksum_add(udp_sum,suffix.data(),suffix.size());
    } else {
        udp_sum=checksum_add(udp_sum,result.data()+12,8);
        const std::array<uint8_t,4> suffix{0,IPPROTO_UDP,static_cast<uint8_t>((8+dns_response.size())>>8),static_cast<uint8_t>(8+dns_response.size())};
        udp_sum=checksum_add(udp_sum,suffix.data(),suffix.size());
    }
    udp_sum=checksum_add(udp_sum,result.data()+view.udp,result.size()-view.udp);
    write16(result.data()+view.udp+6,checksum_finish(udp_sum));
    if(!view.ipv6) { write16(result.data()+10,0); write16(result.data()+10,checksum_finish(checksum_add(0,result.data(),view.udp))); }
    return result;
}

bool should_reinject_udp_immediately(const Config& config,const Packet& captured) {
    const auto view=udp_view(captured);
    const Packet query(captured.begin()+static_cast<ptrdiff_t>(view.payload),captured.end());
    const auto question=parse_question(query);
    if(question.flags&0x8000) throw Error("DNS_MALFORMED","Cannot route a reply as a query");
    const auto& rule=match_rule(config,question.name);
    return rule.action==Action::bypass||(rule.action==Action::process&&rule.server_id==0);
}

Packet make_reflected_tcp_packet(const Packet& captured,uint16_t proxy_port,bool toward_proxy,uint16_t intercepted_port) {
    const auto view=tcp_view(captured);
    if(!proxy_port||!intercepted_port) throw Error("INTERCEPT_PACKET","TCP reflection port is zero");
    if(toward_proxy&&read16(captured.data()+view.tcp+2)!=intercepted_port)
        throw Error("INTERCEPT_PACKET","TCP packet is not addressed to DNS");
    if(!toward_proxy&&read16(captured.data()+view.tcp)!=proxy_port)
        throw Error("INTERCEPT_PACKET","TCP packet is not from the stream proxy");
    Packet result=captured;
    if(view.ipv6) {
        for(size_t i=0;i<16;++i) std::swap(result[8+i],result[24+i]);
    } else {
        std::swap_ranges(result.begin()+12,result.begin()+16,result.begin()+16);
    }
    write16(result.data()+view.tcp+(toward_proxy?2:0),toward_proxy?proxy_port:intercepted_port);
    write16(result.data()+view.tcp+16,0);
    const size_t tcp_length=result.size()-view.tcp;
    uint32_t tcp_sum=0;
    if(view.ipv6) {
        tcp_sum=checksum_add(tcp_sum,result.data()+8,32);
        const std::array<uint8_t,8> suffix{static_cast<uint8_t>(tcp_length>>24),static_cast<uint8_t>(tcp_length>>16),
            static_cast<uint8_t>(tcp_length>>8),static_cast<uint8_t>(tcp_length),0,0,0,IPPROTO_TCP};
        tcp_sum=checksum_add(tcp_sum,suffix.data(),suffix.size());
    } else {
        tcp_sum=checksum_add(tcp_sum,result.data()+12,8);
        const std::array<uint8_t,4> suffix{0,IPPROTO_TCP,static_cast<uint8_t>(tcp_length>>8),static_cast<uint8_t>(tcp_length)};
        tcp_sum=checksum_add(tcp_sum,suffix.data(),suffix.size());
    }
    tcp_sum=checksum_add(tcp_sum,result.data()+view.tcp,tcp_length);
    write16(result.data()+view.tcp+16,checksum_finish(tcp_sum));
    if(!view.ipv6) { write16(result.data()+10,0); write16(result.data()+10,checksum_finish(checksum_add(0,result.data(),view.tcp))); }
    return result;
}

struct WinDivertInterception::Impl {
    using Open=decltype(&WinDivertOpen); using Recv=decltype(&WinDivertRecv); using Send=decltype(&WinDivertSend);
    using Shutdown=decltype(&WinDivertShutdown); using Close=decltype(&WinDivertClose); using SetParam=decltype(&WinDivertSetParam);
    using Compile=decltype(&WinDivertHelperCompileFilter); using CalcChecksums=decltype(&WinDivertHelperCalcChecksums);
    Config config; Logger& logger; Router router; detail::TcpDnsProxy tcp_proxy; detail::FirewallPortRule firewall;
    mutable std::mutex lifecycle; std::atomic<State> state=State::stopped;
    std::string error_code,error_message; HMODULE module=nullptr; HANDLE handle=INVALID_HANDLE_VALUE;
    Open open=nullptr; Recv recv=nullptr; Send send=nullptr; Shutdown shutdown=nullptr; Close close=nullptr; SetParam set_param=nullptr; Compile compile=nullptr; CalcChecksums calc_checksums=nullptr;
    struct Job { Packet packet; WINDIVERT_ADDRESS address{}; };
    std::mutex queue_mutex; std::condition_variable queue_changed; std::deque<Job> jobs;
    std::jthread receiver; std::vector<std::jthread> workers;
    std::atomic<uint64_t> overload_count=0;
    uint16_t tcp_proxy_port=0,intercepted_tcp_port; bool stop_driver_on_release=false;
    Impl(Config value,Logger& output,uint16_t target):config(std::move(value)),logger(output),router(config,logger),tcp_proxy(router,logger,target),intercepted_tcp_port(target) { validate(config); }
    template<class T> T symbol(const char* name) {
        auto address=GetProcAddress(module,name); if(!address) throw Error("WINDIVERT_LOAD",std::string("Missing WinDivert export: ")+name);
        return reinterpret_cast<T>(address);
    }
    void inject(const Packet& packet,WINDIVERT_ADDRESS address) {
        UINT sent=0; if(!send(handle,packet.data(),static_cast<UINT>(packet.size()),&sent,&address)||sent!=packet.size())
            throw Error("WINDIVERT_SEND","WinDivertSend failed: "+std::to_string(GetLastError()));
    }
    void process(Job job) {
        try {
            const auto view=udp_view(job.packet); const auto query=Packet(job.packet.begin()+static_cast<ptrdiff_t>(view.payload),job.packet.end());
            const auto question=parse_question(query); const auto& rule=match_rule(config,question.name);
            if(rule.action==Action::bypass||(rule.action==Action::process&&rule.server_id==0)) { inject(job.packet,job.address); return; }
            auto routed=router.route(query,original_server(job.packet,view));
            if(routed.disposition==Disposition::forward_original) { inject(job.packet,job.address); return; }
            if(routed.disposition==Disposition::silent_drop||routed.packet.empty()) return;
            auto response=make_intercepted_udp_response(job.packet,fit_udp_response(query,routed.packet)); job.address.Outbound=0; job.address.IPChecksum=0; job.address.UDPChecksum=0;
            inject(response,job.address);
        } catch(const Error& error) { logger.write(Level::errors_only,error.code,error.what()); }
    }
    void reject_overload(const Packet& packet,const UdpView& view,WINDIVERT_ADDRESS address) {
        const Packet query(packet.begin()+static_cast<ptrdiff_t>(view.payload),packet.end());
        const auto response=make_intercepted_udp_response(packet,make_error_response(query,2));
        address.Outbound=0;address.IPChecksum=0;address.UDPChecksum=0;
        inject(response,address);
        const auto count=++overload_count;
        if(count==1||(count&(count-1))==0)
            logger.write(Level::errors_only,"WINDIVERT_SATURATED","Routing queue is full; returned SERVFAIL (count="+std::to_string(count)+")");
    }
    void receive_loop() {
        try {
            while(state==State::running) {
                Packet packet(WINDIVERT_MTU_MAX); UINT length=0; WINDIVERT_ADDRESS address{};
                if(!recv(handle,packet.data(),static_cast<UINT>(packet.size()),&length,&address)) {
                    const auto error=GetLastError(); if(state!=State::running) break;
                    throw Error("WINDIVERT_RECV","WinDivertRecv failed: "+std::to_string(error));
                }
                packet.resize(length);
                try {
                    if(is_tcp_packet(packet)) {
                        const auto view=tcp_view(packet);
                        const auto source_port=read16(packet.data()+view.tcp);
                        const auto destination_port=read16(packet.data()+view.tcp+2);
                        if(!address.Outbound) { inject(packet,address); continue; }
                        if(destination_port==intercepted_tcp_port&&detail::is_network_upstream(true,source_port)) { inject(packet,address); continue; }
                        const bool toward_proxy=destination_port==intercepted_tcp_port;
                        if(!toward_proxy&&source_port!=tcp_proxy_port) { inject(packet,address); continue; }
                        const auto flags=packet[view.tcp+13];
                        if(toward_proxy&&(flags&0x02)!=0&&(flags&0x10)==0)
                            tcp_proxy.expect_connection(destination_ip(packet,view.ipv6),source_port);
                        else if(toward_proxy&&(flags&0x04)!=0)
                            tcp_proxy.forget_connection(destination_ip(packet,view.ipv6),source_port);
                        logger.write(Level::debug,"WINDIVERT_TCP_REFLECT",std::string(toward_proxy?"to_proxy":"to_client")+" source_port="+std::to_string(source_port));
                        auto reflected=make_reflected_tcp_packet(packet,tcp_proxy_port,toward_proxy,intercepted_tcp_port);
                        address.Outbound=0; address.IPChecksum=0; address.TCPChecksum=0;
                        if(!calc_checksums(reflected.data(),static_cast<UINT>(reflected.size()),&address,0))
                            throw Error("WINDIVERT_CHECKSUM","Cannot calculate reflected TCP checksums");
                        inject(reflected,address);
                        continue;
                    }
                    const auto view=udp_view(packet);
                    const auto source_port=read16(packet.data()+view.udp);
                    const bool upstream=detail::is_network_upstream(false,source_port);
                    if(upstream) { logger.write(Level::debug,"WINDIVERT_UPSTREAM_BYPASS","source_port="+std::to_string(source_port)); inject(packet,address); continue; }
                    const auto captured_question=parse_question(Packet(packet.begin()+static_cast<ptrdiff_t>(view.payload),packet.end()));
                    const auto& captured_rule=match_rule(config,captured_question.name);
                    logger.write(Level::debug,"DNS_CAPTURE","transport=udp name="+captured_question.name+" rule="+captured_rule.name+" action="+action_name(captured_rule.action)+" server="+std::to_string(captured_rule.server_id));
                    if(should_reinject_udp_immediately(config,packet)) {
                        const auto original=original_server(packet,view);
                        logger.write(Level::normal,"DNS_ROUTE",route_log_message(captured_question,captured_rule,&original));
                        logger.write(Level::debug,"WINDIVERT_RULE_FAST_PATH",captured_question.name+" bypass/original query reinjected before worker queue");
                        inject(packet,address);
                        continue;
                    }
                    bool queued=false;
                    {
                        std::lock_guard lock(queue_mutex);
                        if(jobs.size()<4096) { jobs.push_back({std::move(packet),address});queued=true; }
                    }
                    if(queued) queue_changed.notify_one();
                    else reject_overload(packet,view,address);
                } catch(const Error& error) {
                    logger.write(Level::errors_only,error.code,error.what());
                    try { inject(packet,address); }
                    catch(const Error& inject_error) { logger.write(Level::errors_only,inject_error.code,inject_error.what()); }
                }
            }
        } catch(const Error& error) {
            if(handle!=INVALID_HANDLE_VALUE) shutdown(handle,WINDIVERT_SHUTDOWN_BOTH);
            std::lock_guard lock(lifecycle); error_code=error.code; error_message=error.what(); state=State::error;
            logger.write(Level::errors_only,error.code,error.what());
        }
        queue_changed.notify_all();
    }
    void worker_loop() {
        for(;;) {
            Job job;
            {
                std::unique_lock lock(queue_mutex);
                queue_changed.wait(lock,[&]{return state!=State::running||!jobs.empty();});
                if(state!=State::running) return;
                if(jobs.empty()) continue;
                job=std::move(jobs.front()); jobs.pop_front();
            }
            process(std::move(job));
        }
    }
    void release() {
        firewall.disable();
        tcp_proxy.stop(); tcp_proxy_port=0;
        if(handle!=INVALID_HANDLE_VALUE) { close(handle); handle=INVALID_HANDLE_VALUE; }
        if(module) { FreeLibrary(module); module=nullptr; }
        if(stop_driver_on_release){
            if(stop_windivert_service())logger.write(Level::verbose,"WINDIVERT_DRIVER_STOPPED","NativeDNS WinDivert driver service stopped");
            else logger.write(Level::verbose,"WINDIVERT_DRIVER_RETAINED","WinDivert service is still in use or could not be stopped");
            stop_driver_on_release=false;
        }
    }
};

WinDivertInterception::WinDivertInterception(Config config,Logger& logger,uint16_t intercepted_tcp_port)
    :impl_(std::make_unique<Impl>(std::move(config),logger,intercepted_tcp_port)) {}
WinDivertInterception::~WinDivertInterception() { stop(); }
void WinDivertInterception::start() {
    auto& p=*impl_; std::lock_guard lock(p.lifecycle);
    if(p.state!=State::stopped) throw Error("LIFECYCLE","WinDivert interception is not stopped");
    p.state=State::starting; p.error_code.clear(); p.error_message.clear();
    try {
        p.firewall.disable();
        p.logger.write(Level::verbose,"FIREWALL_STALE_CLEANUP","Removed any stale TCP interception firewall rule");
        p.tcp_proxy_port=p.tcp_proxy.start();
        p.logger.write(Level::verbose,"TCP_PROXY_STARTED","TCP reflection proxy listening on port="+std::to_string(p.tcp_proxy_port));
        try{p.stop_driver_on_release=windivert_service_belongs_to_application();}
        catch(...){p.stop_driver_on_release=false;}
        p.module=LoadLibraryExW(L"WinDivert.dll",nullptr,LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
        if(!p.module) throw Error("WINDIVERT_LOAD","Cannot load WinDivert.dll: "+std::to_string(GetLastError()));
        p.logger.write(Level::verbose,"WINDIVERT_LOADED","WinDivert.dll loaded successfully");
        p.open=p.symbol<Impl::Open>("WinDivertOpen"); p.recv=p.symbol<Impl::Recv>("WinDivertRecv"); p.send=p.symbol<Impl::Send>("WinDivertSend");
        p.shutdown=p.symbol<Impl::Shutdown>("WinDivertShutdown"); p.close=p.symbol<Impl::Close>("WinDivertClose"); p.set_param=p.symbol<Impl::SetParam>("WinDivertSetParam");
        p.compile=p.symbol<Impl::Compile>("WinDivertHelperCompileFilter"); p.calc_checksums=p.symbol<Impl::CalcChecksums>("WinDivertHelperCalcChecksums");
        const std::string target=std::to_string(p.intercepted_tcp_port),proxy=std::to_string(p.tcp_proxy_port);
        const std::string filter="(outbound and !loopback and !impostor and !fragment and udp.DstPort == 53 and udp.PayloadLength >= 12) or (!impostor and tcp and !fragment and (tcp.DstPort == "+target+" or tcp.SrcPort == "+target+" or tcp.DstPort == "+proxy+" or tcp.SrcPort == "+proxy+"))";
        const char* filter_error=nullptr; UINT filter_position=0;
        if(!p.compile(filter.c_str(),WINDIVERT_LAYER_NETWORK,nullptr,0,&filter_error,&filter_position))
            throw Error("WINDIVERT_FILTER",std::string(filter_error?filter_error:"Invalid filter")+" at "+std::to_string(filter_position));
        p.handle=p.open(filter.c_str(),WINDIVERT_LAYER_NETWORK,123,0);
        if(p.handle==INVALID_HANDLE_VALUE) {
            const auto error=GetLastError();
            throw Error(error==ERROR_ACCESS_DENIED?"ELEVATION_REQUIRED":"WINDIVERT_OPEN","WinDivertOpen failed: "+std::to_string(error));
        }
        p.logger.write(Level::verbose,"WINDIVERT_HANDLE_OPEN","WinDivert network handle opened");
        if(!p.set_param(p.handle,WINDIVERT_PARAM_QUEUE_TIME,WINDIVERT_PARAM_QUEUE_TIME_MAX)||
           !p.set_param(p.handle,WINDIVERT_PARAM_QUEUE_LENGTH,8192)||
           !p.set_param(p.handle,WINDIVERT_PARAM_QUEUE_SIZE,WINDIVERT_PARAM_QUEUE_SIZE_MAX))
            throw Error("WINDIVERT_QUEUE","Cannot configure WinDivert queue: "+std::to_string(GetLastError()));
        p.firewall.enable(p.tcp_proxy_port);
        p.logger.write(Level::verbose,"FIREWALL_RULE_ACTIVE","TCP proxy firewall rule enabled");
        p.state=State::running;
        const auto worker_count=std::clamp(std::thread::hardware_concurrency(),4u,16u);
        for(unsigned i=0;i<worker_count;++i) p.workers.emplace_back([&p]{p.worker_loop();});
        p.receiver=std::jthread([&p]{p.receive_loop();});
        p.logger.write(Level::normal,"WINDIVERT_STARTED","Transparent UDP/TCP DNS interception started; TCP proxy port="+std::to_string(p.tcp_proxy_port)+", routing workers="+std::to_string(worker_count));
    } catch(...) {
        const auto failure=std::current_exception(); p.state=State::stopping;
        if(p.handle!=INVALID_HANDLE_VALUE&&p.shutdown) p.shutdown(p.handle,WINDIVERT_SHUTDOWN_BOTH);
        p.queue_changed.notify_all();
        if(p.receiver.joinable()) p.receiver.join();
        for(auto& worker:p.workers) if(worker.joinable()) worker.join();
        p.workers.clear(); { std::lock_guard queue_lock(p.queue_mutex); p.jobs.clear(); }
        try { std::rethrow_exception(failure); }
        catch(const Error& error) { p.error_code=error.code; p.error_message=error.what(); }
        catch(const std::exception& error) { p.error_code="INTERNAL"; p.error_message=error.what(); }
        p.release(); p.state=State::error; std::rethrow_exception(failure);
    }
}
void WinDivertInterception::stop() {
    auto& p=*impl_;
    { std::lock_guard lock(p.lifecycle); if(p.state==State::stopped) return; p.state=State::stopping; }
    if(p.handle!=INVALID_HANDLE_VALUE) p.shutdown(p.handle,WINDIVERT_SHUTDOWN_BOTH);
    p.queue_changed.notify_all();
    if(p.receiver.joinable()) p.receiver.join();
    for(auto& worker:p.workers) if(worker.joinable()) worker.join();
    p.workers.clear();
    { std::lock_guard lock(p.lifecycle); { std::lock_guard queue_lock(p.queue_mutex); p.jobs.clear(); } p.release(); p.state=State::stopped; }
}
InterceptionStatus WinDivertInterception::status() const {
    const auto& p=*impl_; std::lock_guard lock(p.lifecycle);
    return {p.state.load(),p.tcp_proxy_port,true,true,true,p.error_code,p.error_message};
}
}
