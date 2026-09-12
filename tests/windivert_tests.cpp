#include <nativedns/interception.hpp>
#include <nativedns/dns.hpp>
#include <nativedns/dns_network.hpp>
#include <nativedns/tcp_dns_proxy.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <array>
#include <iostream>

void check(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
uint16_t read16(const uint8_t* p) { return static_cast<uint16_t>((p[0]<<8)|p[1]); }
void write16(uint8_t* p,uint16_t v) { p[0]=static_cast<uint8_t>(v>>8); p[1]=static_cast<uint8_t>(v); }
uint32_t add(uint32_t sum,const uint8_t* p,size_t n) { while(n>=2){sum+=read16(p);p+=2;n-=2;} if(n)sum+=p[0]<<8; return sum; }
uint16_t folded(uint32_t sum) { while(sum>>16)sum=(sum&0xffff)+(sum>>16); return static_cast<uint16_t>(sum); }

nd::Packet dns_response() {
    auto packet=nd::make_query("example.com"); packet[2]=0x81; packet[3]=0x80; return packet;
}
nd::Packet ipv4_query() {
    const auto dns=nd::make_query("example.com"); nd::Packet packet(28+dns.size());
    packet[0]=0x45; packet[8]=64; packet[9]=17; write16(packet.data()+2,static_cast<uint16_t>(packet.size()));
    const std::array<uint8_t,4> source{192,0,2,10},destination{8,8,8,8};
    std::copy(source.begin(),source.end(),packet.begin()+12); std::copy(destination.begin(),destination.end(),packet.begin()+16);
    write16(packet.data()+20,50000); write16(packet.data()+22,53); write16(packet.data()+24,static_cast<uint16_t>(8+dns.size()));
    std::copy(dns.begin(),dns.end(),packet.begin()+28); return packet;
}
nd::Packet ipv6_query() {
    const auto dns=nd::make_query("example.com"); nd::Packet packet(48+dns.size());
    packet[0]=0x60; write16(packet.data()+4,static_cast<uint16_t>(8+dns.size())); packet[6]=17; packet[7]=64;
    packet[8]=0x20; packet[9]=0x01; packet[10]=0x0d; packet[11]=0xb8; packet[23]=1;
    packet[24]=0x20; packet[25]=0x01; packet[26]=0x48; packet[27]=0x60; packet[28]=0x48; packet[29]=0x60; packet[39]=0x88; packet[38]=0x88;
    write16(packet.data()+40,50001); write16(packet.data()+42,53); write16(packet.data()+44,static_cast<uint16_t>(8+dns.size()));
    std::copy(dns.begin(),dns.end(),packet.begin()+48); return packet;
}
nd::Packet ipv4_tcp(uint16_t source,uint16_t destination) {
    nd::Packet packet(43);
    packet[0]=0x45; packet[8]=64; packet[9]=6; write16(packet.data()+2,static_cast<uint16_t>(packet.size()));
    const std::array<uint8_t,4> client{192,0,2,10},server{8,8,8,8};
    std::copy(client.begin(),client.end(),packet.begin()+12); std::copy(server.begin(),server.end(),packet.begin()+16);
    write16(packet.data()+20,source); write16(packet.data()+22,destination); packet[32]=0x50; packet[33]=0x18;
    packet[40]='d'; packet[41]='n'; packet[42]='s'; return packet;
}
nd::Packet ipv6_tcp(uint16_t source,uint16_t destination) {
    nd::Packet packet(63);
    packet[0]=0x60; write16(packet.data()+4,23); packet[6]=6; packet[7]=64;
    packet[8]=0x20; packet[9]=0x01; packet[10]=0x0d; packet[11]=0xb8; packet[23]=1;
    packet[24]=0x20; packet[25]=0x01; packet[26]=0x48; packet[27]=0x60; packet[28]=0x48; packet[29]=0x60; packet[38]=0x88; packet[39]=0x88;
    write16(packet.data()+40,source); write16(packet.data()+42,destination); packet[52]=0x50; packet[53]=0x18;
    packet[60]='d'; packet[61]='n'; packet[62]='s'; return packet;
}
void verify_tcp_checksum(const nd::Packet& packet,size_t tcp,bool ipv6) {
    const size_t length=packet.size()-tcp;
    uint32_t sum=0;
    if(ipv6) {
        sum=add(0,packet.data()+8,32);
        const std::array<uint8_t,8> pseudo{static_cast<uint8_t>(length>>24),static_cast<uint8_t>(length>>16),static_cast<uint8_t>(length>>8),static_cast<uint8_t>(length),0,0,0,6};
        sum=add(sum,pseudo.data(),pseudo.size());
    } else {
        sum=add(0,packet.data()+12,8);
        const std::array<uint8_t,4> pseudo{0,6,static_cast<uint8_t>(length>>8),static_cast<uint8_t>(length)};
        sum=add(sum,pseudo.data(),pseudo.size());
    }
    sum=add(sum,packet.data()+tcp,length);
    check(folded(sum)==0xffff,"TCP checksum");
}
void tcp_proxy_roundtrip() {
    nd::Config config=nd::default_config();
    config.rules.front().action=nd::Action::block;
    config.rules.front().block_mode=nd::BlockMode::zero_address;
    nd::Logger logger;
    nd::Router router(config,logger);
    nd::detail::TcpDnsProxy proxy(router,logger);
    const auto port=proxy.start();
    SOCKET client=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    check(client!=INVALID_SOCKET,"TCP proxy test socket");
    sockaddr_in local{}; local.sin_family=AF_INET; local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    check(bind(client,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0,"TCP proxy test bind");
    int local_size=sizeof(local); check(getsockname(client,reinterpret_cast<sockaddr*>(&local),&local_size)==0,"TCP proxy test endpoint");
    proxy.expect_connection("127.0.0.1",ntohs(local.sin_port));
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_port=htons(port); address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    check(connect(client,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"TCP proxy test connect");
    const auto query=nd::make_query("proxy.example");
    nd::Packet frame{static_cast<uint8_t>(query.size()>>8),static_cast<uint8_t>(query.size())};
    frame.insert(frame.end(),query.begin(),query.end());
    for(unsigned request=0;request<2;++request) {
        check(send(client,reinterpret_cast<const char*>(frame.data()),static_cast<int>(frame.size()),0)==static_cast<int>(frame.size()),"TCP proxy query send");
        uint8_t prefix[2]{};
        check(recv(client,reinterpret_cast<char*>(prefix),2,MSG_WAITALL)==2,"TCP proxy response prefix");
        const size_t response_size=static_cast<size_t>((prefix[0]<<8)|prefix[1]);
        nd::Packet response(response_size);
        check(recv(client,reinterpret_cast<char*>(response.data()),static_cast<int>(response.size()),MSG_WAITALL)==static_cast<int>(response.size()),"TCP proxy response frame");
        const auto parsed=nd::parse_response(response,nd::parse_question(query));
        check(parsed.addresses.size()==1&&parsed.addresses.front()=="0.0.0.0","TCP proxy routes framed DNS");
    }
    closesocket(client);
    SOCKET rejected=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    check(rejected!=INVALID_SOCKET&&connect(rejected,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"unregistered TCP proxy connection reaches validator");
    char byte=0;
    check(recv(rejected,&byte,1,0)==0,"unregistered TCP proxy connection rejected");
    closesocket(rejected);
    SOCKET reset=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    check(reset!=INVALID_SOCKET,"forgotten TCP proxy socket");
    sockaddr_in reset_local{};reset_local.sin_family=AF_INET;reset_local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    check(bind(reset,reinterpret_cast<sockaddr*>(&reset_local),sizeof(reset_local))==0,"forgotten TCP proxy bind");
    int reset_size=sizeof(reset_local);check(getsockname(reset,reinterpret_cast<sockaddr*>(&reset_local),&reset_size)==0,"forgotten TCP proxy endpoint");
    proxy.expect_connection("127.0.0.1",ntohs(reset_local.sin_port));
    proxy.forget_connection("127.0.0.1",ntohs(reset_local.sin_port));
    check(connect(reset,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"forgotten TCP proxy connect");
    check(recv(reset,&byte,1,0)==0,"forgotten TCP proxy connection rejected");
    closesocket(reset);
    for(unsigned connection=0;connection<256;++connection) {
        SOCKET short_lived=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        check(short_lived!=INVALID_SOCKET,"short-lived TCP proxy socket");
        sockaddr_in short_local{};short_local.sin_family=AF_INET;short_local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        check(bind(short_lived,reinterpret_cast<sockaddr*>(&short_local),sizeof(short_local))==0,"short-lived TCP proxy bind");
        int short_size=sizeof(short_local);check(getsockname(short_lived,reinterpret_cast<sockaddr*>(&short_local),&short_size)==0,"short-lived TCP proxy endpoint");
        proxy.expect_connection("127.0.0.1",ntohs(short_local.sin_port));
        check(connect(short_lived,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"short-lived TCP proxy connect");
        check(send(short_lived,reinterpret_cast<const char*>(frame.data()),static_cast<int>(frame.size()),0)==static_cast<int>(frame.size()),"short-lived TCP proxy query");
        uint8_t short_prefix[2]{};check(recv(short_lived,reinterpret_cast<char*>(short_prefix),2,MSG_WAITALL)==2,"short-lived TCP proxy prefix");
        nd::Packet short_response(static_cast<size_t>((short_prefix[0]<<8)|short_prefix[1]));
        check(recv(short_lived,reinterpret_cast<char*>(short_response.data()),static_cast<int>(short_response.size()),MSG_WAITALL)==static_cast<int>(short_response.size()),"short-lived TCP proxy response");
        closesocket(short_lived);
    }
    proxy.stop();
}
int main() {
    try {
        check(!nd::detail::is_network_upstream(false,42424),"upstream registry initially empty");
        {
            nd::detail::NetworkUpstreamGuard first(false,42424),second(false,42424);
            check(nd::detail::is_network_upstream(false,42424)&&!nd::detail::is_network_upstream(true,42424),"protocol-specific upstream registration");
        }
        check(!nd::detail::is_network_upstream(false,42424),"reference-counted upstream removal");

        nd::Config fast_path=nd::default_config();
        check(nd::should_reinject_udp_immediately(fast_path,ipv4_query()),"Process/server_id=0 bypasses worker queue");
        fast_path.rules.front().action=nd::Action::bypass;
        check(nd::should_reinject_udp_immediately(fast_path,ipv4_query()),"Bypass action bypasses worker queue");
        fast_path.rules.front().action=nd::Action::block;
        check(!nd::should_reinject_udp_immediately(fast_path,ipv4_query()),"Block remains on worker queue");
        fast_path.rules.front().action=nd::Action::process;
        fast_path.rules.front().server_id=1002;
        nd::Server custom; custom.id=1002; custom.name="Custom"; custom.ip="1.1.1.1";
        fast_path.servers.push_back(custom);
        check(!nd::should_reinject_udp_immediately(fast_path,ipv4_query()),"Custom Process remains on worker queue");

        tcp_proxy_roundtrip();
        const auto dns=dns_response(); const auto v4=nd::make_intercepted_udp_response(ipv4_query(),dns);
        check(v4[0]==0x45&&read16(v4.data()+2)==v4.size(),"IPv4 length");
        check(std::equal(v4.begin()+12,v4.begin()+16,std::array<uint8_t,4>{8,8,8,8}.begin()),"IPv4 source swap");
        check(std::equal(v4.begin()+16,v4.begin()+20,std::array<uint8_t,4>{192,0,2,10}.begin()),"IPv4 destination swap");
        check(read16(v4.data()+20)==53&&read16(v4.data()+22)==50000,"IPv4 port swap");
        check(std::equal(dns.begin(),dns.end(),v4.begin()+28),"IPv4 DNS payload");
        check(folded(add(0,v4.data(),20))==0xffff,"IPv4 header checksum");
        uint32_t sum=add(0,v4.data()+12,8); const std::array<uint8_t,4> pseudo4{0,17,v4[24],v4[25]}; sum=add(sum,pseudo4.data(),pseudo4.size()); sum=add(sum,v4.data()+20,v4.size()-20);
        check(folded(sum)==0xffff,"IPv4 UDP checksum");

        const auto v6=nd::make_intercepted_udp_response(ipv6_query(),dns);
        check((v6[0]>>4)==6&&read16(v6.data()+4)==v6.size()-40,"IPv6 length");
        check(v6[8]==0x20&&v6[9]==0x01&&v6[10]==0x48&&v6[11]==0x60,"IPv6 source swap");
        check(v6[24]==0x20&&v6[25]==0x01&&v6[26]==0x0d&&v6[27]==0xb8,"IPv6 destination swap");
        check(read16(v6.data()+40)==53&&read16(v6.data()+42)==50001,"IPv6 port swap");
        sum=add(0,v6.data()+8,32); const std::array<uint8_t,8> pseudo6{0,0,v6[44],v6[45],0,0,0,17}; sum=add(sum,pseudo6.data(),pseudo6.size()); sum=add(sum,v6.data()+40,v6.size()-40);
        check(folded(sum)==0xffff,"IPv6 UDP checksum");

        const auto tcp4=nd::make_reflected_tcp_packet(ipv4_tcp(51000,53),34010,true);
        check(std::equal(tcp4.begin()+12,tcp4.begin()+16,std::array<uint8_t,4>{8,8,8,8}.begin()),"IPv4 TCP destination reflection source");
        check(read16(tcp4.data()+20)==51000&&read16(tcp4.data()+22)==34010,"IPv4 TCP proxy destination");
        check(folded(add(0,tcp4.data(),20))==0xffff,"IPv4 TCP IP checksum");
        verify_tcp_checksum(tcp4,20,false);
        const auto tcp4_reply=nd::make_reflected_tcp_packet(ipv4_tcp(34010,51000),34010,false);
        check(read16(tcp4_reply.data()+20)==53&&read16(tcp4_reply.data()+22)==51000,"IPv4 TCP DNS response source");
        verify_tcp_checksum(tcp4_reply,20,false);

        const auto tcp6=nd::make_reflected_tcp_packet(ipv6_tcp(51001,53),34010,true);
        check(tcp6[8]==0x20&&tcp6[10]==0x48&&read16(tcp6.data()+40)==51001&&read16(tcp6.data()+42)==34010,"IPv6 TCP reflection");
        verify_tcp_checksum(tcp6,40,true);
        const auto tcp6_reply=nd::make_reflected_tcp_packet(ipv6_tcp(34010,51001),34010,false);
        check(read16(tcp6_reply.data()+40)==53&&read16(tcp6_reply.data()+42)==51001,"IPv6 TCP DNS response source");
        verify_tcp_checksum(tcp6_reply,40,true);

        bool failed=false; auto fragment=ipv4_query(); fragment[6]=0x20;
        try { (void)nd::make_intercepted_udp_response(fragment,dns); } catch(const nd::Error& error) { failed=error.code=="INTERCEPT_PACKET"; }
        check(failed,"fragment rejection");
        failed=false; auto wrong=ipv4_query(); wrong[23]=54;
        try { (void)nd::make_intercepted_udp_response(wrong,dns); } catch(const nd::Error&) { failed=true; }
        check(failed,"non-DNS rejection");
        std::cout<<"WinDivert packet rewrite tests passed\n"; return 0;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
