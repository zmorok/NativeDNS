#include <nativedns/interception.hpp>
#include <nativedns/platform.hpp>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
using Socket=SOCKET;
constexpr Socket bad_socket=INVALID_SOCKET;
void close_socket(Socket value){closesocket(value);}
#else
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
using Socket=int;
constexpr Socket bad_socket=-1;
void close_socket(Socket value){::close(value);}
#endif

namespace {
struct Resources{uint64_t memory=0,handles=0,threads=0;};
Resources resources(){
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS memory{};GetProcessMemoryInfo(GetCurrentProcess(),&memory,sizeof(memory));DWORD handles=0;GetProcessHandleCount(GetCurrentProcess(),&handles);
    return{memory.WorkingSetSize,handles,0};
#else
    Resources value;
    if(DIR* directory=opendir("/proc/self/fd")){while(readdir(directory))++value.handles;closedir(directory);}
    if(DIR* directory=opendir("/proc/self/task")){while(readdir(directory))++value.threads;closedir(directory);}
    rusage usage{};if(getrusage(RUSAGE_SELF,&usage)==0)value.memory=static_cast<uint64_t>(usage.ru_maxrss)*1024;
    return value;
#endif
}
bool exact(Socket socket,uint8_t* data,size_t size,bool writing){size_t offset=0;while(offset<size){const int count=writing?send(socket,reinterpret_cast<const char*>(data+offset),static_cast<int>(size-offset),0):recv(socket,reinterpret_cast<char*>(data+offset),static_cast<int>(size-offset),0);if(count<=0)return false;offset+=static_cast<size_t>(count);}return true;}
Socket connect_to(uint16_t port,int type){Socket socket_value=socket(AF_INET,type,type==SOCK_STREAM?IPPROTO_TCP:IPPROTO_UDP);if(socket_value==bad_socket)return bad_socket;
#ifdef _WIN32
    DWORD timeout=2000;setsockopt(socket_value,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));setsockopt(socket_value,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
#else
    timeval timeout{2,0};setsockopt(socket_value,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(socket_value,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
#endif
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);if(connect(socket_value,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0){close_socket(socket_value);return bad_socket;}return socket_value;}
bool request(uint16_t port,bool tcp,const nd::Packet& query){
    Socket client=connect_to(port,tcp?SOCK_STREAM:SOCK_DGRAM);if(client==bad_socket)return false;
    bool ok=false;
    if(tcp){std::vector<uint8_t> frame{static_cast<uint8_t>(query.size()>>8),static_cast<uint8_t>(query.size())};frame.insert(frame.end(),query.begin(),query.end());uint8_t prefix[2]{};ok=exact(client,frame.data(),frame.size(),true)&&exact(client,prefix,2,false);if(ok){const size_t size=(static_cast<size_t>(prefix[0])<<8)|prefix[1];std::vector<uint8_t> response(size);ok=size>=12&&exact(client,response.data(),response.size(),false);}}
    else{ok=send(client,reinterpret_cast<const char*>(query.data()),static_cast<int>(query.size()),0)==static_cast<int>(query.size());uint8_t response[512]{};if(ok)ok=recv(client,reinterpret_cast<char*>(response),sizeof(response),0)>=12;}
    close_socket(client);return ok;
}
uint64_t number(const char* text){uint64_t value=0;const auto end=text+std::char_traits<char>::length(text);const auto parsed=std::from_chars(text,end,value);if(parsed.ec!=std::errc{}||parsed.ptr!=end||!value)throw std::runtime_error("invalid positive argument");return value;}
}

int main(int argc,char** argv){
    try{
        uint64_t seconds=30,clients=16;bool debug_logging=false;
        for(int i=1;i<argc;++i){const std::string arg=argv[i];if(arg=="--seconds"&&i+1<argc)seconds=number(argv[++i]);else if(arg=="--clients"&&i+1<argc)clients=number(argv[++i]);else if(arg=="--debug-logging")debug_logging=true;else throw std::runtime_error("usage: nativedns_stress [--seconds N] [--clients N] [--debug-logging]");}
#ifdef _WIN32
        WSADATA sockets{};if(WSAStartup(MAKEWORD(2,2),&sockets))throw std::runtime_error("WSAStartup failed");
#endif
        auto config=nd::default_config();config.rules.back().action=nd::Action::block;config.rules.back().block_mode=nd::BlockMode::zero_address;config.logging.screen=debug_logging?nd::Level::debug:nd::Level::errors_only;
        nd::Logger logger(4096);logger.set_display_level(config.logging.screen);auto router=std::make_shared<nd::Router>(config,logger);nd::Server unused;unused.name="unused";unused.ip="127.0.0.1";unused.port=1;
        const auto before=resources();nd::LocalProxy proxy(router,unused,logger);proxy.start();const auto port=proxy.status().port;const auto query=nd::make_query("stress.example");
        std::atomic_uint64_t successes=0,failures=0;std::mutex latency_mutex;std::vector<uint64_t> latencies;latencies.reserve(1000000);const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(seconds);
        std::vector<std::jthread> workers;for(uint64_t index=0;index<clients;++index)workers.emplace_back([&,index]{bool tcp=(index%2)!=0;while(std::chrono::steady_clock::now()<deadline){const auto start=std::chrono::steady_clock::now();const bool ok=request(port,tcp,query);const auto micros=static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count());if(ok){++successes;std::lock_guard lock(latency_mutex);if(latencies.size()<1000000)latencies.push_back(micros);}else ++failures;tcp=!tcp;}});for(auto& worker:workers)worker.join();proxy.stop();
        std::sort(latencies.begin(),latencies.end());const auto percentile=[&](double p){return latencies.empty()?0ULL:latencies[std::min(latencies.size()-1,static_cast<size_t>(p*latencies.size()))];};const auto after=resources();const double qps=static_cast<double>(successes.load())/static_cast<double>(seconds);
        std::cout<<"requests="<<successes.load()<<" failures="<<failures.load()<<" qps="<<qps<<" p50_us="<<percentile(.50)<<" p95_us="<<percentile(.95)<<" p99_us="<<percentile(.99)<<" memory_before="<<before.memory<<" memory_after="<<after.memory<<" handles_before="<<before.handles<<" handles_after="<<after.handles<<" threads_before="<<before.threads<<" threads_after="<<after.threads<<'\n';
        if(failures.load()||successes.load()<clients||after.memory>before.memory+128ULL*1024*1024||after.handles>before.handles+32||after.threads>before.threads+2)return 1;
#ifdef _WIN32
        WSACleanup();
#endif
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
