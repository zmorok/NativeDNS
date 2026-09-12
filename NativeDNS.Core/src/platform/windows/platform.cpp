#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sodium.h>
#include <vector>
#include <cstring>
#include <sstream>
#include <set>

namespace nd::platform {
namespace {
void sodium_ready() {
    static const bool ready=[] { if(sodium_init()<0) throw Error("CRYPTO_INIT","libsodium initialization failed"); return true; }();
    (void)ready;
}
void winsock_ready() {
    static const bool ready=[] { WSADATA data{}; const int rc=WSAStartup(MAKEWORD(2,2),&data); if(rc) throw Error("SOCKET_INIT","WSAStartup: "+std::to_string(rc)); return true; }();
    (void)ready;
}
}
bool parse_ip(const std::string& text,std::array<uint8_t,16>& bytes,bool& ipv6) {
    bytes.fill(0); in_addr v4{}; in6_addr v6{};
    if(InetPtonA(AF_INET,text.c_str(),&v4)==1) { std::memcpy(bytes.data()+12,&v4,4); ipv6=false; return true; }
    if(InetPtonA(AF_INET6,text.c_str(),&v6)==1) { std::memcpy(bytes.data(),&v6,16); ipv6=true; return true; }
    return false;
}
bool is_numeric_ip(const std::string& text) { std::array<uint8_t,16> b{}; bool v6=false; return parse_ip(text,b,v6); }
std::string format_ip(const void* bytes,bool ipv6) {
    char text[INET6_ADDRSTRLEN]{};
    if(!InetNtopA(ipv6?AF_INET6:AF_INET,const_cast<void*>(bytes),text,sizeof(text))) throw Error("ENDPOINT","Cannot format IP address");
    return text;
}
uint16_t secure_random_u16(){ sodium_ready(); uint16_t value=0; randombytes_buf(&value,sizeof(value)); return value; }
uint32_t secure_random_u32(){ sodium_ready(); uint32_t value=0; randombytes_buf(&value,sizeof(value)); return value; }
uint64_t monotonic_millis(){ return GetTickCount64(); }
uint32_t process_id(){ return GetCurrentProcessId(); }
std::filesystem::path executable_path(){
    std::vector<wchar_t> buffer(32768); const DWORD n=GetModuleFileNameW(nullptr,buffer.data(),static_cast<DWORD>(buffer.size()));
    if(!n||n>=buffer.size()) throw Error("PATH","Cannot determine executable path");
    return std::filesystem::path(std::wstring(buffer.data(),n));
}
std::filesystem::path application_root_directory(){ return executable_path().parent_path(); }
std::filesystem::path user_config_directory(){
    const DWORD required=GetEnvironmentVariableW(L"LOCALAPPDATA",nullptr,0);
    if(required>0) {
        std::wstring local(required,L'\0');
        const DWORD written=GetEnvironmentVariableW(L"LOCALAPPDATA",local.data(),required);
        if(written>0&&written<required) {
            local.resize(written);
            return std::filesystem::path(local)/L"NativeDNS";
        }
    }
    return executable_path().parent_path();
}
std::string system_summary(){
    using RtlGetVersionFunction=LONG (WINAPI*)(OSVERSIONINFOW*);
    OSVERSIONINFOW version{}; version.dwOSVersionInfoSize=sizeof(version);
    if(const auto module=GetModuleHandleW(L"ntdll.dll"))
        if(const auto get_version=reinterpret_cast<RtlGetVersionFunction>(GetProcAddress(module,"RtlGetVersion")))
            (void)get_version(&version);

    bool elevated=false;
    HANDLE token=nullptr;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)){
        TOKEN_ELEVATION elevation{}; DWORD size=0;
        if(GetTokenInformation(token,TokenElevation,&elevation,sizeof(elevation),&size)) elevated=elevation.TokenIsElevated!=0;
        CloseHandle(token);
    }
    std::ostringstream output;
    output<<"platform=windows-x64 os="<<version.dwMajorVersion<<'.'<<version.dwMinorVersion<<" build="<<version.dwBuildNumber
          <<" pid="<<process_id()<<" elevated="<<(elevated?1:0);
    return output.str();
}
void wait_socket(std::intptr_t raw,bool writing,std::chrono::steady_clock::time_point deadline){
    const SOCKET socket=static_cast<SOCKET>(raw);
    const auto left=std::chrono::duration_cast<std::chrono::microseconds>(deadline-std::chrono::steady_clock::now());
    if(left.count()<=0) throw Error("TIMEOUT","Socket wait deadline exceeded");
    timeval timeout{static_cast<long>(left.count()/1000000),static_cast<long>(left.count()%1000000)};
    fd_set set; FD_ZERO(&set); FD_SET(socket,&set);
    const int rc=select(0,writing?nullptr:&set,writing?&set:nullptr,nullptr,&timeout);
    if(rc==0) throw Error("TIMEOUT","Socket wait timed out");
    if(rc<0) throw Error("SOCKET","Socket wait failed: Winsock "+std::to_string(WSAGetLastError()));
}
void configure_upstream_socket(std::intptr_t) {}
uint16_t prepare_upstream_socket(std::intptr_t raw,bool) {
    winsock_ready();
    const SOCKET socket=static_cast<SOCKET>(raw);
    WSAPROTOCOL_INFOW info{}; int info_size=sizeof(info);
    if(getsockopt(socket,SOL_SOCKET,SO_PROTOCOL_INFOW,reinterpret_cast<char*>(&info),&info_size)==SOCKET_ERROR)
        throw Error("SOCKET","Cannot inspect secure upstream socket: Winsock "+std::to_string(WSAGetLastError()));
    sockaddr_storage local{}; int local_size=info.iAddressFamily==AF_INET?sizeof(sockaddr_in):sizeof(sockaddr_in6);
    local.ss_family=static_cast<ADDRESS_FAMILY>(info.iAddressFamily);
    if(bind(socket,reinterpret_cast<const sockaddr*>(&local),local_size)==SOCKET_ERROR&&WSAGetLastError()!=WSAEINVAL)
        throw Error("SOCKET","Cannot bind secure upstream socket: Winsock "+std::to_string(WSAGetLastError()));
    if(getsockname(socket,reinterpret_cast<sockaddr*>(&local),&local_size)==SOCKET_ERROR)
        throw Error("SOCKET","Cannot inspect secure upstream endpoint: Winsock "+std::to_string(WSAGetLastError()));
    return ntohs(info.iAddressFamily==AF_INET?reinterpret_cast<const sockaddr_in*>(&local)->sin_port
                                            :reinterpret_cast<const sockaddr_in6*>(&local)->sin6_port);
}
int close_upstream_socket(std::intptr_t raw) noexcept { return closesocket(static_cast<SOCKET>(raw))==0?0:1; }
std::vector<std::string> resolve_host(const std::string& hostname) {
    winsock_ready();
    addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM; hints.ai_flags=AI_ADDRCONFIG;
    addrinfo* addresses=nullptr; const int rc=getaddrinfo(hostname.c_str(),nullptr,&hints,&addresses);
    if(rc) throw Error("BOOTSTRAP","Cannot resolve secure upstream "+hostname+": Winsock "+std::to_string(rc));
    std::unique_ptr<addrinfo,decltype(&freeaddrinfo)> cleanup(addresses,&freeaddrinfo);
    std::vector<std::string> result; std::set<std::string> unique;
    for(auto* address=addresses;address;address=address->ai_next) {
        const bool ipv6=address->ai_family==AF_INET6;
        if(address->ai_family!=AF_INET&&!ipv6)continue;
        const void* bytes=ipv6?static_cast<const void*>(&reinterpret_cast<const sockaddr_in6*>(address->ai_addr)->sin6_addr)
                              :static_cast<const void*>(&reinterpret_cast<const sockaddr_in*>(address->ai_addr)->sin_addr);
        auto text=format_ip(bytes,ipv6);if(unique.insert(text).second)result.push_back(std::move(text));
    }
    if(result.empty())throw Error("BOOTSTRAP","Secure upstream hostname has no usable address: "+hostname);
    return result;
}
void atomic_publish_file(const std::filesystem::path& temp,const std::filesystem::path& target,const std::filesystem::path& backup){
    if(std::filesystem::exists(target)) {
        if(!ReplaceFileW(target.c_str(),temp.c_str(),backup.c_str(),REPLACEFILE_WRITE_THROUGH,nullptr,nullptr))
            throw Error("CONFIG_IO","Atomic replacement failed: "+std::to_string(GetLastError()));
    } else if(!MoveFileExW(temp.c_str(),target.c_str(),MOVEFILE_WRITE_THROUGH))
        throw Error("CONFIG_IO","Atomic creation failed: "+std::to_string(GetLastError()));
}
struct ProcessInstanceLock::Impl {
    HANDLE handle=nullptr;
    bool owns=false;
};

ProcessInstanceLock::ProcessInstanceLock(const std::string& name):impl_(std::make_unique<Impl>()){
    const std::wstring mutexName=L"Local\\"+nd::widen(name);
    impl_->handle=CreateMutexW(nullptr,FALSE,mutexName.c_str());
    if(!impl_->handle){
        const DWORD error=GetLastError();
        if(error==ERROR_ACCESS_DENIED)return;
        throw Error("INSTANCE_LOCK","Cannot create process mutex: "+std::to_string(error));
    }
    impl_->owns=GetLastError()!=ERROR_ALREADY_EXISTS;
}
ProcessInstanceLock::~ProcessInstanceLock(){if(impl_&&impl_->handle)CloseHandle(impl_->handle);}
bool ProcessInstanceLock::acquired() const noexcept{return impl_&&impl_->owns;}

void local_time(std::time_t instant,std::tm& output){ localtime_s(&output,&instant); }
}
