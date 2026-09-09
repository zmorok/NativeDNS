#include <nativedns/ipc.hpp>
#include <windows.h>
#include <sddl.h>
#include <vector>

namespace nd {
namespace {
constexpr uint32_t magic = 0x31444e4e, max_payload = 1024 * 1024;
constexpr size_t header_size = 20;
void put16(uint8_t* out, uint16_t v) { out[0]=static_cast<uint8_t>(v); out[1]=static_cast<uint8_t>(v>>8); }
void put32(uint8_t* out, uint32_t v) { for (unsigned i=0;i<4;++i) out[i]=static_cast<uint8_t>(v>>(i*8)); }
void put64(uint8_t* out, uint64_t v) { for (unsigned i=0;i<8;++i) out[i]=static_cast<uint8_t>(v>>(i*8)); }
uint16_t get16(const uint8_t* in) { return static_cast<uint16_t>(in[0] | (in[1]<<8)); }
uint32_t get32(const uint8_t* in) { uint32_t v=0; for(unsigned i=0;i<4;++i) v |= static_cast<uint32_t>(in[i])<<(i*8); return v; }
uint64_t get64(const uint8_t* in) { uint64_t v=0; for(unsigned i=0;i<8;++i) v |= static_cast<uint64_t>(in[i])<<(i*8); return v; }
std::vector<uint8_t> frame(uint16_t operation, uint64_t request, uint32_t status, const std::string& payload) {
    if (payload.size() > max_payload) throw Error("IPC_LIMIT","IPC payload exceeds 1 MiB");
    std::vector<uint8_t> out(header_size + payload.size());
    put32(out.data(),magic); put16(out.data()+4,1); put16(out.data()+6,operation);
    put64(out.data()+8,request); put32(out.data()+16,static_cast<uint32_t>(payload.size()));
    // Responses set the operation high bit and prefix their payload with status.
    if (operation & 0x8000) {
        std::vector<uint8_t> response(header_size + 4 + payload.size());
        std::copy(out.begin(),out.begin()+header_size,response.begin()); put32(response.data()+16,static_cast<uint32_t>(payload.size()+4));
        put32(response.data()+header_size,status); std::copy(payload.begin(),payload.end(),response.begin()+header_size+4); return response;
    }
    std::copy(payload.begin(),payload.end(),out.begin()+header_size); return out;
}
void timed_transfer(HANDLE pipe, uint8_t* data, size_t size, bool write, uint64_t deadline) {
    size_t at=0;
    while(at<size) {
        HANDLE event=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if(!event) throw Error("IPC_IO","Cannot create client IPC event");
        OVERLAPPED overlapped{}; overlapped.hEvent=event; DWORD amount=0;
        BOOL ok = write ? WriteFile(pipe,data+at,static_cast<DWORD>(size-at),nullptr,&overlapped)
                        : ReadFile(pipe,data+at,static_cast<DWORD>(size-at),nullptr,&overlapped);
        if(!ok && GetLastError()!=ERROR_IO_PENDING) {
            const auto error=GetLastError(); CloseHandle(event);
            throw Error("IPC_IO","Named pipe transfer failed: " + std::to_string(error));
        }
        const auto now=GetTickCount64();
        const auto remaining=now>=deadline?0:static_cast<DWORD>(std::min<uint64_t>(deadline-now,MAXDWORD));
        if(WaitForSingleObject(event,remaining)!=WAIT_OBJECT_0) {
            CancelIoEx(pipe,&overlapped); WaitForSingleObject(event,INFINITE); CloseHandle(event);
            throw Error("IPC_TIMEOUT","Named pipe request timed out");
        }
        if(!GetOverlappedResult(pipe,&overlapped,&amount,FALSE) || !amount) {
            const auto error=GetLastError(); CloseHandle(event);
            throw Error("IPC_IO","Named pipe transfer completion failed: " + std::to_string(error));
        }
        CloseHandle(event);
        at += amount;
    }
}
bool async_transfer(HANDLE pipe, uint8_t* data, size_t size, bool write, HANDLE stop) {
    size_t at=0;
    while(at<size) {
        HANDLE event=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if(!event) throw Error("IPC_IO","Cannot create IPC event");
        OVERLAPPED overlapped{}; overlapped.hEvent=event; DWORD amount=0;
        BOOL ok = write ? WriteFile(pipe,data+at,static_cast<DWORD>(size-at),nullptr,&overlapped)
                        : ReadFile(pipe,data+at,static_cast<DWORD>(size-at),nullptr,&overlapped);
        if(!ok && GetLastError()!=ERROR_IO_PENDING) { const auto error=GetLastError(); CloseHandle(event); throw Error("IPC_IO","Named pipe I/O: " + std::to_string(error)); }
        const HANDLE waits[]{stop,event}; const DWORD wait=WaitForMultipleObjects(2,waits,FALSE,INFINITE);
        if(wait==WAIT_OBJECT_0) { CancelIoEx(pipe,&overlapped); WaitForSingleObject(event,INFINITE); CloseHandle(event); return false; }
        if(wait!=WAIT_OBJECT_0+1 || !GetOverlappedResult(pipe,&overlapped,&amount,FALSE) || !amount) { const auto error=GetLastError(); CloseHandle(event); throw Error("IPC_IO","Named pipe completion: " + std::to_string(error)); }
        CloseHandle(event); at += amount;
    }
    return true;
}
PSECURITY_DESCRIPTOR current_user_descriptor() {
    HANDLE token=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) throw Error("IPC_SECURITY","Cannot open process token");
    DWORD size=0; GetTokenInformation(token,TokenUser,nullptr,0,&size);
    std::vector<uint8_t> buffer(size);
    if(!GetTokenInformation(token,TokenUser,buffer.data(),size,&size)) { CloseHandle(token); throw Error("IPC_SECURITY","Cannot read user token"); }
    CloseHandle(token);
    wchar_t* sid=nullptr;
    if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid,&sid)) throw Error("IPC_SECURITY","Cannot format user SID");
    const std::wstring sddl=L"D:P(A;;GA;;;" + std::wstring(sid) + L")"; LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,nullptr)) throw Error("IPC_SECURITY","Cannot create pipe ACL");
    return descriptor;
}
}
PipeServer::PipeServer(std::string name, Handler handler) : name_(std::move(name)),handler_(std::move(handler)) {
    if(name_.empty() || !handler_) throw Error("IPC_CONFIG","Pipe server needs name and handler");
}
PipeServer::~PipeServer() { stop(); }
void PipeServer::start() {
    if(running_.exchange(true)) throw Error("IPC_LIFECYCLE","Pipe server already running");
    HANDLE event=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    HANDLE startup=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if(!event||!startup) { if(event) CloseHandle(event); if(startup) CloseHandle(startup); running_=false; throw Error("IPC_IO","Cannot create pipe lifecycle events"); }
    { std::lock_guard lock(error_mutex_); startup_error_.clear(); }
    native_stop_=event; startup_event_=startup; thread_=std::jthread([this]{run();});
    if(WaitForSingleObject(startup,3000)!=WAIT_OBJECT_0) { stop(); throw Error("IPC_IO","Timed out creating named pipe"); }
    if(!running_) { std::string error_text; { std::lock_guard lock(error_mutex_); error_text=startup_error_; } stop(); throw Error("IPC_IO","Named pipe startup failed: "+error_text); }
}
void PipeServer::stop() {
    running_=false;
    if(native_stop_) SetEvent(static_cast<HANDLE>(native_stop_));
    if(thread_.joinable()) thread_.join();
    if(native_stop_) CloseHandle(static_cast<HANDLE>(native_stop_)); native_stop_=nullptr;
    if(startup_event_) CloseHandle(static_cast<HANDLE>(startup_event_)); startup_event_=nullptr;
}
void PipeServer::run() {
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    try {
        descriptor=current_user_descriptor(); SECURITY_ATTRIBUTES attributes{sizeof(attributes),descriptor,FALSE};
        bool startup_signaled=false;
        while(running_) {
            HANDLE pipe=CreateNamedPipeW(widen(name_).c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,header_size+max_payload+4,header_size+max_payload,0,&attributes);
            if(pipe==INVALID_HANDLE_VALUE) throw Error("IPC_IO","CreateNamedPipe: " + std::to_string(GetLastError()));
            if(!startup_signaled) { SetEvent(static_cast<HANDLE>(startup_event_)); startup_signaled=true; }
            HANDLE connected=CreateEventW(nullptr,TRUE,FALSE,nullptr);
            if(!connected) { CloseHandle(pipe); throw Error("IPC_IO","Cannot create connect event"); }
            OVERLAPPED overlap{}; overlap.hEvent=connected;
            BOOL ok=ConnectNamedPipe(pipe,&overlap);
            const DWORD error=ok?ERROR_SUCCESS:GetLastError();
            if(!ok && error!=ERROR_IO_PENDING && error!=ERROR_PIPE_CONNECTED) { CloseHandle(connected); CloseHandle(pipe); throw Error("IPC_IO","ConnectNamedPipe: " + std::to_string(error)); }
            if(error==ERROR_PIPE_CONNECTED) SetEvent(connected);
            const HANDLE waits[]{static_cast<HANDLE>(native_stop_),connected};
            const DWORD wait=WaitForMultipleObjects(2,waits,FALSE,INFINITE);
            if(wait==WAIT_OBJECT_0) { CancelIoEx(pipe,&overlap); WaitForSingleObject(connected,INFINITE); CloseHandle(connected); CloseHandle(pipe); break; }
            CloseHandle(connected);
            try {
                uint8_t header[header_size]{};
                if(!async_transfer(pipe,header,sizeof(header),false,static_cast<HANDLE>(native_stop_))) { CloseHandle(pipe); break; }
                if(get32(header)!=magic || get16(header+4)!=1) throw Error("IPC_PROTOCOL","Bad IPC magic/version");
                const uint16_t operation=get16(header+6); const uint64_t request=get64(header+8); const uint32_t length=get32(header+16);
                if(!request || length>max_payload || operation<1 || operation>10) throw Error("IPC_PROTOCOL","Invalid IPC request header");
                std::string payload(length,'\0');
                if(length && !async_transfer(pipe,reinterpret_cast<uint8_t*>(payload.data()),length,false,static_cast<HANDLE>(native_stop_))) { CloseHandle(pipe); break; }
                IpcResponse response;
                try { response=handler_(static_cast<IpcOperation>(operation),payload); }
                catch(const Error& e) { response={1,e.code + ": " + e.what()}; }
                catch(const std::exception& e) { response={2,std::string("INTERNAL: ")+e.what()}; }
                auto output=frame(static_cast<uint16_t>(operation|0x8000),request,response.status,response.payload);
                (void)async_transfer(pipe,output.data(),output.size(),true,static_cast<HANDLE>(native_stop_));
            } catch(const std::exception&) { /* malformed/abandoned client is isolated */ }
            FlushFileBuffers(pipe); DisconnectNamedPipe(pipe); CloseHandle(pipe);
        }
    } catch(const std::exception& error) {
        { std::lock_guard lock(error_mutex_); startup_error_=error.what(); }
        running_=false;
        if(startup_event_) SetEvent(static_cast<HANDLE>(startup_event_));
    }
    if(descriptor) LocalFree(descriptor);
}
IpcResponse pipe_request(const std::string& name, IpcOperation operation, const std::string& payload, uint32_t timeout_ms) {
    const auto deadline=GetTickCount64()+timeout_ms;
    HANDLE pipe=INVALID_HANDLE_VALUE;
    for(;;) {
        pipe=CreateFileW(widen(name).c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
        if(pipe!=INVALID_HANDLE_VALUE) break;
        const auto error=GetLastError();
        if(error!=ERROR_FILE_NOT_FOUND && error!=ERROR_PIPE_BUSY) throw Error("IPC_CONNECT","Cannot connect core host: " + std::to_string(error));
        const auto now=GetTickCount64();
        if(now>=deadline) throw Error("IPC_CONNECT","Core host pipe unavailable: " + std::to_string(error));
        const auto wait=static_cast<DWORD>(std::min<uint64_t>(deadline-now,50));
        if(error==ERROR_PIPE_BUSY) (void)WaitNamedPipeW(widen(name).c_str(),wait); else Sleep(wait);
    }
    try {
        const uint64_t request=(static_cast<uint64_t>(GetCurrentProcessId())<<32) | (GetTickCount64() & 0xffffffffULL);
        auto output=frame(static_cast<uint16_t>(operation),request,0,payload); timed_transfer(pipe,output.data(),output.size(),true,deadline);
        uint8_t header[header_size]{}; timed_transfer(pipe,header,sizeof(header),false,deadline);
        if(get32(header)!=magic || get16(header+4)!=1 || get16(header+6)!=(static_cast<uint16_t>(operation)|0x8000) || get64(header+8)!=request)
            throw Error("IPC_PROTOCOL","Mismatched IPC response");
        const uint32_t length=get32(header+16);
        if(length<4 || length>max_payload+4) throw Error("IPC_PROTOCOL","Invalid IPC response size");
        std::vector<uint8_t> body(length); timed_transfer(pipe,body.data(),body.size(),false,deadline);
        IpcResponse response; response.status=get32(body.data()); response.payload.assign(reinterpret_cast<char*>(body.data()+4),body.size()-4);
        CloseHandle(pipe); return response;
    } catch(...) { CloseHandle(pipe); throw; }
}
}
