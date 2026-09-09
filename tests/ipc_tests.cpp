#include <nativedns/ipc.hpp>
#include <nativedns/host.hpp>
#include <nativedns/dns.hpp>
#include <nativedns/platform.hpp>
#include <future>
#include <iostream>
#include <sstream>
#include <vector>
#include <thread>
#include <filesystem>
#include <fstream>

void check(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
int main() {
    try {
#ifdef _WIN32
        const auto name=std::string(R"(\\.\pipe\NativeDNS.Test.)")+std::to_string(nd::platform::process_id());
#else
        const auto name=std::string("/tmp/nativedns-test-")+std::to_string(nd::platform::process_id())+".sock";
#endif
        std::atomic_uint calls=0;
        nd::PipeServer server(name,[&](nd::IpcOperation operation,const std::string& payload)->nd::IpcResponse {
            ++calls;
            if(operation==nd::IpcOperation::ping) return {0,"pong:"+payload};
            if(operation==nd::IpcOperation::status) return {0,"RUNNING port=5300 transparent=0"};
            if(operation==nd::IpcOperation::start) throw nd::Error("LIFECYCLE","already running");
            if(operation==nd::IpcOperation::clear_file_log) { std::this_thread::sleep_for(std::chrono::milliseconds(250)); return {0,"late"}; }
            return {7,"unsupported in test"};
        });
        server.start(); check(server.running(),"server running");
        auto response=nd::pipe_request(name,nd::IpcOperation::ping,"hello");
        check(response.status==0 && response.payload=="pong:hello","ping round trip");
        response=nd::pipe_request(name,nd::IpcOperation::status);
        check(response.payload.find("RUNNING")!=std::string::npos,"status round trip");
        response=nd::pipe_request(name,nd::IpcOperation::start);
        check(response.status==1 && response.payload.find("LIFECYCLE")!=std::string::npos,"structured handler failure");
        std::vector<std::future<void>> clients;
        for(unsigned i=0;i<8;++i) clients.push_back(std::async(std::launch::async,[&,i] {
            auto result=nd::pipe_request(name,nd::IpcOperation::ping,std::to_string(i),5000);
            check(result.status==0,"concurrent sequential clients");
        }));
        for(auto& client:clients) client.get();
        check(calls==11,"handler call count");
        bool failed=false; try { (void)nd::pipe_request(name,nd::IpcOperation::clear_file_log,{},50); } catch(const nd::Error& error) { failed=error.code=="IPC_TIMEOUT"; }
        check(failed,"whole-request deadline");
        failed=false; try { (void)nd::pipe_request(name,nd::IpcOperation::ping,std::string(1024*1024+1,'x')); } catch(const nd::Error&) { failed=true; }
        check(failed,"client payload bound");
        const auto start=std::chrono::steady_clock::now(); server.stop();
        check(!server.running() && std::chrono::steady_clock::now()-start<std::chrono::seconds(2),"idle deterministic stop");
        server.start(); check(nd::pipe_request(name,nd::IpcOperation::ping).status==0,"restart"); server.stop(); server.stop();
        failed=false; try { (void)nd::pipe_request(name,nd::IpcOperation::ping,{},50); } catch(const nd::Error&) { failed=true; }
        check(failed,"unavailable host failure");
        const auto host_name=name+".Host";
        const auto host_log_name=host_name+".logs";
        const auto log_directory=std::filesystem::current_path()/("ipc-log-test-"+std::to_string(nd::platform::process_id()));
        auto config=nd::default_config(); config.logging.file_enabled=false; config.logging.directory=log_directory.string(); config.rules.back().action=nd::Action::block;
        nd::Server original; original.name="unused"; original.ip="127.0.0.1"; original.port=1;
        nd::CoreHost host(config,original,0,host_name); host.start();
        check(nd::pipe_request(host_name,nd::IpcOperation::configure_file_log,"1\t2").payload=="FILE_LOG_ENABLED","enable file log through IPC");
        response=nd::pipe_request(host_name,nd::IpcOperation::status);
        check(response.payload.starts_with("RUNNING") && response.payload.find("transparent=0")!=std::string::npos,"host status");
        const auto marker=response.payload.find("port="); const auto finish=response.payload.find(' ',marker);
        const auto port=static_cast<uint16_t>(std::stoul(response.payload.substr(marker+5,finish-marker-5)));
        auto local=original; local.port=port;
        check(nd::test_server(local,"example.com").success,"host routes actual local DNS request");
        {
            std::ifstream stream(log_directory/"NativeDNS.log",std::ios::binary);
            const std::string contents((std::istreambuf_iterator<char>(stream)),{});
            check(contents.find("[INFO]")!=std::string::npos&&contents.find("FILE_LOG_CONFIGURED")!=std::string::npos&&contents.find("DNS_ROUTE")!=std::string::npos,"runtime file log configuration");
        }
        response=nd::pipe_request(host_log_name,nd::IpcOperation::logs,"0\t0\t3");
        check(response.payload.find("CORE_STARTED")!=std::string::npos && response.payload.find("DNS_ROUTE")!=std::string::npos,"host log stream snapshot");
        check(nd::pipe_request(host_log_name,nd::IpcOperation::logs,"0\t0\t4").status==1,"reject invalid requested log level");
        uint64_t last_sequence=0; std::istringstream rows(response.payload); std::string row;
        while(std::getline(rows,row)) { const auto tab=row.find('\t'); if(tab!=std::string::npos) last_sequence=std::stoull(row.substr(0,tab)); }
        auto live=std::async(std::launch::async,[&]{return nd::pipe_request(host_log_name,nd::IpcOperation::logs,std::to_string(last_sequence)+"\t1000",2000);});
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); const auto command_start=std::chrono::steady_clock::now();
        check(nd::pipe_request(host_name,nd::IpcOperation::status).payload.starts_with("RUNNING"),"command during live log wait");
        check(std::chrono::steady_clock::now()-command_start<std::chrono::milliseconds(500),"log wait does not block command pipe");
        check(nd::test_server(local,"example.com").success,"second routed DNS request");
        check(live.wait_for(std::chrono::seconds(2))==std::future_status::ready,"live log wait wakes");
        check(live.get().payload.find("DNS_ROUTE")!=std::string::npos,"live log event delivered");
        check(nd::pipe_request(host_name,nd::IpcOperation::clear_display).status==0,"clear display through IPC");
        check(nd::pipe_request(host_log_name,nd::IpcOperation::logs,"0").payload.empty(),"display buffer cleared");
        check(nd::pipe_request(host_name,nd::IpcOperation::status).payload.starts_with("RUNNING"),"commands remain responsive after live log wait");
        check(nd::pipe_request(host_name,nd::IpcOperation::configure_file_log,"bad\t2").status==1,"reject invalid file log configuration");
        check(nd::pipe_request(host_name,nd::IpcOperation::stop).payload=="STOPPED","remote stop");
        check(nd::pipe_request(host_name,nd::IpcOperation::start).payload.starts_with("RUNNING"),"remote start");
        auto waiter=std::async(std::launch::async,[&]{host.wait_for_shutdown();});
        check(nd::pipe_request(host_name,nd::IpcOperation::restart).payload=="RESTARTING","remote restart signal");
        check(waiter.wait_for(std::chrono::seconds(2))==std::future_status::ready,"shutdown wake"); waiter.get(); host.stop();
        check(host.restart_requested(),"restart intent survives host stop");
        host.stop();
        {
            std::ifstream stream(log_directory/"NativeDNS.log",std::ios::binary);
            const std::string contents((std::istreambuf_iterator<char>(stream)),{});
            const auto first=contents.find("CORE_STOPPED");
            check(first!=std::string::npos&&contents.find("CORE_STOPPED",first+1)==std::string::npos,"host stop is logged once");
        }
        host.logger().configure_file(false,nd::Level::normal,{});
        for(const auto& entry:std::filesystem::directory_iterator(log_directory))std::filesystem::remove(entry.path());
        std::filesystem::remove(log_directory);
        std::cout << "cross-platform IPC protocol tests passed\n"; return 0;
    } catch(const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
