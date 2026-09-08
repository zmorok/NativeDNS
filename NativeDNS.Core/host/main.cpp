#include <nativedns/host.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/autostart.hpp>
#include <iostream>

namespace {
nd::Server default_original(){
    nd::Server s;
    s.id=1;
    s.name="System fallback";
    s.protocol=nd::Protocol::udp;
    s.ip="1.1.1.1";
    s.port=53;
    s.timeout_ms=3000;
    return s;
}

void usage(){
    std::cout
        <<"NativeDNSCoreHost --config <file> [--transparent] [--port N]\n"
        <<"NativeDNSCoreHost --register-autostart <config>\n"
        <<"NativeDNSCoreHost --unregister-autostart\n";
}
}

int main(int argc,char** argv){
    try{
        std::filesystem::path config_path;
        std::filesystem::path autostart_config;
        bool transparent=false;
        bool register_autostart=false;
        bool unregister_autostart=false;
        uint16_t port=0;

        for(int i=1;i<argc;++i){
            const std::string arg=argv[i];
            if(arg=="--config"&&i+1<argc)config_path=argv[++i];
            else if(arg=="--transparent")transparent=true;
            else if(arg=="--port"&&i+1<argc)port=static_cast<uint16_t>(std::stoul(argv[++i]));
            else if(arg=="--register-autostart"&&i+1<argc){
                register_autostart=true;
                autostart_config=argv[++i];
            }
            else if(arg=="--unregister-autostart")unregister_autostart=true;
            else if(arg=="--help"){usage();return 0;}
            else {
                std::cerr<<"Unknown or incomplete argument: "<<arg<<"\n";
                usage();
                return 2;
            }
        }

        if(register_autostart&&unregister_autostart)
            throw nd::Error("AUTOSTART","Conflicting autostart operations");

        if(register_autostart){
            nd::enable_autostart(nd::platform::executable_path(),autostart_config);
            return 0;
        }
        if(unregister_autostart){
            nd::disable_autostart();
            return 0;
        }

        nd::platform::ProcessInstanceLock instanceLock("NativeDNS.CoreHost.Instance.v1");
        if(!instanceLock.acquired()){
            std::cerr<<"NativeDNSCoreHost is already running\n";
            return 0;
        }

        if(config_path.empty()){
            config_path=nd::platform::user_config_directory()/"NativeDNS.xml";
            if(!std::filesystem::exists(config_path)){
                std::filesystem::create_directories(config_path.parent_path());
                nd::save_config(nd::default_config(),config_path);
            }
        }

        auto config=nd::load_config(config_path);
        nd::CoreHost host(
            std::move(config),
            default_original(),
            port,
            nd::core_pipe_name,
            transparent?nd::InterceptionMode::transparent:nd::InterceptionMode::local_proxy);
        host.start();
        host.wait_for_shutdown();
        const bool restart=host.restart_requested();
        host.stop();
        return restart?23:0;
    }catch(const nd::Error& e){
        std::cerr<<e.code<<": "<<e.what()<<"\n";
        return 10;
    }catch(const std::exception& e){
        std::cerr<<"INTERNAL: "<<e.what()<<"\n";
        return 11;
    }
}
