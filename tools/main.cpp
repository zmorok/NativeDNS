#include <nativedns/config.hpp>
#include <nativedns/autostart.hpp>
#include <nativedns/dns.hpp>
#include <nativedns/router.hpp>
#include <nativedns/interception.hpp>
#include <nativedns/ipc.hpp>
#include <algorithm>
#include <filesystem>
#include <iostream>

namespace {
int print_test(const nd::TestResult& result){std::cout<<(result.success?"OK":"ERROR")<<" protocol="<<nd::protocol_name(result.protocol)<<" rtt_ms="<<result.rtt_ms<<" rcode="<<result.rcode<<" "<<result.error_code<<" "<<result.message;for(const auto& a:result.addresses)std::cout<<" "<<a;std::cout<<'\n';return result.success?0:1;}
void usage(){std::cerr<<"Usage:\n"
"  nativednsctl core status|start|stop|logs [AFTER [WAIT_MS]]|clear-file|clear-display|shutdown|restart\n"
"  nativednsctl config import-yoga INPUT OUTPUT\n"
"  nativednsctl config export INPUT OUTPUT\n"
"  nativednsctl rules list CONFIG\n"
"  nativednsctl rules match CONFIG HOST\n"
"  nativednsctl servers list CONFIG\n"
"  nativednsctl servers test CONFIG ID\n"
"  nativednsctl probe udp|tcp IP [HOST [PORT]]\n"
"  nativednsctl resolve CONFIG HOST ORIGINAL_IP [ORIGINAL_PORT]\n"
"  nativednsctl serve CONFIG ORIGINAL_IP [LOCAL_PORT]\n"
"  nativednsctl autostart status|enable COREHOST CONFIG|disable\n";}
}
int main(int argc,char** argv){
    try{
        if(argc>=3&&std::string(argv[1])=="core"){
            const std::string cmd=argv[2];nd::IpcOperation op;
            if(cmd=="status")op=nd::IpcOperation::status;else if(cmd=="start")op=nd::IpcOperation::start;else if(cmd=="stop")op=nd::IpcOperation::stop;else if(cmd=="logs")op=nd::IpcOperation::logs;else if(cmd=="shutdown")op=nd::IpcOperation::shutdown;else if(cmd=="restart")op=nd::IpcOperation::restart;else if(cmd=="clear-file")op=nd::IpcOperation::clear_file_log;else if(cmd=="clear-display")op=nd::IpcOperation::clear_display;else throw nd::Error("COMMAND","Unknown core command");
            std::string payload=argc>=4?argv[3]:"";if(op==nd::IpcOperation::logs&&argc>=5){payload.push_back('\t');payload+=argv[4];}const auto endpoint=op==nd::IpcOperation::logs?nd::core_log_pipe_name:nd::core_pipe_name;auto r=nd::pipe_request(endpoint,op,payload,op==nd::IpcOperation::logs?2000:3000);std::cout<<r.payload;if(r.payload.empty()||r.payload.back()!='\n')std::cout<<'\n';return r.status?1:0;
        }
        if(argc>=3&&std::string(argv[1])=="autostart"){
            const std::string cmd=argv[2];if(cmd=="status"&&argc==3){auto st=nd::autostart_status();std::cout<<(st.enabled?"ENABLED":"DISABLED");if(st.enabled)std::cout<<" executable="<<st.executable.string()<<" arguments="<<st.arguments;std::cout<<'\n';return 0;}if(cmd=="enable"&&argc==5){nd::enable_autostart(std::filesystem::absolute(argv[3]),std::filesystem::absolute(argv[4]));std::cout<<"ENABLED\n";return 0;}if(cmd=="disable"&&argc==3){nd::disable_autostart();std::cout<<"DISABLED\n";return 0;}throw nd::Error("COMMAND","Invalid autostart command");
        }
        if((argc==5||argc==6)&&std::string(argv[1])=="resolve"){
            nd::Logger logger;nd::Router router(nd::load_config(argv[2]),logger);nd::Server original;original.name="Original destination";original.ip=argv[4];if(argc==6){const int port=std::stoi(argv[5]);if(port<1||port>65535)throw nd::Error("PORT","Invalid port");original.port=static_cast<uint16_t>(port);}const auto query=nd::make_query(argv[3]);auto routed=router.route(query,original);for(const auto&e:logger.snapshot(nd::Level::debug))std::cerr<<e.code<<" "<<e.message<<'\n';if(routed.disposition==nd::Disposition::silent_drop){std::cout<<"BLOCKED: silent drop\n";return 1;}if(routed.disposition==nd::Disposition::forward_original)routed.packet=nd::make_transport(original.protocol)->exchange(routed.packet,original);const auto response=nd::parse_response(routed.packet,nd::parse_question(query));std::cout<<"rule="<<routed.rule_id<<" server="<<routed.server_id<<" action="<<nd::action_name(routed.action)<<" rcode="<<response.rcode;for(const auto&a:response.addresses)std::cout<<" "<<a;std::cout<<'\n';return response.rcode||!routed.error_code.empty()?1:0;
        }
        if((argc==4||argc==5)&&std::string(argv[1])=="serve"){
            nd::Logger logger;auto router=std::make_shared<nd::Router>(nd::load_config(argv[2]),logger);nd::Server original;original.name="Original resolver";original.ip=argv[3];const int port=argc==5?std::stoi(argv[4]):0;if(port<0||port>65535)throw nd::Error("PORT","Invalid port");nd::LocalProxy proxy(router,original,logger,static_cast<uint16_t>(port));proxy.start();std::cout<<"Local UDP/TCP proxy at 127.0.0.1:"<<proxy.status().port<<". Press Enter to stop.\n"<<std::flush;std::string line;std::getline(std::cin,line);proxy.stop();return 0;
        }
        if(argc>=4&&argc<=6&&std::string(argv[1])=="probe"){
            nd::Server server;server.id=1;server.name="Command line probe";server.ip=argv[3];const std::string type=argv[2];if(type=="udp")server.protocol=nd::Protocol::udp;else if(type=="tcp")server.protocol=nd::Protocol::tcp;else throw nd::Error("PROTOCOL","probe expects udp or tcp");if(argc==6){const int port=std::stoi(argv[5]);if(port<1||port>65535)throw nd::Error("PORT","Invalid port");server.port=static_cast<uint16_t>(port);}return print_test(nd::test_server(server,argc>=5?argv[4]:"iana.org"));
        }
        if(argc>=4&&std::string(argv[1])=="servers"){
            auto config=nd::load_config(argv[3]);if(std::string(argv[2])=="list"&&argc==4){for(const auto&server:config.servers)std::cout<<server.id<<'\t'<<server.name<<'\t'<<nd::protocol_name(server.protocol)<<'\n';return 0;}if(std::string(argv[2])=="test"&&argc==5){const auto id=std::stoul(argv[4]);const auto it=std::find_if(config.servers.begin(),config.servers.end(),[&](const nd::Server&s){return s.id==id;});if(it==config.servers.end())throw nd::Error("SERVER_ID","Unknown server ID");return print_test(nd::test_server(*it,config.test_target));}}
        if(argc==5&&std::string(argv[1])=="config"&&std::string(argv[2])=="import-yoga"){auto result=nd::import_yoga(argv[3]);nd::save_config(result.config,argv[4]);for(const auto&w:result.warnings)std::cerr<<"WARNING: "<<w<<'\n';std::cout<<result.config.servers.size()<<" servers, "<<result.config.rules.size()<<" rules\n";return 0;}
        if(argc==5&&std::string(argv[1])=="config"&&std::string(argv[2])=="export"){nd::save_config(nd::load_config(argv[3]),argv[4]);return 0;}
        if(argc>=4&&std::string(argv[1])=="rules"){
            auto config=nd::load_config(argv[3]);if(std::string(argv[2])=="list"&&argc==4){for(const auto&r:config.rules)std::cout<<r.id<<'\t'<<r.name<<'\t'<<nd::action_name(r.action)<<'\t'<<r.server_id<<'\n';return 0;}if(std::string(argv[2])=="match"&&argc==5){const std::string host=argv[4];const auto&r=nd::match_rule(config,host);std::cout<<r.name<<'\t'<<nd::action_name(r.action)<<'\t'<<r.server_id<<'\n';return 0;}}
        usage();return 2;
    }catch(const nd::Error&e){std::cerr<<e.code<<": "<<e.what()<<'\n';return 1;}catch(const std::exception&e){std::cerr<<"ERROR: "<<e.what()<<'\n';return 1;}
}
