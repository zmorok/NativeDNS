#include <nativedns/host.hpp>
#include <nativedns/platform.hpp>
#include <charconv>
#include <sstream>

namespace nd {
CoreHost::CoreHost(Config config,Server original,uint16_t local_port,std::string pipe_name,InterceptionMode mode)
    :config_(std::move(config)),original_(std::move(original)),local_port_(local_port),pipe_name_(std::move(pipe_name)),
      log_pipe_name_(pipe_name_==core_pipe_name?core_log_pipe_name:pipe_name_+".logs"),logger_(4096){
    validate(config_);
    if(config_.logging.file_enabled){auto path=std::filesystem::path(config_.logging.directory)/"NativeDNS.log";if(path.is_relative())path=platform::user_config_directory()/path;logger_.configure_file(true,config_.logging.file,path);}
    router_=std::make_shared<Router>(config_,logger_);
    if(mode==InterceptionMode::transparent)interception_=make_platform_interception(config_,logger_,local_port_?local_port_:53);
    else interception_=std::make_unique<LocalProxy>(router_,original_,logger_,local_port_);
    ipc_=std::make_unique<PipeServer>(pipe_name_,[this](IpcOperation op,const std::string& payload){return handle(op,payload);});
    log_ipc_=std::make_unique<PipeServer>(log_pipe_name_,[this](IpcOperation op,const std::string& payload){if(op!=IpcOperation::logs)throw Error("IPC_PROTOCOL","Log IPC endpoint only accepts logs operation");return handle(op,payload);});
}
CoreHost::~CoreHost(){stop();}
void CoreHost::start(){
    std::lock_guard lock(mutex_);if(interception_->status().state!=State::stopped)throw Error("LIFECYCLE","Core is not stopped");shutdown_requested_=false;restart_requested_=false;interception_->start();
    try{ipc_->start();log_ipc_->start();}catch(...){if(ipc_)ipc_->stop();interception_->stop();throw;}
    const auto value=interception_->status();logger_.write(Level::normal,"CORE_STARTED","Core host started; port="+std::to_string(value.port)+" transparent="+(value.transparent?"1":"0"));
}
void CoreHost::stop(){
    if(log_ipc_) log_ipc_->stop();
    if(ipc_) ipc_->stop();
    std::lock_guard lock(mutex_);
    if(interception_) interception_->stop();
    shutdown_requested_=true;
    shutdown_cv_.notify_all();
}
void CoreHost::wait_for_shutdown(){
    std::unique_lock lock(mutex_);
    for(;;){if(shutdown_cv_.wait_for(lock,std::chrono::milliseconds(500),[&]{return shutdown_requested_;}))return;const auto value=interception_->status();if(value.state==State::error)throw Error(value.error_code.empty()?"INTERCEPTION_FAILED":value.error_code,value.error_message.empty()?"Interception backend failed":value.error_message);}
}
InterceptionStatus CoreHost::status() const{std::lock_guard lock(mutex_);return interception_->status();}
IpcResponse CoreHost::handle(IpcOperation operation,const std::string& payload){
    if(operation==IpcOperation::ping)return{0,"NativeDNS Core API 1"};
    if(operation==IpcOperation::status){const auto value=interception_->status();const char* state="ERROR";switch(value.state){case State::stopped:state="STOPPED";break;case State::starting:state="STARTING";break;case State::running:state="RUNNING";break;case State::stopping:state="STOPPING";break;case State::error:break;}auto text=std::string(state)+" port="+std::to_string(value.port)+" transparent="+(value.transparent?"1":"0")+" udp="+(value.udp?"1":"0")+" tcp="+(value.tcp?"1":"0");if(!value.error_code.empty())text+=" error="+value.error_code+" "+value.error_message;return{0,std::move(text)};}
    if(operation==IpcOperation::start){std::lock_guard lock(mutex_);interception_->start();return{0,"RUNNING port="+std::to_string(interception_->status().port)};}
    if(operation==IpcOperation::stop){std::lock_guard lock(mutex_);interception_->stop();return{0,"STOPPED"};}
    if(operation==IpcOperation::shutdown||operation==IpcOperation::restart){{std::lock_guard lock(mutex_);if(operation==IpcOperation::restart)restart_requested_=true;shutdown_requested_=true;}shutdown_cv_.notify_all();return{0,operation==IpcOperation::restart?"RESTARTING":"SHUTTING_DOWN"};}
    if(operation==IpcOperation::logs){uint64_t after=0,wait_ms=0,requested_level=static_cast<uint64_t>(config_.logging.screen);const auto separator=payload.find('\t');const auto level_separator=separator==std::string::npos?std::string::npos:payload.find('\t',separator+1);const auto sequence=payload.substr(0,separator);if(!sequence.empty()){auto[end,error]=std::from_chars(sequence.data(),sequence.data()+sequence.size(),after);if(error!=std::errc{}||end!=sequence.data()+sequence.size())throw Error("IPC_PROTOCOL","logs payload has invalid sequence");}if(separator!=std::string::npos){const auto wait=payload.substr(separator+1,level_separator==std::string::npos?std::string::npos:level_separator-separator-1);auto[end,error]=std::from_chars(wait.data(),wait.data()+wait.size(),wait_ms);if(wait.empty()||error!=std::errc{}||end!=wait.data()+wait.size()||wait_ms>1000)throw Error("IPC_PROTOCOL","logs wait must be 0..1000 ms");}if(level_separator!=std::string::npos){const auto level=payload.substr(level_separator+1);auto[end,error]=std::from_chars(level.data(),level.data()+level.size(),requested_level);if(level.empty()||error!=std::errc{}||end!=level.data()+level.size()||requested_level>3)throw Error("IPC_PROTOCOL","logs level must be 0..3");}std::ostringstream output;const auto level=static_cast<Level>(requested_level);const auto events=wait_ms?logger_.wait_snapshot(level,after,std::chrono::milliseconds(wait_ms)):logger_.snapshot(level,after);for(const auto& event:events){const auto line=std::to_string(event.sequence)+'\t'+std::to_string(static_cast<unsigned>(event.level))+'\t'+event.code+'\t'+event.message+'\n';if(output.tellp()+static_cast<std::streamoff>(line.size())>1024*1024)break;output<<line;}return{0,output.str()};}
    if(operation==IpcOperation::clear_file_log){logger_.clear_file();return{0,"FILE_LOG_CLEARED"};}
    if(operation==IpcOperation::clear_display){logger_.clear_display();return{0,"DISPLAY_LOG_CLEARED"};}
    throw Error("IPC_PROTOCOL","Unsupported operation");
}
}
