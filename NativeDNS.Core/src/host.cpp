#include <nativedns/host.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/detail/fault_injection.hpp>
#include <charconv>
#include <sstream>
#include <filesystem>

namespace nd {
namespace {
std::filesystem::path file_log_directory(const LoggingSettings& settings){
    if(platform::is_elevated()){platform::prepare_privileged_log_directory();return platform::privileged_log_directory();}
    auto directory=std::filesystem::path(settings.directory);
    if(directory.is_relative()) directory=platform::application_root_directory()/directory;
    return directory;
}
}
CoreHost::CoreHost(Config config,Server original,uint16_t local_port,std::string pipe_name,InterceptionMode mode)
    :config_(std::move(config)),original_(std::move(original)),local_port_(local_port),pipe_name_(std::move(pipe_name)),
      log_pipe_name_(pipe_name_==core_pipe_name?core_log_pipe_name:pipe_name_+".logs"),logger_(4096){
    validate(config_);
    logger_.set_display_level(config_.logging.screen);
    if(mode==InterceptionMode::transparent)prepare_secure_endpoints(config_);
    try{
        if(config_.logging.file_enabled)file_log_path_=timestamped_log_path(file_log_directory(config_.logging));
        logger_.configure_file(config_.logging.file_enabled,config_.logging.file,file_log_path_);file_log_enabled_=config_.logging.file_enabled;
    }
    catch(const std::exception& error){logger_.write(Level::errors_only,"FILE_LOG_INIT_FAILED",error.what());}
    logger_.write(Level::normal,"CORE_INITIALIZING","Core host initialization started");
    logger_.write(Level::normal,"SYSTEM_ENVIRONMENT",platform::system_summary());
    logger_.write(Level::verbose,"CORE_PATHS","executable="+platform::executable_path().string()+" working_directory="+std::filesystem::current_path().string()+" log="+(file_log_path_.empty()?"disabled":file_log_path_.string()));
    logger_.write(Level::verbose,"CONFIG_SUMMARY","servers="+std::to_string(config_.servers.size())+" rules="+std::to_string(config_.rules.size())+" mode="+(mode==InterceptionMode::transparent?"transparent":"local_proxy"));
    router_=std::make_shared<Router>(config_,logger_);
    if(mode==InterceptionMode::transparent)interception_=make_platform_interception(config_,logger_,local_port_?local_port_:53);
    else interception_=std::make_unique<LocalProxy>(router_,original_,logger_,local_port_);
    ipc_=std::make_unique<PipeServer>(pipe_name_,[this](IpcOperation op,const std::string& payload){return handle(op,payload);});
    log_ipc_=std::make_unique<PipeServer>(log_pipe_name_,[this](IpcOperation op,const std::string& payload){if(op!=IpcOperation::logs)throw Error("IPC_PROTOCOL","Log IPC endpoint only accepts logs operation");return handle(op,payload);});
}
CoreHost::~CoreHost(){stop();}
void CoreHost::start(){
    std::lock_guard lock(mutex_);if(interception_->status().state!=State::stopped)throw Error("LIFECYCLE","Core is not stopped");shutdown_requested_=false;restart_requested_=false;
    stopped_=false;
    const char* stage="interception";
    try{
        logger_.write(Level::verbose,"INTERCEPTION_STARTING","Starting DNS interception backend");
        interception_->start();
        stage="command IPC";
        detail::fault_point("core.command_ipc");
        logger_.write(Level::verbose,"IPC_STARTING","Starting command and live-log IPC endpoints");
        ipc_->start();
        stage="log IPC";
        detail::fault_point("core.log_ipc");
        log_ipc_->start();
        const auto value=interception_->status();logger_.write(Level::normal,"CORE_STARTED","Core host started; port="+std::to_string(value.port)+" transparent="+(value.transparent?"1":"0"));
    }catch(...){
        const auto failure=std::current_exception();
        try{std::rethrow_exception(failure);}catch(const std::exception& error){logger_.write(Level::errors_only,"CORE_START_FAILED",std::string("stage=")+stage+" error="+error.what());}catch(...){logger_.write(Level::errors_only,"CORE_START_FAILED",std::string("stage=")+stage+" error=unknown");}
        if(log_ipc_)log_ipc_->stop();
        if(ipc_)ipc_->stop();
        if(interception_)interception_->stop();
        stopped_=true;
        logger_.write(Level::verbose,"CORE_START_ROLLBACK","Released resources acquired before "+std::string(stage)+" startup failure");
        std::rethrow_exception(failure);
    }
}
void CoreHost::stop(){
    if(stopped_.exchange(true))return;
    logger_.write(Level::verbose,"CORE_STOPPING","Core host shutdown started");
    if(log_ipc_) log_ipc_->stop();
    if(ipc_) ipc_->stop();
    std::lock_guard lock(mutex_);
    if(interception_) interception_->stop();
    shutdown_requested_=true;
    shutdown_cv_.notify_all();
    logger_.write(Level::normal,"CORE_STOPPED","Core host stopped");
}
void CoreHost::wait_for_shutdown(){
    std::unique_lock lock(mutex_);
    for(;;){if(shutdown_cv_.wait_for(lock,std::chrono::milliseconds(500),[&]{return shutdown_requested_;}))return;const auto value=interception_->status();if(value.state==State::error)throw Error(value.error_code.empty()?"INTERCEPTION_FAILED":value.error_code,value.error_message.empty()?"Interception backend failed":value.error_message);}
}
InterceptionStatus CoreHost::status() const{std::lock_guard lock(mutex_);return interception_->status();}
IpcResponse CoreHost::handle(IpcOperation operation,const std::string& payload){
    if(operation!=IpcOperation::logs&&operation!=IpcOperation::configure_file_log&&!payload.empty())
        throw Error("IPC_PROTOCOL","This operation requires an empty payload");
    if(operation==IpcOperation::ping)return{0,"NativeDNS Core API 1"};
    if(operation==IpcOperation::status){const auto value=interception_->status();const char* state="ERROR";switch(value.state){case State::stopped:state="STOPPED";break;case State::starting:state="STARTING";break;case State::running:state="RUNNING";break;case State::stopping:state="STOPPING";break;case State::error:break;}auto text=std::string(state)+" port="+std::to_string(value.port)+" transparent="+(value.transparent?"1":"0")+" udp="+(value.udp?"1":"0")+" tcp="+(value.tcp?"1":"0");if(!value.error_code.empty())text+=" error="+value.error_code+" "+value.error_message;return{0,std::move(text)};}
    if(operation==IpcOperation::start){std::lock_guard lock(mutex_);interception_->start();return{0,"RUNNING port="+std::to_string(interception_->status().port)};}
    if(operation==IpcOperation::stop){std::lock_guard lock(mutex_);interception_->stop();return{0,"STOPPED"};}
    if(operation==IpcOperation::shutdown||operation==IpcOperation::restart){{std::lock_guard lock(mutex_);if(operation==IpcOperation::restart)restart_requested_=true;shutdown_requested_=true;}shutdown_cv_.notify_all();return{0,operation==IpcOperation::restart?"RESTARTING":"SHUTTING_DOWN"};}
    if(operation==IpcOperation::logs){uint64_t after=0,wait_ms=0,requested_level=static_cast<uint64_t>(config_.logging.screen);const auto separator=payload.find('\t');const auto level_separator=separator==std::string::npos?std::string::npos:payload.find('\t',separator+1);const auto sequence=payload.substr(0,separator);if(!sequence.empty()){auto[end,error]=std::from_chars(sequence.data(),sequence.data()+sequence.size(),after);if(error!=std::errc{}||end!=sequence.data()+sequence.size())throw Error("IPC_PROTOCOL","logs payload has invalid sequence");}if(separator!=std::string::npos){const auto wait=payload.substr(separator+1,level_separator==std::string::npos?std::string::npos:level_separator-separator-1);auto[end,error]=std::from_chars(wait.data(),wait.data()+wait.size(),wait_ms);if(wait.empty()||error!=std::errc{}||end!=wait.data()+wait.size()||wait_ms>1000)throw Error("IPC_PROTOCOL","logs wait must be 0..1000 ms");}if(level_separator!=std::string::npos){const auto level=payload.substr(level_separator+1);auto[end,error]=std::from_chars(level.data(),level.data()+level.size(),requested_level);if(level.empty()||error!=std::errc{}||end!=level.data()+level.size()||requested_level>3)throw Error("IPC_PROTOCOL","logs level must be 0..3");}std::ostringstream output;const auto level=static_cast<Level>(requested_level);const auto events=wait_ms?logger_.wait_snapshot(level,after,std::chrono::milliseconds(wait_ms)):logger_.snapshot(level,after);for(const auto& event:events){const auto timestamp=std::chrono::duration_cast<std::chrono::milliseconds>(event.time.time_since_epoch()).count();const auto line=std::to_string(event.sequence)+'\t'+std::to_string(static_cast<unsigned>(event.level))+'\t'+std::to_string(timestamp)+'\t'+event.code+'\t'+event.message+'\n';if(output.tellp()+static_cast<std::streamoff>(line.size())>1024*1024)break;output<<line;}return{0,output.str()};}
    if(operation==IpcOperation::clear_file_log){logger_.clear_file();return{0,"FILE_LOG_CLEARED"};}
    if(operation==IpcOperation::configure_file_log){
        std::lock_guard lock(mutex_);
        const auto separator=payload.find('\t');
        if(separator==std::string::npos)throw Error("IPC_PROTOCOL","file log payload must be enabled<TAB>level");
        const auto enabled_text=payload.substr(0,separator),level_text=payload.substr(separator+1);
        if(enabled_text!="0"&&enabled_text!="1")throw Error("IPC_PROTOCOL","file log enabled must be 0 or 1");
        uint64_t requested_level=0;
        auto[end,error]=std::from_chars(level_text.data(),level_text.data()+level_text.size(),requested_level);
        if(level_text.empty()||error!=std::errc{}||end!=level_text.data()+level_text.size()||requested_level>3)throw Error("IPC_PROTOCOL","file log level must be 0..3");
        const bool enabled=enabled_text=="1";
        if(enabled&&!file_log_enabled_)file_log_path_=timestamped_log_path(file_log_directory(config_.logging));
        logger_.configure_file(enabled,static_cast<Level>(requested_level),file_log_path_);
        file_log_enabled_=enabled;
        if(enabled)logger_.write(Level::normal,"FILE_LOG_CONFIGURED","path="+file_log_path_.string()+" level="+level_text);
        return{0,enabled?"FILE_LOG_ENABLED":"FILE_LOG_DISABLED"};
    }
    if(operation==IpcOperation::clear_display){logger_.clear_display();return{0,"DISPLAY_LOG_CLEARED"};}
    throw Error("IPC_PROTOCOL","Unsupported operation");
}
}
