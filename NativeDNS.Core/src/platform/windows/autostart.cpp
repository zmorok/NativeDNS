#include <nativedns/autostart.hpp>
#include <nativedns/config.hpp>
#include <windows.h>
#include <taskschd.h>
#include <oleauto.h>

namespace nd {
namespace {
constexpr wchar_t task_name[]=L"NativeDNS Core";
constexpr wchar_t gui_task_name[]=L"NativeDNS GUI";

template<class T> struct ComPtr {
    T* value=nullptr;
    ~ComPtr() { if(value) value->Release(); }
    ComPtr()=default;
    ComPtr(const ComPtr&)=delete;
    ComPtr& operator=(const ComPtr&)=delete;
    ComPtr(ComPtr&& other) noexcept:value(other.value) { other.value=nullptr; }
    ComPtr& operator=(ComPtr&& other) noexcept { if(this!=&other) { if(value) value->Release(); value=other.value; other.value=nullptr; } return *this; }
    T** put() { return &value; }
    T* operator->() const { return value; }
};
struct Bstr {
    BSTR value=nullptr;
    explicit Bstr(const wchar_t* text):value(SysAllocString(text)) { if(!value) throw Error("AUTOSTART","Cannot allocate task string"); }
    explicit Bstr(const std::wstring& text):value(SysAllocStringLen(text.data(),static_cast<UINT>(text.size()))) { if(!value) throw Error("AUTOSTART","Cannot allocate task string"); }
    ~Bstr() { SysFreeString(value); }
};
struct OutBstr {
    BSTR value=nullptr;
    ~OutBstr() { SysFreeString(value); }
    BSTR* put() { return &value; }
};
struct ComApartment {
    bool initialized=false;
    ComApartment() {
        const HRESULT result=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        if(SUCCEEDED(result)) initialized=true;
        else if(result!=RPC_E_CHANGED_MODE) fail(result,"Initialize Task Scheduler COM");
    }
    ~ComApartment() { if(initialized) CoUninitialize(); }
    static void fail(HRESULT result,const char* operation) {
        const auto code=result==E_ACCESSDENIED||result==HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)?"ELEVATION_REQUIRED":"AUTOSTART";
        throw Error(code,std::string(operation)+" failed: "+std::to_string(static_cast<uint32_t>(result)));
    }
};
void check(HRESULT result,const char* operation) { if(FAILED(result)) ComApartment::fail(result,operation); }
VARIANT empty_variant() { VARIANT value; VariantInit(&value); return value; }

struct Scheduler {
    ComApartment apartment;
    ComPtr<ITaskService> service;
    ComPtr<ITaskFolder> root;
    Scheduler() {
        check(CoCreateInstance(CLSID_TaskScheduler,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(service.put())),"Create Task Scheduler service");
        auto empty=empty_variant();
        check(service->Connect(empty,empty,empty,empty),"Connect Task Scheduler service");
        Bstr path(L"\\");
        check(service->GetFolder(path.value,root.put()),"Open Task Scheduler root");
    }
};

std::wstring quote_argument(const std::wstring& value) {
    std::wstring result=L"\"";
    size_t slashes=0;
    for(const wchar_t character:value) {
        if(character==L'\\') { ++slashes; continue; }
        if(character==L'\"') { result.append(slashes*2+1,L'\\'); result.push_back(character); slashes=0; continue; }
        result.append(slashes,L'\\'); slashes=0; result.push_back(character);
    }
    result.append(slashes*2,L'\\'); result.push_back(L'\"');
    return result;
}
}

void enable_autostart(const std::filesystem::path& executable,const std::filesystem::path& config,
                      const std::filesystem::path& gui_executable) {
    const auto gui=gui_executable.empty()?executable.parent_path()/L"NativeDNS.exe":gui_executable;
    if(!std::filesystem::is_regular_file(executable)) throw Error("AUTOSTART","NativeDNS executable does not exist");
    if(!std::filesystem::is_regular_file(config)) throw Error("AUTOSTART","Autostart config does not exist");
    if(!std::filesystem::is_regular_file(gui)) throw Error("AUTOSTART","NativeDNS GUI executable does not exist");
    (void)load_config(config);
    Scheduler scheduler;
    ComPtr<ITaskDefinition> definition;
    check(scheduler.service->NewTask(0,definition.put()),"Create task definition");

    ComPtr<IRegistrationInfo> registration;
    check(definition->get_RegistrationInfo(registration.put()),"Open task registration info");
    Bstr author(L"NativeDNS"),description(L"Starts the NativeDNS transparent DNS Core on demand for the desktop application.");
    check(registration->put_Author(author.value),"Set task author");
    check(registration->put_Description(description.value),"Set task description");

    ComPtr<IPrincipal> principal;
    check(definition->get_Principal(principal.put()),"Open task principal");
    check(principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN),"Set task logon type");
    check(principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST),"Set task run level");

    ComPtr<ITaskSettings> settings;
    check(definition->get_Settings(settings.put()),"Open task settings");
    check(settings->put_Enabled(VARIANT_TRUE),"Enable task");
    check(settings->put_Hidden(VARIANT_TRUE),"Hide background task");
    check(settings->put_StartWhenAvailable(VARIANT_TRUE),"Enable delayed task start");
    check(settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE),"Allow task on battery");
    check(settings->put_StopIfGoingOnBatteries(VARIANT_FALSE),"Keep task on battery");
    check(settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW),"Set single task instance");
    check(settings->put_RestartCount(3),"Set task restart count");
    Bstr restart_interval(L"PT1M"),execution_limit(L"PT0S");
    check(settings->put_RestartInterval(restart_interval.value),"Set task restart interval");
    check(settings->put_ExecutionTimeLimit(execution_limit.value),"Remove task execution limit");

    ComPtr<IActionCollection> actions;
    check(definition->get_Actions(actions.put()),"Open task actions");
    ComPtr<IAction> action;
    check(actions->Create(TASK_ACTION_EXEC,action.put()),"Create executable action");
    ComPtr<IExecAction> execute;
    check(action->QueryInterface(IID_PPV_ARGS(execute.put())),"Configure executable action");
    const auto absolute_executable=std::filesystem::absolute(executable).lexically_normal();
    const auto absolute_config=std::filesystem::absolute(config).lexically_normal();
    const std::wstring arguments=L"--config "+quote_argument(absolute_config.wstring())+L" --transparent";
    Bstr executable_text(absolute_executable.wstring()),arguments_text(arguments),working_directory(absolute_executable.parent_path().wstring());
    check(execute->put_Path(executable_text.value),"Set task executable");
    check(execute->put_Arguments(arguments_text.value),"Set task arguments");
    check(execute->put_WorkingDirectory(working_directory.value),"Set task working directory");

    Bstr name(task_name);
    auto empty=empty_variant();
    ComPtr<IRegisteredTask> registered;
    check(scheduler.root->RegisterTaskDefinition(name.value,definition.value,TASK_CREATE_OR_UPDATE,empty,empty,
        TASK_LOGON_INTERACTIVE_TOKEN,empty,registered.put()),"Register NativeDNS autostart task");

    ComPtr<ITaskDefinition> gui_definition;
    check(scheduler.service->NewTask(0,gui_definition.put()),"Create GUI task definition");
    ComPtr<IRegistrationInfo> gui_registration;
    check(gui_definition->get_RegistrationInfo(gui_registration.put()),"Open GUI task registration info");
    Bstr gui_author(L"NativeDNS"),gui_description(L"Starts the NativeDNS desktop application in the system tray.");
    check(gui_registration->put_Author(gui_author.value),"Set GUI task author");
    check(gui_registration->put_Description(gui_description.value),"Set GUI task description");
    ComPtr<IPrincipal> gui_principal;
    check(gui_definition->get_Principal(gui_principal.put()),"Open GUI task principal");
    check(gui_principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN),"Set GUI task logon type");
    check(gui_principal->put_RunLevel(TASK_RUNLEVEL_LUA),"Keep GUI task unprivileged");
    ComPtr<ITaskSettings> gui_settings;
    check(gui_definition->get_Settings(gui_settings.put()),"Open GUI task settings");
    check(gui_settings->put_Enabled(VARIANT_TRUE),"Enable GUI task");
    check(gui_settings->put_Hidden(VARIANT_TRUE),"Hide GUI task metadata");
    check(gui_settings->put_StartWhenAvailable(VARIANT_TRUE),"Enable delayed GUI start");
    check(gui_settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE),"Allow GUI task on battery");
    check(gui_settings->put_StopIfGoingOnBatteries(VARIANT_FALSE),"Keep GUI task on battery");
    check(gui_settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW),"Set single GUI task instance");
    check(gui_settings->put_RestartCount(3),"Set GUI restart count");
    Bstr gui_restart_interval(L"PT1M"),gui_execution_limit(L"PT0S");
    check(gui_settings->put_RestartInterval(gui_restart_interval.value),"Set GUI restart interval");
    check(gui_settings->put_ExecutionTimeLimit(gui_execution_limit.value),"Remove GUI task execution limit");
    ComPtr<ITriggerCollection> gui_triggers;
    check(gui_definition->get_Triggers(gui_triggers.put()),"Open GUI task triggers");
    ComPtr<ITrigger> gui_trigger;
    check(gui_triggers->Create(TASK_TRIGGER_LOGON,gui_trigger.put()),"Create GUI logon trigger");
    ComPtr<ILogonTrigger> gui_logon;
    check(gui_trigger->QueryInterface(IID_PPV_ARGS(gui_logon.put())),"Configure GUI logon trigger");
    Bstr gui_trigger_id(L"NativeDNS GUI user logon"),gui_delay(L"PT5S");
    check(gui_logon->put_Id(gui_trigger_id.value),"Set GUI logon trigger id");
    check(gui_logon->put_Delay(gui_delay.value),"Set GUI logon delay");
    ComPtr<IActionCollection> gui_actions;
    check(gui_definition->get_Actions(gui_actions.put()),"Open GUI task actions");
    ComPtr<IAction> gui_action;
    check(gui_actions->Create(TASK_ACTION_EXEC,gui_action.put()),"Create GUI executable action");
    ComPtr<IExecAction> gui_execute;
    check(gui_action->QueryInterface(IID_PPV_ARGS(gui_execute.put())),"Configure GUI executable action");
    const auto absolute_gui=std::filesystem::absolute(gui).lexically_normal();
    Bstr gui_path(absolute_gui.wstring()),gui_arguments(L"--background"),gui_working_directory(absolute_gui.parent_path().wstring());
    check(gui_execute->put_Path(gui_path.value),"Set GUI task executable");
    check(gui_execute->put_Arguments(gui_arguments.value),"Set GUI task arguments");
    check(gui_execute->put_WorkingDirectory(gui_working_directory.value),"Set GUI task working directory");
    Bstr gui_name(gui_task_name);
    ComPtr<IRegisteredTask> gui_registered;
    check(scheduler.root->RegisterTaskDefinition(gui_name.value,gui_definition.value,TASK_CREATE_OR_UPDATE,empty,empty,
        TASK_LOGON_INTERACTIVE_TOKEN,empty,gui_registered.put()),"Register NativeDNS GUI autostart task");
}

void disable_autostart() {
    Scheduler scheduler;
    Bstr name(task_name);
    const HRESULT result=scheduler.root->DeleteTask(name.value,0);
    if(FAILED(result)&&result!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) check(result,"Delete NativeDNS autostart task");
    Bstr gui_name(gui_task_name);
    const HRESULT gui_result=scheduler.root->DeleteTask(gui_name.value,0);
    if(FAILED(gui_result)&&gui_result!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) check(gui_result,"Delete NativeDNS GUI autostart task");
}

AutostartStatus autostart_status() {
    Scheduler scheduler;
    AutostartStatus result;

    Bstr core_name(task_name);
    ComPtr<IRegisteredTask> core_task;
    const HRESULT core_found=scheduler.root->GetTask(core_name.value,core_task.put());
    VARIANT_BOOL core_enabled=VARIANT_FALSE;
    if(core_found!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)){
        check(core_found,"Read NativeDNS Core autostart task");
        check(core_task->get_Enabled(&core_enabled),"Read Core autostart enabled state");
    }

    Bstr name(gui_task_name);
    ComPtr<IRegisteredTask> task;
    const HRESULT found=scheduler.root->GetTask(name.value,task.put());
    VARIANT_BOOL enabled=VARIANT_FALSE;
    if(found!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)){
        check(found,"Read NativeDNS autostart task");
        check(task->get_Enabled(&enabled),"Read autostart enabled state");
    }

    result.enabled=core_enabled==VARIANT_TRUE||enabled==VARIANT_TRUE;
    if(!result.enabled)return result;

    bool core_is_on_demand=false;
    if(core_enabled==VARIANT_TRUE){
        ComPtr<ITaskDefinition> core_definition;
        check(core_task->get_Definition(core_definition.put()),"Read Core autostart definition");
        ComPtr<ITriggerCollection> core_triggers;
        check(core_definition->get_Triggers(core_triggers.put()),"Read Core autostart triggers");
        LONG trigger_count=0;
        check(core_triggers->get_Count(&trigger_count),"Count Core autostart triggers");
        core_is_on_demand=trigger_count==0;
    }
    result.needs_repair=core_enabled!=VARIANT_TRUE||enabled!=VARIANT_TRUE||!core_is_on_demand;
    if(enabled!=VARIANT_TRUE)return result;

    ComPtr<ITaskDefinition> definition;
    check(task->get_Definition(definition.put()),"Read autostart definition");
    ComPtr<IActionCollection> actions;
    check(definition->get_Actions(actions.put()),"Read autostart actions");
    ComPtr<IAction> action;
    check(actions->get_Item(1,action.put()),"Read autostart executable action");
    ComPtr<IExecAction> execute;
    check(action->QueryInterface(IID_PPV_ARGS(execute.put())),"Read autostart executable details");
    OutBstr path,arguments;
    check(execute->get_Path(path.put()),"Read autostart executable");
    check(execute->get_Arguments(arguments.put()),"Read autostart arguments");
    if(path.value) result.executable=path.value;
    if(arguments.value) result.arguments=narrow(arguments.value);
    return result;
}

bool start_autostart_core(const std::filesystem::path& executable,const std::filesystem::path& config) {
    Scheduler scheduler;
    Bstr name(task_name);
    ComPtr<IRegisteredTask> task;
    const HRESULT found=scheduler.root->GetTask(name.value,task.put());
    if(found==HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))return false;
    check(found,"Read NativeDNS Core task");

    VARIANT_BOOL enabled=VARIANT_FALSE;
    check(task->get_Enabled(&enabled),"Read NativeDNS Core task state");
    if(enabled!=VARIANT_TRUE)return false;

    ComPtr<ITaskDefinition> definition;
    check(task->get_Definition(definition.put()),"Read NativeDNS Core task definition");
    ComPtr<IActionCollection> actions;
    check(definition->get_Actions(actions.put()),"Read NativeDNS Core task actions");
    ComPtr<IAction> action;
    check(actions->get_Item(1,action.put()),"Read NativeDNS Core task action");
    ComPtr<IExecAction> execute;
    check(action->QueryInterface(IID_PPV_ARGS(execute.put())),"Read NativeDNS Core task executable");
    OutBstr path,arguments;
    check(execute->get_Path(path.put()),"Read NativeDNS Core executable path");
    check(execute->get_Arguments(arguments.put()),"Read NativeDNS Core arguments");

    const auto absolute_executable=std::filesystem::absolute(executable).lexically_normal();
    const auto absolute_config=std::filesystem::absolute(config).lexically_normal();
    const std::wstring expected_arguments=L"--config "+quote_argument(absolute_config.wstring())+L" --transparent";
    if(!path.value||!arguments.value||_wcsicmp(path.value,absolute_executable.c_str())!=0||expected_arguments!=arguments.value)
        return false;

    auto empty=empty_variant();
    ComPtr<IRunningTask> running;
    check(task->Run(empty,running.put()),"Start NativeDNS Core task");
    return true;
}

}
