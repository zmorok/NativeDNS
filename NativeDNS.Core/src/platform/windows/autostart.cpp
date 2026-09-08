#include <nativedns/autostart.hpp>
#include <nativedns/config.hpp>
#include <windows.h>
#include <taskschd.h>
#include <oleauto.h>

namespace nd {
namespace {
constexpr wchar_t task_name[]=L"NativeDNS Core";

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

void enable_autostart(const std::filesystem::path& executable,const std::filesystem::path& config) {
    if(!std::filesystem::is_regular_file(executable)) throw Error("AUTOSTART","NativeDNS executable does not exist");
    if(!std::filesystem::is_regular_file(config)) throw Error("AUTOSTART","Autostart config does not exist");
    (void)load_config(config);
    Scheduler scheduler;
    ComPtr<ITaskDefinition> definition;
    check(scheduler.service->NewTask(0,definition.put()),"Create task definition");

    ComPtr<IRegistrationInfo> registration;
    check(definition->get_RegistrationInfo(registration.put()),"Open task registration info");
    Bstr author(L"NativeDNS"),description(L"Starts the NativeDNS transparent DNS Core at user logon and restarts it after failures.");
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

    ComPtr<ITriggerCollection> triggers;
    check(definition->get_Triggers(triggers.put()),"Open task triggers");
    ComPtr<ITrigger> trigger;
    check(triggers->Create(TASK_TRIGGER_LOGON,trigger.put()),"Create logon trigger");
    ComPtr<ILogonTrigger> logon;
    check(trigger->QueryInterface(IID_PPV_ARGS(logon.put())),"Configure logon trigger");
    Bstr trigger_id(L"NativeDNS user logon"),delay(L"PT5S");
    check(logon->put_Id(trigger_id.value),"Set logon trigger id");
    check(logon->put_Delay(delay.value),"Set logon trigger delay");

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
}

void disable_autostart() {
    Scheduler scheduler;
    Bstr name(task_name);
    const HRESULT result=scheduler.root->DeleteTask(name.value,0);
    if(FAILED(result)&&result!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) check(result,"Delete NativeDNS autostart task");
}

AutostartStatus autostart_status() {
    Scheduler scheduler;
    Bstr name(task_name);
    ComPtr<IRegisteredTask> task;
    const HRESULT found=scheduler.root->GetTask(name.value,task.put());
    if(found==HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) return {};
    check(found,"Read NativeDNS autostart task");
    VARIANT_BOOL enabled=VARIANT_FALSE;
    check(task->get_Enabled(&enabled),"Read autostart enabled state");
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
    AutostartStatus result;
    result.enabled=enabled==VARIANT_TRUE;
    if(path.value) result.executable=path.value;
    if(arguments.value) result.arguments=narrow(arguments.value);
    return result;
}

}
