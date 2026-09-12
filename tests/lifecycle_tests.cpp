#include <nativedns/platform.hpp>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}

bool wait_until_locked(const std::string& name){
    for(unsigned attempt=0;attempt<100;++attempt){
        bool available=false;
        {nd::platform::ProcessInstanceLock probe(name);available=probe.acquired();}
        if(!available)return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
}

void verify_abnormal_process_release(const std::string& name){
#ifdef _WIN32
    auto command=L"\""+nd::platform::executable_path().wstring()+L"\" --hold-lock "+std::wstring(name.begin(),name.end());
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
    check(CreateProcessW(nullptr,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process)!=FALSE,"cannot launch lifecycle crash child");
    CloseHandle(process.hThread);
    check(wait_until_locked(name),"crash child did not acquire process-instance lock");
    check(TerminateProcess(process.hProcess,99)!=FALSE,"cannot terminate lifecycle crash child");
    check(WaitForSingleObject(process.hProcess,5000)==WAIT_OBJECT_0,"lifecycle crash child did not terminate");
    CloseHandle(process.hProcess);
#else
    const auto child=fork();check(child>=0,"cannot fork lifecycle crash child");
    if(child==0){execl(nd::platform::executable_path().c_str(),nd::platform::executable_path().c_str(),"--hold-lock",name.c_str(),nullptr);_exit(127);}
    check(wait_until_locked(name),"crash child did not acquire process-instance lock");
    check(kill(child,SIGKILL)==0,"cannot terminate lifecycle crash child");
    int status=0;check(waitpid(child,&status,0)==child,"cannot reap lifecycle crash child");
#endif
    nd::platform::ProcessInstanceLock recovered(name);
    check(recovered.acquired(),"process-instance lock must recover after forced process termination");
}
}

int main(int argc,char** argv){
    try{
        if(argc==3&&std::string(argv[1])=="--hold-lock"){
            nd::platform::ProcessInstanceLock held(argv[2]);
            if(!held.acquired())return 2;
            std::this_thread::sleep_for(std::chrono::seconds(30));
            return 0;
        }
        const std::string name="NativeDNS.Test.InstanceLock."+std::to_string(nd::platform::process_id())+"."+std::to_string(nd::platform::secure_random_u32());
        {
            nd::platform::ProcessInstanceLock first(name);
            check(first.acquired(),"first process-instance lock must be acquired");
            {
                nd::platform::ProcessInstanceLock second(name);
                check(!second.acquired(),"second process-instance lock must be rejected");
            }
        }
        nd::platform::ProcessInstanceLock afterRelease(name);
        check(afterRelease.acquired(),"process-instance lock must be reusable after owner exits");
        const std::string crash_name=name+".Crash";
        verify_abnormal_process_release(crash_name);
        std::cout<<"Lifecycle instance-lock and crash-recovery tests passed\n";
        return 0;
    }catch(const std::exception& error){
        std::cerr<<error.what()<<'\n';
        return 1;
    }
}
