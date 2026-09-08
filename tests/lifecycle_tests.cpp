#include <nativedns/platform.hpp>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
}

int main(){
    try{
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
        std::cout<<"Lifecycle instance-lock tests passed\n";
        return 0;
    }catch(const std::exception& error){
        std::cerr<<error.what()<<'\n';
        return 1;
    }
}
