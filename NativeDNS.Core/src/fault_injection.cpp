#include <nativedns/detail/fault_injection.hpp>
#include <nativedns/config.hpp>
#include <mutex>

namespace nd::detail {
namespace {std::mutex fault_mutex;std::string fault_stage;}
void set_fault_stage_for_testing(std::string stage){std::lock_guard lock(fault_mutex);fault_stage=std::move(stage);}
void clear_fault_stage_for_testing(){std::lock_guard lock(fault_mutex);fault_stage.clear();}
void fault_point(std::string_view stage){std::lock_guard lock(fault_mutex);if(fault_stage==stage)throw Error("FAULT_INJECTED","Injected startup failure at "+std::string(stage));}
}
