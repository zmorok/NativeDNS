#pragma once
#include <string>
#include <string_view>

namespace nd::detail {
void set_fault_stage_for_testing(std::string stage);
void clear_fault_stage_for_testing();
void fault_point(std::string_view stage);
} // namespace nd::detail
