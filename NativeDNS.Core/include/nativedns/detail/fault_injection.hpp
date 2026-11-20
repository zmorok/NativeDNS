#pragma once
#include <string>
#include <string_view>

namespace nd::detail {
void set_fault_stage_for_testing(std::string stage, bool once = false);
void clear_fault_stage_for_testing();
void fault_point(std::string_view stage);
void set_test_ca_file_for_testing(std::string path);
std::string test_ca_file_for_testing();
} // namespace nd::detail
