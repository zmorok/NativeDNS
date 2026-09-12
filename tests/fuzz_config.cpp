#include <nativedns/config.hpp>
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,size_t size){
    try{(void)nd::parse_config(std::string(reinterpret_cast<const char*>(data),size));}catch(...){}
    return 0;
}
