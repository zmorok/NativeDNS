#include <nativedns/detail/ipc_wire.hpp>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,size_t size){
    if(size<nd::detail::ipc_header_size)return 0;
    const std::span<const uint8_t> bytes(data,nd::detail::ipc_header_size);
    try{(void)nd::detail::parse_ipc_header(bytes,false);}catch(...){}
    try{(void)nd::detail::parse_ipc_header(bytes,true);}catch(...){}
    return 0;
}
