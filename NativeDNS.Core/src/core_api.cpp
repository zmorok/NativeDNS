#include <nativedns/core_api.h>

#include "version.hpp"

uint32_t NativeDns_GetApiVersion(void) {
    return 1;
}

const char* NativeDns_GetBuildVersion(void) {
    return nd::build::version;
}
