#pragma once
#include <stdint.h>
#if defined(NATIVEDNS_EXPORTS)
#define ND_API __declspec(dllexport)
#elif defined(NATIVEDNS_IMPORTS)
#define ND_API __declspec(dllimport)
#else
#define ND_API
#endif
#ifdef __cplusplus
extern "C" {
#endif
// ABI uses caller-owned buffers and fixed-width scalars only.
ND_API uint32_t NativeDns_GetApiVersion(void);
ND_API const char* NativeDns_GetBuildVersion(void); // immutable, module-owned
#ifdef __cplusplus
}
#endif
