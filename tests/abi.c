#include <nativedns/core_api.h>
int main(void) { return NativeDns_GetApiVersion() == 1 ? 0 : 1; }
