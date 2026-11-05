#include <curl/curl.h>
#include <cstdio>
#include <cstdlib>

// Linked into secure_tests only. Give its real production transport a private
// fixture CA without modifying production sources or any system trust store.
extern "C" CURL* __real_curl_easy_init();
extern "C" void __real_curl_easy_reset(CURL*);
namespace {
void fixture_trust(CURL* handle) {
    if (const auto* ca = std::getenv("NATIVEDNS_TEST_CA_FILE"); ca && *ca) {
        if (curl_easy_setopt(handle, CURLOPT_CAINFO, ca) != CURLE_OK) {
            std::fputs("Cannot configure the private TLS fixture CA\n", stderr);
            std::abort();
        }
    }
}
} // namespace
extern "C" CURL* __wrap_curl_easy_init() {
    auto* handle = __real_curl_easy_init();
    if (handle)
        fixture_trust(handle);
    return handle;
}
extern "C" void __wrap_curl_easy_reset(CURL* handle) {
    __real_curl_easy_reset(handle);
    fixture_trust(handle);
}
