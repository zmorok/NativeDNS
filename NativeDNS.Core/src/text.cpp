#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>

namespace nd::platform {
std::string path_to_utf8(const std::filesystem::path& path) {
    const auto text = path.u8string();
    return {text.begin(), text.end()};
}
std::filesystem::path path_from_utf8(const std::string& text) {
    (void)widen(text); // Reject invalid UTF-8 on every platform.
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}
} // namespace nd::platform
