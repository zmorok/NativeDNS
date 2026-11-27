#include <nativedns/platform.hpp>
#include <nativedns/detail/cancellation.hpp>
#include <nativedns/config.hpp>
#include <nativedns/network.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <powrprof.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <sodium.h>
#include <vector>
#include <cstring>
#include <sstream>
#include <set>
#include <optional>
#include <algorithm>
#include <cctype>
#include <condition_variable>
#include <cstdlib>
#include <fstream>

namespace nd::platform {
std::vector<std::string> command_line_arguments(int, char**) {
    int count = 0;
    auto** arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!arguments)
        throw Error("COMMAND_LINE", "Cannot read Unicode command line");
    struct Release {
        HLOCAL value;
        ~Release() { LocalFree(value); }
    } release{arguments};
    std::vector<std::string> result;
    for (int i = 0; i < count; ++i)
        result.push_back(narrow(arguments[i]));
    return result;
}
std::vector<std::string> system_dns_servers() {
    return select_bootstrap_dns_servers(enumerate_interfaces());
}
namespace {
void sodium_ready() {
    static const bool ready = [] {
        if (sodium_init() < 0)
            throw Error("CRYPTO_INIT", "libsodium initialization failed");
        return true;
    }();
    (void)ready;
}
void winsock_ready() {
    static const bool ready = [] {
        WSADATA data{};
        const int rc = WSAStartup(MAKEWORD(2, 2), &data);
        if (rc)
            throw Error("SOCKET_INIT", "WSAStartup: " + std::to_string(rc));
        return true;
    }();
    (void)ready;
}
constexpr wchar_t windows_version_key[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

std::wstring version_registry_string(const wchar_t* name) {
    wchar_t value[256]{};
    DWORD bytes = sizeof(value);
    if (RegGetValueW(
            HKEY_LOCAL_MACHINE, windows_version_key, name, RRF_RT_REG_SZ, nullptr, value, &bytes) !=
        ERROR_SUCCESS)
        return {};
    return value;
}
std::optional<DWORD> version_registry_dword(const wchar_t* name) {
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    if (RegGetValueW(HKEY_LOCAL_MACHINE,
                     windows_version_key,
                     name,
                     RRF_RT_REG_DWORD,
                     nullptr,
                     &value,
                     &bytes) != ERROR_SUCCESS)
        return std::nullopt;
    return value;
}
std::string utf8(const std::wstring& value) {
    if (value.empty())
        return {};
    const int size = WideCharToMultiByte(CP_UTF8,
                                         WC_ERR_INVALID_CHARS,
                                         value.data(),
                                         static_cast<int>(value.size()),
                                         nullptr,
                                         0,
                                         nullptr,
                                         nullptr);
    if (size <= 0)
        return {};
    std::string result(static_cast<size_t>(size), '\0');
    if (!WideCharToMultiByte(CP_UTF8,
                             WC_ERR_INVALID_CHARS,
                             value.data(),
                             static_cast<int>(value.size()),
                             result.data(),
                             size,
                             nullptr,
                             nullptr))
        return {};
    return result;
}
} // namespace
bool parse_ip(const std::string& text, std::array<uint8_t, 16>& bytes, bool& ipv6) {
    bytes.fill(0);
    in_addr v4{};
    in6_addr v6{};
    if (InetPtonA(AF_INET, text.c_str(), &v4) == 1) {
        std::memcpy(bytes.data() + 12, &v4, 4);
        ipv6 = false;
        return true;
    }
    if (InetPtonA(AF_INET6, text.c_str(), &v6) == 1) {
        std::memcpy(bytes.data(), &v6, 16);
        ipv6 = true;
        return true;
    }
    return false;
}
bool is_numeric_ip(const std::string& text) {
    std::array<uint8_t, 16> b{};
    bool v6 = false;
    return parse_ip(text, b, v6);
}
std::string format_ip(const void* bytes, bool ipv6) {
    char text[INET6_ADDRSTRLEN]{};
    if (!InetNtopA(ipv6 ? AF_INET6 : AF_INET, const_cast<void*>(bytes), text, sizeof(text)))
        throw Error("ENDPOINT", "Cannot format IP address");
    return text;
}
uint16_t secure_random_u16() {
    sodium_ready();
    uint16_t value = 0;
    randombytes_buf(&value, sizeof(value));
    return value;
}
uint32_t secure_random_u32() {
    sodium_ready();
    uint32_t value = 0;
    randombytes_buf(&value, sizeof(value));
    return value;
}
uint64_t monotonic_millis() {
    return GetTickCount64();
}
MonotonicClocks monotonic_clocks() {
    const uint64_t boot = GetTickCount64();
    ULONGLONG unbiased = 0;
    const uint64_t active =
        QueryUnbiasedInterruptTime(&unbiased) ? static_cast<uint64_t>(unbiased / 10000ULL) : boot;
    return {boot, active};
}
struct SuspendResumeSubscription::Impl {
    using RegisterFn = DWORD(WINAPI*)(DWORD, HANDLE, PHPOWERNOTIFY);
    using UnregisterFn = DWORD(WINAPI*)(HPOWERNOTIFY);
    HMODULE powrprof = nullptr;
    UnregisterFn unregister_fn = nullptr;
    HPOWERNOTIFY handle = nullptr;
    std::function<void()> callback;

    static ULONG CALLBACK on_power_event(PVOID context, ULONG type, PVOID) noexcept {
        if (type == PBT_APMRESUMEAUTOMATIC || type == PBT_APMRESUMESUSPEND) {
            auto* self = static_cast<Impl*>(context);
            if (self && self->callback) {
                try {
                    self->callback();
                } catch (...) {
                }
            }
        }
        return ERROR_SUCCESS;
    }

    ~Impl() {
        if (handle && unregister_fn)
            (void)unregister_fn(handle);
        if (powrprof)
            FreeLibrary(powrprof);
    }
};
SuspendResumeSubscription::SuspendResumeSubscription(std::function<void()> on_resume) {
    if (!on_resume)
        return;
    auto impl = std::make_unique<Impl>();
    impl->callback = std::move(on_resume);
    impl->powrprof = LoadLibraryExW(L"powrprof.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!impl->powrprof)
        return;
    const auto register_fn = reinterpret_cast<Impl::RegisterFn>(
        GetProcAddress(impl->powrprof, "PowerRegisterSuspendResumeNotification"));
    impl->unregister_fn = reinterpret_cast<Impl::UnregisterFn>(
        GetProcAddress(impl->powrprof, "PowerUnregisterSuspendResumeNotification"));
    if (!register_fn || !impl->unregister_fn)
        return;
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS params{};
    params.Callback = &Impl::on_power_event;
    params.Context = impl.get();
    if (register_fn(DEVICE_NOTIFY_CALLBACK, &params, &impl->handle) == ERROR_SUCCESS &&
        impl->handle)
        impl_ = std::move(impl);
}
SuspendResumeSubscription::~SuspendResumeSubscription() = default;
void elevate_service_process_priority() noexcept {
    (void)SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
}
void set_current_thread_priority(ThreadPriority priority) noexcept {
    int level = THREAD_PRIORITY_NORMAL;
    switch (priority) {
        case ThreadPriority::below_normal:
            level = THREAD_PRIORITY_BELOW_NORMAL;
            break;
        case ThreadPriority::normal:
            level = THREAD_PRIORITY_NORMAL;
            break;
        case ThreadPriority::above_normal:
            level = THREAD_PRIORITY_ABOVE_NORMAL;
            break;
        case ThreadPriority::highest:
            level = THREAD_PRIORITY_HIGHEST;
            break;
    }
    (void)SetThreadPriority(GetCurrentThread(), level);
}
uint32_t process_id() {
    return GetCurrentProcessId();
}
std::jthread watch_shutdown_deadline(std::function<bool()> shutdown_requested) {
    return std::jthread([requested = std::move(shutdown_requested)](std::stop_token stop) {
        std::mutex wait_mutex;
        std::condition_variable_any changed;
        std::unique_lock lock(wait_mutex);
        std::optional<std::chrono::steady_clock::time_point> shutdown_time;
        while (!stop.stop_requested()) {
            if (requested()) {
                const auto now = std::chrono::steady_clock::now();
                if (!shutdown_time)
                    shutdown_time = now;
                if (now - *shutdown_time >= std::chrono::seconds(10))
                    std::_Exit(12);
            }
            changed.wait_for(lock, stop, std::chrono::milliseconds(100), [] { return false; });
        }
    });
}
std::filesystem::path executable_path() {
    std::vector<wchar_t> buffer(32768);
    const DWORD n = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!n || n >= buffer.size())
        throw Error("PATH", "Cannot determine executable path");
    return std::filesystem::path(std::wstring(buffer.data(), n));
}
std::filesystem::path application_root_directory() {
    const auto binary = executable_path().parent_path();
    if (binary.filename() == L"bin" && binary.parent_path().filename() == L"app")
        return binary.parent_path().parent_path();
    return binary;
}
std::filesystem::path application_binary_directory() {
    const auto binary = executable_path().parent_path();
    std::error_code ec;
    if (std::filesystem::is_directory(binary / L"bin", ec))
        return binary / L"bin";
    return binary;
}
std::filesystem::path gui_entrypoint() { return application_root_directory() / L"NativeDNS.exe"; }
std::filesystem::path core_host_executable() {
    const auto root = application_root_directory();
    std::error_code ec;
    if (std::filesystem::is_regular_file(root / L"NativeDNS.exe", ec) &&
        std::filesystem::is_regular_file(root / L"bin" / L"NativeDNS.CoreHost.dll", ec))
        return root / L"NativeDNS.exe";
    return application_binary_directory() / L"NativeDNS.CoreHost.exe";
}
std::filesystem::path windivert_directory() {
    const auto root = application_root_directory();
    std::error_code ec;
    if (std::filesystem::is_directory(root / L"bin" / L"drivers", ec))
        return root / L"bin" / L"drivers";
    if (std::filesystem::is_directory(root / L"app" / L"drivers" / L"windivert", ec))
        return root / L"app" / L"drivers" / L"windivert";
    return executable_path().parent_path();
}
void initialize_application_paths() {
    const auto root = application_root_directory();
    std::error_code ec;
    std::filesystem::path library;
    if (std::filesystem::is_directory(root / L"bin", ec))
        library = root / L"bin";
    else if (std::filesystem::is_directory(root / L"app" / L"lib", ec))
        library = root / L"app" / L"lib";
    else
        return;
    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS) ||
        !AddDllDirectory(library.c_str()) || !SetDllDirectoryW(library.c_str()))
        throw Error("PATH", "Cannot configure application DLL search paths");
}
std::filesystem::path user_config_directory() {
    const DWORD required = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    if (required > 0) {
        std::wstring local(required, L'\0');
        const DWORD written = GetEnvironmentVariableW(L"LOCALAPPDATA", local.data(), required);
        if (written > 0 && written < required) {
            local.resize(written);
            return std::filesystem::path(local) / L"NativeDNS";
        }
    }
    return executable_path().parent_path();
}
bool is_elevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const bool result =
        GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) &&
        elevation.TokenIsElevated != 0;
    CloseHandle(token);
    return result;
}
namespace {
std::optional<DistributionKind> read_distribution_marker(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec))
        return std::nullopt;
    std::ifstream file(path);
    std::string line;
    if (!std::getline(file, line))
        return std::nullopt;
    std::string token;
    for (unsigned char ch : line) {
        if (!std::isspace(ch))
            token.push_back(static_cast<char>(std::tolower(ch)));
    }
    if (token == "executable" || token == "installer")
        return DistributionKind::executable;
    if (token == "portable")
        return DistributionKind::portable;
    if (token == "appimage")
        return DistributionKind::appimage;
    if (token == "deb" || token == "package")
        return DistributionKind::package;
    return std::nullopt;
}
bool is_inno_setup_installed_at(const std::filesystem::path& root) {
    constexpr wchar_t uninstall_key[] =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{2F47E185-E56B-42F0-A85F-D6F276F3AF6B}_is1";
    std::error_code ec;
    const auto canonical_root = std::filesystem::weakly_canonical(root, ec).wstring();
    if (canonical_root.empty())
        return false;
    for (const HKEY hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
        wchar_t location[32768]{};
        DWORD bytes = sizeof(location);
        if (RegGetValueW(hive,
                         uninstall_key,
                         L"InstallLocation",
                         RRF_RT_REG_SZ,
                         nullptr,
                         location,
                         &bytes) != ERROR_SUCCESS)
            continue;
        std::wstring text(location);
        while (!text.empty() && (text.back() == L'\\' || text.back() == L'/'))
            text.pop_back();
        if (text.empty())
            continue;
        const auto canonical_installed = std::filesystem::weakly_canonical(text, ec).wstring();
        if (!canonical_installed.empty() &&
            CompareStringOrdinal(canonical_root.c_str(),
                                 -1,
                                 canonical_installed.c_str(),
                                 -1,
                                 TRUE) == CSTR_EQUAL)
            return true;
    }
    return false;
}
} // namespace
const char* distribution_name(DistributionKind kind) noexcept {
    switch (kind) {
        case DistributionKind::portable:
            return "portable";
        case DistributionKind::executable:
            return "executable";
        case DistributionKind::appimage:
            return "appimage";
        case DistributionKind::package:
            return "package";
    }
    return "portable";
}
const char* distribution_label(DistributionKind kind) noexcept {
    switch (kind) {
        case DistributionKind::portable:
            return "Portable";
        case DistributionKind::executable:
            return "Executable";
        case DistributionKind::appimage:
            return "AppImage";
        case DistributionKind::package:
            return "Package";
    }
    return "Portable";
}
DistributionKind detect_distribution_in_directory(const std::filesystem::path& root,
                                                  bool registry_installed) {
    for (const auto& candidate :
         {root / L"bin" / L"distribution", root / L"app" / L"distribution", root / L"distribution"}) {
        if (const auto marked = read_distribution_marker(candidate))
            return *marked;
    }
    std::error_code ec;
    if (registry_installed || std::filesystem::is_regular_file(root / L"unins000.exe", ec))
        return DistributionKind::executable;
    return DistributionKind::portable;
}
DistributionKind distribution_kind() {
    try {
        const auto root = application_root_directory();
        return detect_distribution_in_directory(root, is_inno_setup_installed_at(root));
    } catch (...) {
        return DistributionKind::portable;
    }
}
std::string system_summary() {
    using RtlGetVersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
    OSVERSIONINFOW version{};
    version.dwOSVersionInfoSize = sizeof(version);
    if (const auto module = GetModuleHandleW(L"ntdll.dll"))
        if (const auto get_version =
                reinterpret_cast<RtlGetVersionFunction>(GetProcAddress(module, "RtlGetVersion")))
            (void)get_version(&version);

    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    const char* architecture = "unknown";
    switch (system.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            architecture = "x64";
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            architecture = "x86";
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            architecture = "arm64";
            break;
    }

    auto product_name = version_registry_string(L"ProductName");
    // Windows 11 can still report "Windows 10" in this registry value.
    if (version.dwBuildNumber >= 22000 && product_name.starts_with(L"Windows 10 "))
        product_name.replace(0, 10, L"Windows 11");
    if (product_name.empty())
        product_name = L"Windows";
    const auto display_version = utf8(version_registry_string(L"DisplayVersion"));
    const auto ubr = version_registry_dword(L"UBR");

    std::ostringstream output;
    output << "platform=windows-" << architecture << " os=\"" << utf8(product_name) << ' '
           << architecture << '"';
    if (!display_version.empty())
        output << " version=" << display_version;
    output << " build=" << version.dwBuildNumber;
    if (ubr)
        output << '.' << *ubr;
    output << " pid=" << process_id() << " elevated=" << (is_elevated() ? 1 : 0)
           << " distribution=" << distribution_name(distribution_kind())
           << " ansi_cp=" << GetACP() << " oem_cp=" << GetOEMCP()
           << " console_input_cp=" << GetConsoleCP()
           << " console_output_cp=" << GetConsoleOutputCP() << " log_encoding=UTF-8";
    return output.str();
}
void wait_socket(std::intptr_t raw, bool writing, std::chrono::steady_clock::time_point deadline) {
    const SOCKET socket = static_cast<SOCKET>(raw);
    for (;;) {
        detail::check_cancelled();
        const auto left = std::chrono::duration_cast<std::chrono::microseconds>(
            std::min(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(100)) -
            std::chrono::steady_clock::now());
        if (left.count() <= 0)
            throw Error("TIMEOUT", "Socket wait deadline exceeded");
        timeval timeout{static_cast<long>(left.count() / 1000000),
                        static_cast<long>(left.count() % 1000000)};
        fd_set set;
        FD_ZERO(&set);
        FD_SET(socket, &set);
        auto exceptions = set;
        const int rc = select(0,
                              writing ? nullptr : &set,
                              writing ? &set : nullptr,
                              writing ? &exceptions : nullptr,
                              &timeout);
        if (rc == 0)
            continue;
        if (rc < 0)
            throw Error("SOCKET",
                        "Socket wait failed: Winsock " + std::to_string(WSAGetLastError()));
        detail::check_cancelled();
        return;
    }
}
void configure_upstream_socket(std::intptr_t) {
}
uint16_t prepare_upstream_socket(std::intptr_t raw, bool) {
    winsock_ready();
    const SOCKET socket = static_cast<SOCKET>(raw);
    WSAPROTOCOL_INFOW info{};
    int info_size = sizeof(info);
    if (getsockopt(
            socket, SOL_SOCKET, SO_PROTOCOL_INFOW, reinterpret_cast<char*>(&info), &info_size) ==
        SOCKET_ERROR)
        throw Error("SOCKET",
                    "Cannot inspect secure upstream socket: Winsock " +
                        std::to_string(WSAGetLastError()));
    sockaddr_storage local{};
    int local_size = info.iAddressFamily == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    local.ss_family = static_cast<ADDRESS_FAMILY>(info.iAddressFamily);
    if (bind(socket, reinterpret_cast<const sockaddr*>(&local), local_size) == SOCKET_ERROR &&
        WSAGetLastError() != WSAEINVAL)
        throw Error("SOCKET",
                    "Cannot bind secure upstream socket: Winsock " +
                        std::to_string(WSAGetLastError()));
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&local), &local_size) == SOCKET_ERROR)
        throw Error("SOCKET",
                    "Cannot inspect secure upstream endpoint: Winsock " +
                        std::to_string(WSAGetLastError()));
    return ntohs(info.iAddressFamily == AF_INET
                     ? reinterpret_cast<const sockaddr_in*>(&local)->sin_port
                     : reinterpret_cast<const sockaddr_in6*>(&local)->sin6_port);
}
bool socket_is_ipv6(std::intptr_t raw) {
    WSAPROTOCOL_INFOW info{};
    int size = sizeof(info);
    if (getsockopt(static_cast<SOCKET>(raw),
                   SOL_SOCKET,
                   SO_PROTOCOL_INFOW,
                   reinterpret_cast<char*>(&info),
                   &size) == SOCKET_ERROR)
        throw Error("SOCKET", "Cannot inspect upstream address family");
    return info.iAddressFamily == AF_INET6;
}
int close_upstream_socket(std::intptr_t raw) noexcept {
    return closesocket(static_cast<SOCKET>(raw)) == 0 ? 0 : 1;
}
std::vector<std::string> resolve_host(const std::string& hostname) {
    winsock_ready();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* addresses = nullptr;
    const int rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &addresses);
    if (rc)
        throw Error("BOOTSTRAP",
                    "Cannot resolve secure upstream " + hostname + ": Winsock " +
                        std::to_string(rc));
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> cleanup(addresses, &freeaddrinfo);
    std::vector<std::string> result;
    std::set<std::string> unique;
    for (auto* address = addresses; address; address = address->ai_next) {
        const bool ipv6 = address->ai_family == AF_INET6;
        if (address->ai_family != AF_INET && !ipv6)
            continue;
        const void* bytes =
            ipv6 ? static_cast<const void*>(
                       &reinterpret_cast<const sockaddr_in6*>(address->ai_addr)->sin6_addr)
                 : static_cast<const void*>(
                       &reinterpret_cast<const sockaddr_in*>(address->ai_addr)->sin_addr);
        auto text = format_ip(bytes, ipv6);
        if (unique.insert(text).second)
            result.push_back(std::move(text));
    }
    if (result.empty())
        throw Error("BOOTSTRAP", "Secure upstream hostname has no usable address: " + hostname);
    return result;
}
void atomic_publish_file(const std::filesystem::path& temp,
                         const std::filesystem::path& target,
                         const std::filesystem::path& backup) {
    if (std::filesystem::exists(target)) {
        if (!ReplaceFileW(target.c_str(),
                          temp.c_str(),
                          backup.c_str(),
                          REPLACEFILE_WRITE_THROUGH,
                          nullptr,
                          nullptr))
            throw Error("CONFIG_IO",
                        "Atomic replacement failed: " + std::to_string(GetLastError()));
    } else if (!MoveFileExW(temp.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH))
        throw Error("CONFIG_IO", "Atomic creation failed: " + std::to_string(GetLastError()));
}
struct ProcessInstanceLock::Impl {
    HANDLE handle = nullptr;
    bool owns = false;
};

ProcessInstanceLock::ProcessInstanceLock(const std::string& name, InstanceScope scope)
    : impl_(std::make_unique<Impl>()) {
    const std::wstring mutexName =
        (scope == InstanceScope::machine ? L"Global\\" : L"Local\\") + nd::widen(name);
    impl_->handle = CreateMutexW(nullptr, FALSE, mutexName.c_str());
    if (!impl_->handle) {
        const DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED)
            return;
        throw Error("INSTANCE_LOCK", "Cannot create process mutex: " + std::to_string(error));
    }
    impl_->owns = GetLastError() != ERROR_ALREADY_EXISTS;
}
ProcessInstanceLock::~ProcessInstanceLock() {
    if (impl_ && impl_->handle)
        CloseHandle(impl_->handle);
}
bool ProcessInstanceLock::acquired() const noexcept {
    return impl_ && impl_->owns;
}

void local_time(std::time_t instant, std::tm& output) {
    localtime_s(&output, &instant);
}
} // namespace nd::platform
