#include <nativedns/platform.hpp>
#include <nativedns/detail/cancellation.hpp>
#include <poll.h>
#include <nativedns/config.hpp>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <unistd.h>
#include <sodium.h>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <limits.h>
#include <cerrno>
#include <cctype>
#include <sstream>
#include <set>
#include <fstream>
#include <algorithm>

namespace nd::platform {
std::vector<std::string> system_dns_servers() {
    std::vector<std::string> servers;
    for (const char* path : {"/run/systemd/resolve/resolv.conf",
                             "/run/NetworkManager/no-stub-resolv.conf",
                             "/etc/resolv.conf"}) {
        std::ifstream input(path);
        std::string line;
        while (std::getline(input, line)) {
            std::istringstream row(line);
            std::string key, address;
            row >> key >> address;
            if (key != "nameserver" || !is_numeric_ip(address) || address == "127.0.0.1" ||
                address == "127.0.0.53" || address == "::1")
                continue;
            if (std::find(servers.begin(), servers.end(), address) == servers.end())
                servers.push_back(address);
        }
        if (!servers.empty())
            break;
    }
    return servers;
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
} // namespace
bool parse_ip(const std::string& text, std::array<uint8_t, 16>& bytes, bool& ipv6) {
    bytes.fill(0);
    in_addr v4{};
    in6_addr v6{};
    if (inet_pton(AF_INET, text.c_str(), &v4) == 1) {
        std::memcpy(bytes.data() + 12, &v4, 4);
        ipv6 = false;
        return true;
    }
    if (inet_pton(AF_INET6, text.c_str(), &v6) == 1) {
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
    if (!inet_ntop(ipv6 ? AF_INET6 : AF_INET, bytes, text, sizeof(text)))
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
    timespec boot{};
    if (clock_gettime(CLOCK_BOOTTIME, &boot) == 0)
        return static_cast<uint64_t>(boot.tv_sec) * 1000 +
               static_cast<uint64_t>(boot.tv_nsec) / 1000000;
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
}
uint32_t process_id() {
    return static_cast<uint32_t>(::getpid());
}
std::filesystem::path executable_path() {
    char buffer[PATH_MAX + 1]{};
    const ssize_t n = ::readlink("/proc/self/exe", buffer, PATH_MAX);
    if (n <= 0)
        throw Error("PATH", "Cannot determine executable path");
    buffer[n] = '\0';
    return std::filesystem::path(buffer);
}
std::filesystem::path application_root_directory() {
    const auto directory = executable_path().parent_path();
    return directory.filename() == "bin" ? directory.parent_path() : directory;
}
std::filesystem::path user_config_directory() {
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg)
        return std::filesystem::path(xdg) / "nativedns";
    if (const char* home = std::getenv("HOME"); home && *home)
        return std::filesystem::path(home) / ".config" / "nativedns";
    return executable_path().parent_path();
}
bool is_elevated() {
    return geteuid() == 0;
}
std::string system_summary() {
    utsname details{};
    const bool available = ::uname(&details) == 0;
    std::ostringstream output;
    output << "platform=linux-x64";
    if (available)
        output << " kernel=" << details.sysname << ' ' << details.release
               << " machine=" << details.machine;
    output << " pid=" << process_id() << " uid=" << ::getuid() << " euid=" << ::geteuid();
    return output.str();
}
void wait_socket(std::intptr_t raw, bool writing, std::chrono::steady_clock::time_point deadline) {
    const int socket = static_cast<int>(raw);
    for (;;) {
        detail::check_cancelled();
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0)
            throw Error("TIMEOUT", "Socket wait deadline exceeded");
        pollfd descriptor{socket, static_cast<short>(writing ? POLLOUT : POLLIN), 0};
        const int rc = poll(&descriptor, 1, static_cast<int>(std::min<int64_t>(left.count(), 100)));
        if (rc == 0)
            continue;
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0)
            throw Error("SOCKET", "Socket wait failed: " + std::string(std::strerror(errno)));
        detail::check_cancelled();
        return;
    }
}
void configure_upstream_socket(std::intptr_t raw) {
#ifdef SO_MARK
    constexpr uint32_t mark = 0x4e444e53u;
    const int fd = static_cast<int>(raw);
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        // Server tests and non-transparent LocalProxy mode may run unprivileged.
        // The mark is mandatory only for the privileged transparent backend.
        if (errno == EPERM || errno == EACCES)
            return;
        throw Error("SOCKET_MARK",
                    "Cannot mark NativeDNS upstream socket: " + std::string(std::strerror(errno)));
    }
#else
    (void)raw;
#endif
}
uint16_t prepare_upstream_socket(std::intptr_t raw, bool) {
    configure_upstream_socket(raw);
    return 0;
}
bool socket_is_ipv6(std::intptr_t raw) {
    sockaddr_storage address{};
    socklen_t size = sizeof(address);
    if (getsockname(static_cast<int>(raw), reinterpret_cast<sockaddr*>(&address), &size) != 0)
        throw Error("SOCKET", "Cannot inspect upstream address family");
    return address.ss_family == AF_INET6;
}
int close_upstream_socket(std::intptr_t raw) noexcept {
    return ::close(static_cast<int>(raw)) == 0 ? 0 : 1;
}
std::vector<std::string> resolve_host(const std::string& hostname) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* addresses = nullptr;
    const int rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &addresses);
    if (rc)
        throw Error("BOOTSTRAP",
                    "Cannot resolve secure upstream " + hostname + ": " + gai_strerror(rc));
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
    std::error_code ec;
    if (std::filesystem::exists(target)) {
        std::filesystem::copy_file(
            target, backup, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec)
            throw Error("CONFIG_IO", "Cannot create config backup: " + ec.message());
    }
    std::filesystem::rename(temp, target, ec);
    if (ec)
        throw Error("CONFIG_IO", "Atomic config rename failed: " + ec.message());
}

struct ProcessInstanceLock::Impl {
    int fd = -1;
    bool owns = false;
};

ProcessInstanceLock::ProcessInstanceLock(const std::string& name, InstanceScope scope)
    : impl_(std::make_unique<Impl>()) {
    std::string safe = name;
    for (char& character : safe)
        if (!std::isalnum(static_cast<unsigned char>(character)) && character != '.' &&
            character != '-')
            character = '_';
    std::filesystem::path directory;
    if (const char* runtime = std::getenv("XDG_RUNTIME_DIR");
        runtime && *runtime && std::filesystem::is_directory(runtime))
        directory = runtime;
    else
        directory = "/tmp";
    const auto path =
        scope == InstanceScope::machine
            ? std::filesystem::path("/tmp") / (safe + ".machine.lock")
            : directory /
                  (safe + "." + std::to_string(static_cast<unsigned long>(::getuid())) + ".lock");
    impl_->fd = ::open(path.c_str(),
                       O_CREAT | O_CLOEXEC | O_NOFOLLOW |
                           (scope == InstanceScope::machine ? O_RDONLY : O_RDWR),
                       scope == InstanceScope::machine ? 0644 : 0600);
    if (impl_->fd < 0)
        throw Error("INSTANCE_LOCK",
                    "Cannot create process lock: " + std::string(std::strerror(errno)));
    struct stat info{};
    if (fstat(impl_->fd, &info) < 0 || !S_ISREG(info.st_mode)) {
        ::close(impl_->fd);
        impl_->fd = -1;
        throw Error("INSTANCE_LOCK", "Process lock is not a regular file");
    }
    if (::flock(impl_->fd, LOCK_EX | LOCK_NB) == 0)
        impl_->owns = true;
    else if (errno != EWOULDBLOCK && errno != EAGAIN) {
        const auto error = std::string(std::strerror(errno));
        ::close(impl_->fd);
        impl_->fd = -1;
        throw Error("INSTANCE_LOCK", "Cannot lock process instance: " + error);
    }
}
ProcessInstanceLock::~ProcessInstanceLock() {
    if (impl_ && impl_->fd >= 0) {
        if (impl_->owns)
            (void)::flock(impl_->fd, LOCK_UN);
        ::close(impl_->fd);
    }
}
bool ProcessInstanceLock::acquired() const noexcept {
    return impl_ && impl_->owns;
}

void local_time(std::time_t instant, std::tm& output) {
    localtime_r(&instant, &output);
}

} // namespace nd::platform
