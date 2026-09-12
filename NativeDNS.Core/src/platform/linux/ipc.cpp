#include <nativedns/ipc.hpp>
#include <nativedns/platform.hpp>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include <cerrno>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

namespace nd {
namespace {
constexpr uint32_t magic = 0x31444e4e;
constexpr uint32_t max_payload = 1024 * 1024;
constexpr size_t header_size = 20;
std::string owner_name(const std::string& name){uint64_t hash=1469598103934665603ULL;for(const unsigned char value:name){hash^=value;hash*=1099511628211ULL;}return "NativeDNS.IPC."+std::to_string(hash);}

void put16(uint8_t* out, uint16_t value) {
    out[0] = static_cast<uint8_t>(value);
    out[1] = static_cast<uint8_t>(value >> 8);
}

void put32(uint8_t* out, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) {
        out[i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

void put64(uint8_t* out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

uint16_t get16(const uint8_t* data) {
    return static_cast<uint16_t>(data[0] | (data[1] << 8));
}

uint32_t get32(const uint8_t* data) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) {
        value |= static_cast<uint32_t>(data[i]) << (i * 8);
    }
    return value;
}

uint64_t get64(const uint8_t* data) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(data[i]) << (i * 8);
    }
    return value;
}

std::vector<uint8_t> frame(uint16_t operation, uint64_t request, uint32_t status, const std::string& payload) {
    if (payload.size() > max_payload) {
        throw Error("IPC_LIMIT", "IPC payload exceeds 1 MiB");
    }

    const size_t extra = (operation & 0x8000) ? 4 : 0;
    std::vector<uint8_t> output(header_size + extra + payload.size());
    put32(output.data(), magic);
    put16(output.data() + 4, 1);
    put16(output.data() + 6, operation);
    put64(output.data() + 8, request);
    put32(output.data() + 16, static_cast<uint32_t>(extra + payload.size()));
    if (extra) {
        put32(output.data() + header_size, status);
    }
    std::copy(payload.begin(), payload.end(), output.begin() + static_cast<ptrdiff_t>(header_size + extra));
    return output;
}

class Fd {
public:
    explicit Fd(int value = -1) : value_(value) {}
    ~Fd() {
        if (value_ >= 0) {
            ::close(value_);
        }
    }

    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;

    int get() const { return value_; }
    int release(){const int value=value_;value_=-1;return value;}

private:
    int value_ = -1;
};

[[noreturn]] void io_error(const char* what) {
    throw Error("IPC_IO", std::string(what) + ": " + std::strerror(errno));
}

void wait_fd(int fd, short events, std::chrono::steady_clock::time_point deadline,const std::atomic_bool* running=nullptr) {
    for (;;) {
        if(running&&!*running)throw Error("IPC_STOPPED","IPC server is stopping");
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) {
            throw Error("IPC_TIMEOUT", "IPC request timed out");
        }

        pollfd item{fd, events, 0};
        const int result = poll(&item, 1, static_cast<int>(std::min<long long>(left, running?100:1000)));
        if (result > 0) {
            if (item.revents & events) {
                return;
            }
            if (item.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                throw Error("IPC_IO", "IPC socket closed");
            }
            continue;
        }
        if (result == 0 || errno == EINTR) {
            continue;
        }
        io_error("poll");
    }
}

void transfer(int fd, uint8_t* data, size_t size, bool writing, std::chrono::steady_clock::time_point deadline,const std::atomic_bool* running=nullptr) {
    size_t offset = 0;
    while (offset < size) {
        wait_fd(fd, writing ? POLLOUT : POLLIN, deadline,running);
        const auto count = writing
            ? send(fd, data + offset, size - offset, MSG_NOSIGNAL)
            : recv(fd, data + offset, size - offset, 0);

        if (count < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            io_error(writing ? "send" : "recv");
        }
        if (count == 0) {
            throw Error("IPC_IO", "IPC peer closed connection");
        }
        offset += static_cast<size_t>(count);
    }
}

sockaddr_un address_for(const std::string& name) {
    if (name.empty() || name.size() >= sizeof(sockaddr_un::sun_path)) {
        throw Error("IPC_CONFIG", "Unix socket path is invalid/too long");
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, name.c_str(), name.size() + 1);
    return address;
}
}

PipeServer::PipeServer(std::string name, Handler handler)
    : name_(std::move(name)), handler_(std::move(handler)) {
    if (name_.empty() || !handler_) {
        throw Error("IPC_CONFIG", "IPC server needs name and handler");
    }
}

PipeServer::~PipeServer() {
    stop();
}

void PipeServer::start() {
    if (running_.exchange(true)) {
        throw Error("IPC_LIFECYCLE", "IPC server already running");
    }
    owner_=std::make_unique<platform::ProcessInstanceLock>(owner_name(name_));
    if(!owner_->acquired()){owner_.reset();running_=false;throw Error("IPC_LIFECYCLE","Another IPC server owns this endpoint");}

    {
        std::lock_guard lock(error_mutex_);
        startup_error_.clear();
        startup_ready_ = false;
    }

    thread_ = std::jthread([this] { run(); });
    std::unique_lock lock(error_mutex_);
    if (!startup_cv_.wait_for(lock, std::chrono::seconds(3), [&] { return startup_ready_; })) {
        lock.unlock();
        stop();
        throw Error("IPC_IO", "Timed out creating Unix domain socket");
    }
    if (!startup_error_.empty()) {
        const auto error = startup_error_;
        lock.unlock();
        stop();
        throw Error("IPC_IO", "Unix socket startup failed: " + error);
    }
}

void PipeServer::stop() {
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
    std::error_code error;
    std::filesystem::remove(name_, error);
    owner_.reset();
}

void PipeServer::run() {
    try {
        std::error_code error;
        std::filesystem::remove(name_, error);

        Fd listener(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (listener.get() < 0) {
            io_error("socket");
        }

        const auto address = address_for(name_);
        if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
            io_error("bind");
        }
        if (chmod(name_.c_str(), 0600) < 0) {
            io_error("chmod");
        }

        // pkexec exposes the original desktop uid through PKEXEC_UID. Keep
        // restrictive permissions and transfer socket ownership back to that
        // user instead of making the endpoint globally accessible.
        if (geteuid() == 0) {
            if (const char* caller = std::getenv("PKEXEC_UID"); caller && *caller) {
                char* end = nullptr;
                errno = 0;
                const unsigned long raw = std::strtoul(caller, &end, 10);
                if (!errno && end && !*end && raw <= std::numeric_limits<uid_t>::max()) {
                    if (chown(name_.c_str(), static_cast<uid_t>(raw), static_cast<gid_t>(-1)) < 0) {
                        io_error("chown");
                    }
                }
            }
        }

        if (listen(listener.get(), 8) < 0) {
            io_error("listen");
        }
        {
            std::lock_guard lock(error_mutex_);
            startup_ready_ = true;
        }
        startup_cv_.notify_all();

        struct Worker { std::jthread thread;std::shared_ptr<std::atomic_bool> done; };
        std::vector<Worker> workers;
        const auto reap_workers=[&](bool all=false){std::erase_if(workers,[&](const Worker& worker){return all||worker.done->load();});};
        while (running_) {
            pollfd item{listener.get(), POLLIN, 0};
            const int poll_result = poll(&item, 1, 100);
            if (poll_result < 0) {
                if (errno == EINTR) {
                    continue;
                }
                io_error("poll accept");
            }
            if (poll_result == 0) {
                continue;
            }

            Fd client(accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC));
            if (client.get() < 0) {
                if (errno == EINTR) {
                    continue;
                }
                io_error("accept");
            }

            reap_workers();
            if(workers.size()>=16)continue;
            const int client_fd=client.get();
            auto done=std::make_shared<std::atomic_bool>(false);
            workers.push_back({std::jthread([this,client_fd,done] {
              Fd client(client_fd);
              try {
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                uint8_t header[header_size]{};
                transfer(client.get(), header, sizeof(header), false, deadline,&running_);
                if (get32(header) != magic || get16(header + 4) != 1) {
                    throw Error("IPC_PROTOCOL", "Bad IPC magic/version");
                }

                const uint16_t operation = get16(header + 6);
                const uint64_t request = get64(header + 8);
                const uint32_t length = get32(header + 16);
                if (!request || length > max_payload || operation < 1 || operation > 10) {
                    throw Error("IPC_PROTOCOL", "Invalid IPC request header");
                }

                std::string payload(length, '\0');
                if (length) {
                    transfer(client.get(), reinterpret_cast<uint8_t*>(payload.data()), length, false, deadline,&running_);
                }

                IpcResponse response;
                try {
                    response = handler_(static_cast<IpcOperation>(operation), payload);
                } catch (const Error& e) {
                    response = {1, e.code + ": " + e.what()};
                } catch (const std::exception& e) {
                    response = {2, std::string("INTERNAL: ") + e.what()};
                }

                auto output = frame(static_cast<uint16_t>(operation | 0x8000), request, response.status, response.payload);
                transfer(client.get(), output.data(), output.size(), true, deadline,&running_);
            } catch (const std::exception&) {
                // Malformed or disconnected clients are isolated from the server.
            }
              done->store(true);
            }),done});
            (void)client.release();
        }
        reap_workers(true);
    } catch (const std::exception& e) {
        std::lock_guard lock(error_mutex_);
        startup_error_ = e.what();
        startup_ready_ = true;
        running_ = false;
        startup_cv_.notify_all();
    }

    std::error_code error;
    std::filesystem::remove(name_, error);
}

IpcResponse pipe_request(const std::string& name, IpcOperation operation, const std::string& payload, uint32_t timeout_ms) {
    Fd socket_fd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (socket_fd.get() < 0) {
        io_error("socket");
    }

    const auto address = address_for(name);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    const int flags = fcntl(socket_fd.get(), F_GETFL, 0);
    if (flags < 0 || fcntl(socket_fd.get(), F_SETFL, flags | O_NONBLOCK) < 0) {
        io_error("fcntl");
    }

    if (connect(socket_fd.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0 && errno != EINPROGRESS) {
        throw Error("IPC_CONNECT", "Cannot connect CoreHost: " + std::string(std::strerror(errno)));
    }

    wait_fd(socket_fd.get(), POLLOUT, deadline);
    int connection_error = 0;
    socklen_t error_size = sizeof(connection_error);
    if (getsockopt(socket_fd.get(), SOL_SOCKET, SO_ERROR, &connection_error, &error_size) < 0) {
        io_error("getsockopt");
    }
    if (connection_error) {
        throw Error("IPC_CONNECT", "Cannot connect CoreHost: " + std::string(std::strerror(connection_error)));
    }
    if (fcntl(socket_fd.get(), F_SETFL, flags) < 0) {
        io_error("fcntl restore");
    }

    static std::atomic_uint64_t next_request{(static_cast<uint64_t>(platform::secure_random_u32())<<32)|platform::secure_random_u32()};
    uint64_t request=next_request.fetch_add(1,std::memory_order_relaxed);if(!request)request=next_request.fetch_add(1,std::memory_order_relaxed);
    auto output = frame(static_cast<uint16_t>(operation), request, 0, payload);
    transfer(socket_fd.get(), output.data(), output.size(), true, deadline);

    uint8_t header[header_size]{};
    transfer(socket_fd.get(), header, sizeof(header), false, deadline);
    if (get32(header) != magic || get16(header + 4) != 1 ||
        get16(header + 6) != (static_cast<uint16_t>(operation) | 0x8000) || get64(header + 8) != request) {
        throw Error("IPC_PROTOCOL", "Mismatched IPC response");
    }

    const uint32_t length = get32(header + 16);
    if (length < 4 || length > max_payload + 4) {
        throw Error("IPC_PROTOCOL", "Invalid IPC response size");
    }

    std::vector<uint8_t> body(length);
    transfer(socket_fd.get(), body.data(), body.size(), false, deadline);

    IpcResponse response;
    response.status = get32(body.data());
    response.payload.assign(reinterpret_cast<char*>(body.data() + 4), body.size() - 4);
    return response;
}
}
