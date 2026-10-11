#include <nativedns/ipc.hpp>
#include <nativedns/platform.hpp>
#include <windows.h>
#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
DWORD handle_count() {
    DWORD count = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &count))
        throw std::runtime_error("cannot inspect process handle count");
    return count;
}
} // namespace

int main(int argc, char** argv) {
    try {
        const auto seconds = argc == 2 ? std::stoul(argv[1]) : 10ul;
        const auto name = std::string(R"(\\.\pipe\NativeDNS.IpcStress.)") +
                          std::to_string(nd::platform::process_id());
        nd::PipeServer server(name, [](nd::IpcOperation op, const std::string& payload) {
            if (op == nd::IpcOperation::logs)
                Sleep(15); // Clients with short deadlines will abandon this work.
            return nd::IpcResponse{0, payload};
        });
        server.start();
        const auto baseline = handle_count();
        std::atomic_uint64_t completed = 0, expired = 0;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
        std::vector<std::future<void>> clients;
        for (unsigned worker = 0; worker < 8; ++worker)
            clients.push_back(std::async(std::launch::async, [&, worker] {
                unsigned iteration = 0;
                while (std::chrono::steady_clock::now() < deadline) {
                    const bool abandon = ++iteration % 7 == 0;
                    const auto payload = std::to_string(worker) + ':' + std::to_string(iteration);
                    try {
                        const auto response = nd::pipe_request(name,
                                                               abandon ? nd::IpcOperation::logs
                                                                       : nd::IpcOperation::status,
                                                               payload,
                                                               abandon ? 1 : 1500);
                        if (response.status || response.payload != payload)
                            throw std::runtime_error("stress response corrupted");
                        ++completed;
                    } catch (const nd::Error& error) {
                        if (!abandon ||
                            (error.code != "IPC_TIMEOUT" && error.code != "IPC_CONNECT"))
                            throw;
                        ++expired;
                    }
                }
            }));
        for (auto& client : clients)
            client.get();
        const auto cleanup_deadline = GetTickCount64() + 4000;
        auto after = handle_count();
        while (after > baseline + 8 && GetTickCount64() < cleanup_deadline) {
            Sleep(20);
            after = handle_count();
        }
        if (!server.running() || !completed || !expired || after > baseline + 8)
            throw std::runtime_error("IPC stress lost listener or leaked handles");
        if (nd::pipe_request(name, nd::IpcOperation::ping, "healthy").payload != "healthy")
            throw std::runtime_error("IPC did not recover after timeout churn");
        server.stop();
        std::cout << "seconds=" << seconds << " completed=" << completed << " expired=" << expired
                  << " handles_before=" << baseline << " handles_after=" << after << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
