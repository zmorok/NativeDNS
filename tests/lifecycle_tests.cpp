#include <nativedns/platform.hpp>
#include <nativedns/config.hpp>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
void check(bool value, const char* message) {
    if (!value)
        throw std::runtime_error(message);
}

bool wait_until_locked(const std::string& name, nd::platform::InstanceScope scope) {
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
        bool available = false;
        {
            nd::platform::ProcessInstanceLock probe(name, scope);
            available = probe.acquired();
        }
        if (!available)
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
}

#ifdef _WIN32
void verify_force_shutdown_helper() {
    const auto executable = nd::widen(NATIVEDNS_COREHOST_TEST_PATH);
    auto command = L"\"" + executable + L"\" --help";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    // The production CoreHost never reaches main, opens IPC or takes the real
    // singleton. This safely models an unresponsive Core with no control pipes.
    check(CreateProcessW(nullptr,
                         command.data(),
                         nullptr,
                         nullptr,
                         FALSE,
                         CREATE_NO_WINDOW | CREATE_SUSPENDED,
                         nullptr,
                         nullptr,
                         &startup,
                         &child) != FALSE,
          "cannot create suspended CoreHost child");
    struct Cleanup {
        PROCESS_INFORMATION process;
        ~Cleanup() {
            TerminateProcess(process.hProcess, 99);
            WaitForSingleObject(process.hProcess, 5000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    } cleanup{child};
    nd::platform::ProcessIdentity identity;
    for (const auto candidate : nd::platform::matching_processes(executable))
        if (candidate.pid == child.dwProcessId)
            identity = candidate;
    check(identity.started != 0, "cannot discover suspended CoreHost identity");
    const auto helper = [&](uint64_t started) {
        auto args = L"\"" + executable + L"\" --force-shutdown " + std::to_wstring(identity.pid) +
                    L" " + std::to_wstring(started);
        PROCESS_INFORMATION process{};
        check(CreateProcessW(nullptr,
                             args.data(),
                             nullptr,
                             nullptr,
                             FALSE,
                             CREATE_NO_WINDOW,
                             nullptr,
                             nullptr,
                             &startup,
                             &process) != FALSE,
              "cannot start production force-shutdown helper");
        const auto wait = WaitForSingleObject(process.hProcess, 5000);
        DWORD code = 0;
        GetExitCodeProcess(process.hProcess, &code);
        if (wait != WAIT_OBJECT_0) {
            TerminateProcess(process.hProcess, 99);
            WaitForSingleObject(process.hProcess, 5000);
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        check(wait == WAIT_OBJECT_0, "force-shutdown helper timed out");
        return code;
    };
    check(helper(identity.started + 1) == 10 &&
              WaitForSingleObject(child.hProcess, 0) == WAIT_TIMEOUT,
          "production helper must reject a stale birth token");
    check(helper(identity.started) == 0 &&
              WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0,
          "production helper must terminate CoreHost without any IPC endpoint");
    DWORD exit_code = 0;
    GetExitCodeProcess(child.hProcess, &exit_code);
    check(exit_code == 12, "forced CoreHost exit code must be 12");
}
#endif

void verify_abnormal_process_release(const std::string& name, nd::platform::InstanceScope scope) {
    const std::string option =
        scope == nd::platform::InstanceScope::machine ? "--hold-machine-lock" : "--hold-lock";
#ifdef _WIN32
    auto command = L"\"" + nd::platform::executable_path().wstring() + L"\" " + nd::widen(option) +
                   L" " + std::wstring(name.begin(), name.end());
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    check(CreateProcessW(nullptr,
                         command.data(),
                         nullptr,
                         nullptr,
                         FALSE,
                         CREATE_NO_WINDOW,
                         nullptr,
                         nullptr,
                         &startup,
                         &process) != FALSE,
          "cannot launch lifecycle crash child");
    CloseHandle(process.hThread);
    check(wait_until_locked(name, scope), "crash child did not acquire process-instance lock");
    nd::platform::ProcessIdentity identity;
    for (const auto candidate : nd::platform::matching_processes(nd::platform::executable_path()))
        if (candidate.pid == process.dwProcessId)
            identity = candidate;
    check(identity.pid && identity.started, "cannot discover lifecycle child identity");
    bool rejected = false;
    try {
        nd::platform::force_stop_process(nd::platform::executable_path(),
                                         {identity.pid, identity.started + 1});
    } catch (const nd::Error&) {
        rejected = true;
    }
    check(rejected && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT,
          "wrong birth token must not terminate a live process");
    rejected = false;
    try {
        nd::platform::force_stop_process(
            nd::platform::executable_path().parent_path() / "other.exe", identity);
    } catch (const nd::Error&) {
        rejected = true;
    }
    check(rejected && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT,
          "wrong executable must not terminate a live process");
    nd::platform::force_stop_process(nd::platform::executable_path(), identity);
    check(WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0,
          "lifecycle crash child did not terminate");
    CloseHandle(process.hProcess);
    // Already exited processes are a successful, idempotent shutdown.
    nd::platform::force_stop_process(nd::platform::executable_path(), identity);
#else
    const auto child = fork();
    check(child >= 0, "cannot fork lifecycle crash child");
    if (child == 0) {
        execl(nd::platform::executable_path().c_str(),
              nd::platform::executable_path().c_str(),
              option.c_str(),
              name.c_str(),
              nullptr);
        _exit(127);
    }
    check(wait_until_locked(name, scope), "crash child did not acquire process-instance lock");
    check(kill(child, SIGKILL) == 0, "cannot terminate lifecycle crash child");
    int status = 0;
    check(waitpid(child, &status, 0) == child, "cannot reap lifecycle crash child");
#endif
    nd::platform::ProcessInstanceLock recovered(name, scope);
    check(recovered.acquired(),
          "process-instance lock must recover after forced process termination");
}
} // namespace

int main(int argc, char** argv) {
    try {
#ifdef _WIN32
        if (argc == 2 && std::string(argv[1]) == "--stuck-shutdown") {
            auto deadline = nd::platform::watch_shutdown_deadline([] { return true; });
            std::this_thread::sleep_for(std::chrono::seconds(30));
            return 1;
        }
#endif
        if (argc == 3 && (std::string(argv[1]) == "--hold-lock" ||
                          std::string(argv[1]) == "--hold-machine-lock")) {
            nd::platform::ProcessInstanceLock held(argv[2],
                                                   std::string(argv[1]) == "--hold-machine-lock"
                                                       ? nd::platform::InstanceScope::machine
                                                       : nd::platform::InstanceScope::session);
            if (!held.acquired())
                return 2;
            std::this_thread::sleep_for(std::chrono::seconds(30));
            return 0;
        }
        const std::string name = "NativeDNS.Test.InstanceLock." +
                                 std::to_string(nd::platform::process_id()) + "." +
                                 std::to_string(nd::platform::secure_random_u32());
        {
            nd::platform::ProcessInstanceLock first(name);
            check(first.acquired(), "first process-instance lock must be acquired");
            {
                nd::platform::ProcessInstanceLock second(name);
                check(!second.acquired(), "second process-instance lock must be rejected");
            }
        }
        nd::platform::ProcessInstanceLock afterRelease(name);
        check(afterRelease.acquired(), "process-instance lock must be reusable after owner exits");
        const std::string crash_name = name + ".Crash";
        verify_abnormal_process_release(crash_name, nd::platform::InstanceScope::session);
        verify_abnormal_process_release(crash_name + ".Machine",
                                        nd::platform::InstanceScope::machine);
#ifdef _WIN32
        verify_force_shutdown_helper();
        {
            // Exercise the production deadline in a disposable process whose
            // main thread simulates a permanently stuck backend stop/join.
            auto command =
                L"\"" + nd::platform::executable_path().wstring() + L"\" --stuck-shutdown";
            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            PROCESS_INFORMATION child{};
            check(CreateProcessW(nullptr,
                                 command.data(),
                                 nullptr,
                                 nullptr,
                                 FALSE,
                                 CREATE_NO_WINDOW,
                                 nullptr,
                                 nullptr,
                                 &startup,
                                 &child) != FALSE,
                  "cannot launch shutdown deadline child");
            CloseHandle(child.hThread);
            const auto wait = WaitForSingleObject(child.hProcess, 13000);
            DWORD exit_code = 0;
            GetExitCodeProcess(child.hProcess, &exit_code);
            if (wait != WAIT_OBJECT_0) {
                TerminateProcess(child.hProcess, 99);
                WaitForSingleObject(child.hProcess, 2000);
            }
            CloseHandle(child.hProcess);
            check(wait == WAIT_OBJECT_0 && exit_code == 12,
                  "shutdown deadline must exit even when backend cleanup is stuck");
        }
#endif
        std::cout << "Lifecycle instance-lock and crash-recovery tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
