#include <windows.h>
#include <shellapi.h>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>

namespace {
struct JobHandle {
    HANDLE value = nullptr;
    ~JobHandle() {
        if (value)
            CloseHandle(value);
    }
};
std::wstring quote(const std::wstring& text) {
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t c : text) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        result.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        result += c;
        slashes = 0;
    }
    result.append(slashes * 2, L'\\');
    result += L'"';
    return result;
}
bool contains(const std::vector<std::wstring>& args, const wchar_t* option) {
    return std::find(args.begin(), args.end(), option) != args.end();
}
void report(const std::wstring& message, bool quiet) {
    const auto output = GetStdHandle(STD_ERROR_HANDLE);
    if (output && output != INVALID_HANDLE_VALUE) {
        const auto size = WideCharToMultiByte(CP_UTF8,
                                              0,
                                              message.data(),
                                              static_cast<int>(message.size()),
                                              nullptr,
                                              0,
                                              nullptr,
                                              nullptr);
        std::string bytes(static_cast<size_t>(size), '\0');
        WideCharToMultiByte(CP_UTF8,
                            0,
                            message.data(),
                            static_cast<int>(message.size()),
                            bytes.data(),
                            size,
                            nullptr,
                            nullptr);
        bytes += '\n';
        DWORD written = 0;
        (void)WriteFile(output, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    }
    if (!quiet)
        MessageBoxW(nullptr,
                    message.c_str(),
                    L"NativeDNS",
                    MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}
} // namespace
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    bool quiet = false;
    try {
        int argc = 0;
        auto** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (!argv)
            return 2;
        std::vector<std::wstring> args;
        for (int i = 1; i < argc; ++i)
            args.emplace_back(argv[i]);
        LocalFree(argv);
        quiet = contains(args, L"--quiet");
        args.erase(std::remove(args.begin(), args.end(), L"--quiet"), args.end());
        wchar_t path[32768]{};
        const auto length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
        if (!length || length >= std::size(path))
            throw std::runtime_error("Cannot locate NativeDNS package");
        const auto root = std::filesystem::path(path).parent_path();
        const auto library = root / L"app" / L"lib";
        std::wstring name = L"NativeDNS.GUI.exe";
        bool wait = contains(args, L"--layout-check"), worker = false, collect = false;
        if (!args.empty() && args.front() == L"--core-host") {
            args.erase(args.begin());
            name = L"NativeDNS.CoreHost.exe";
            worker = true;
            wait = wait || contains(args, L"--register-autostart") ||
                   contains(args, L"--unregister-autostart") || contains(args, L"--force-shutdown");
        } else if (!args.empty() && args.front() == L"--collect") {
            args.erase(args.begin());
            name = L"NativeDNS.Diagnostics.exe";
            wait = worker = collect = true;
        } else if (!args.empty() && args.front() == L"--cli") {
            args.erase(args.begin());
            name = L"nativednsctl.exe";
            wait = worker = true;
            quiet = true;
        }
#ifdef NATIVEDNS_DEBUG_LAUNCHER
        if (!worker)
            args.emplace_back(L"--diagnostics");
#endif
        const auto executable = root / L"app" / L"bin" / name;
        if (!std::filesystem::is_regular_file(executable) ||
            !std::filesystem::is_directory(library)) {
            report(L"The NativeDNS package is incomplete. Extract the complete archive, including "
                   L"the app folder.",
                   quiet);
            return 3;
        }
        // Process-local setting inherited by CreateProcess children. Elevation
        // targets this static launcher, so the UAC broker need not inherit it.
        if (!SetDllDirectoryW(library.c_str()))
            throw std::runtime_error("Cannot configure packaged library directory");
        std::wstring command = quote(executable.wstring());
        for (const auto& arg : args) {
            command += L' ';
            command += quote(arg);
        }
        STARTUPINFOW startup{sizeof(startup)};
        const auto stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE),
                   stderr_handle = GetStdHandle(STD_ERROR_HANDLE);
        const bool inherit = stdout_handle && stdout_handle != INVALID_HANDLE_VALUE;
        if (inherit) {
            startup.dwFlags |= STARTF_USESTDHANDLES;
            startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            startup.hStdOutput = stdout_handle;
            startup.hStdError = stderr_handle;
        }
        PROCESS_INFORMATION process{};
        JobHandle job;
        if (worker && wait) {
            job.value = CreateJobObjectW(nullptr, nullptr);
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!job.value ||
                !SetInformationJobObject(
                    job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
                throw std::runtime_error("Cannot create diagnostic/helper process job");
        }
        const bool suspended = job.value || !worker;
        if (!CreateProcessW(executable.c_str(),
                            command.data(),
                            nullptr,
                            nullptr,
                            inherit,
                            (worker ? CREATE_NO_WINDOW : 0) | (suspended ? CREATE_SUSPENDED : 0),
                            nullptr,
                            root.c_str(),
                            &startup,
                            &process)) {
            report(L"NativeDNS could not start its application module. Windows error=" +
                       std::to_wstring(GetLastError()),
                   quiet);
            return 4;
        }
        if (job.value) {
            if (!AssignProcessToJobObject(job.value, process.hProcess)) {
                TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
                throw std::runtime_error("Cannot contain diagnostic/helper process");
            }
        }
        if (!worker)
            (void)AllowSetForegroundWindow(process.dwProcessId);
        if (suspended) {
            if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
                TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
                throw std::runtime_error("Cannot resume diagnostic/helper process");
            }
        }
        CloseHandle(process.hThread);
        DWORD code = 0;
        if (wait) {
            const auto status = WaitForSingleObject(process.hProcess, collect ? 150000 : INFINITE);
            if (status != WAIT_OBJECT_0) {
                TerminateProcess(process.hProcess, ERROR_TIMEOUT);
                code = ERROR_TIMEOUT;
            } else
                GetExitCodeProcess(process.hProcess, &code);
        }
        CloseHandle(process.hProcess);
        if (collect && !quiet) {
            MessageBoxW(
                nullptr,
                code ? L"Diagnostic collection failed. Partial results may be available in logs."
                     : L"Diagnostic collection finished. The report is in the logs folder.",
                L"NativeDNS diagnostics",
                MB_OK | MB_SETFOREGROUND | MB_TOPMOST | (code ? MB_ICONERROR : MB_ICONINFORMATION));
        }
        return static_cast<int>(code);
    } catch (const std::exception& error) {
        const std::string text = error.what();
        report(std::wstring(text.begin(), text.end()), quiet);
        return 5;
    }
}
