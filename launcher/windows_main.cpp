#include <windows.h>
#include <shellapi.h>
#include <algorithm>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using ModuleEntryFn = int (*)(int, char**);

std::string to_utf8(const std::wstring& value) {
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
    std::string out(static_cast<size_t>(size), '\0');
    if (!WideCharToMultiByte(CP_UTF8,
                             WC_ERR_INVALID_CHARS,
                             value.data(),
                             static_cast<int>(value.size()),
                             out.data(),
                             size,
                             nullptr,
                             nullptr))
        return {};
    return out;
}

bool contains(const std::vector<std::wstring>& args, const wchar_t* option) {
    return std::find(args.begin(), args.end(), option) != args.end();
}

void report(const std::wstring& message, bool quiet) {
    const auto output = GetStdHandle(STD_ERROR_HANDLE);
    if (output && output != INVALID_HANDLE_VALUE) {
        std::string bytes = to_utf8(message);
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
            throw std::runtime_error("Cannot locate NativeDNS executable");
        const std::filesystem::path exe_path(path, path + length);
        const auto root = exe_path.parent_path();
        const auto bin_dir = root / L"bin";

        std::wstring module_name = L"NativeDNS.GUI.dll";
        const char* entry_symbol = "nativedns_run_gui";
        bool collect = false;
        bool cli = false;
        if (!args.empty() && args.front() == L"--core-host") {
            args.erase(args.begin());
            module_name = L"NativeDNS.CoreHost.dll";
            entry_symbol = "nativedns_run_core_host";
        } else if (!args.empty() && args.front() == L"--cli") {
            args.erase(args.begin());
            module_name = L"NativeDNS.Cli.dll";
            entry_symbol = "nativedns_run_cli";
            cli = true;
            quiet = true;
        } else if (!args.empty() && args.front() == L"--collect") {
            args.erase(args.begin());
            module_name = L"NativeDNS.Diagnostics.dll";
            entry_symbol = "nativedns_run_diagnostics";
            collect = true;
        }

        const auto module_path = bin_dir / module_name;
        if (!std::filesystem::is_regular_file(module_path) ||
            !std::filesystem::is_directory(bin_dir)) {
            report(L"The NativeDNS package is incomplete. Extract the complete archive, including "
                   L"the bin folder.",
                   quiet);
            return 3;
        }

        if (cli) {
            const auto output = GetStdHandle(STD_OUTPUT_HANDLE);
            if (!output || output == INVALID_HANDLE_VALUE)
                (void)AttachConsole(ATTACH_PARENT_PROCESS);
        }

        if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                      LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                      LOAD_LIBRARY_SEARCH_USER_DIRS) ||
            !AddDllDirectory(bin_dir.c_str()) || !SetDllDirectoryW(bin_dir.c_str()))
            throw std::runtime_error("Cannot configure packaged runtime directory");

        const HMODULE module = LoadLibraryExW(
            module_path.c_str(),
            nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (!module) {
            report(L"NativeDNS could not load its runtime module (" + module_name +
                       L"). Windows error=" + std::to_wstring(GetLastError()),
                   quiet);
            return 4;
        }

        const auto entry =
            reinterpret_cast<ModuleEntryFn>(GetProcAddress(module, entry_symbol));
        if (!entry) {
            FreeLibrary(module);
            report(L"NativeDNS runtime module is missing its entry point.", quiet);
            return 4;
        }

        std::vector<std::string> utf8_storage;
        utf8_storage.reserve(args.size() + 1);
        utf8_storage.push_back(to_utf8(exe_path.wstring()));
        for (const auto& arg : args)
            utf8_storage.push_back(to_utf8(arg));
        std::vector<char*> c_argv;
        c_argv.reserve(utf8_storage.size() + 1);
        for (auto& item : utf8_storage)
            c_argv.push_back(item.data());
        c_argv.push_back(nullptr);

        const int code = entry(static_cast<int>(utf8_storage.size()), c_argv.data());
        if (collect && !quiet) {
            MessageBoxW(
                nullptr,
                code ? L"Diagnostic collection failed. Partial results may be available in logs."
                     : L"Diagnostic collection finished. The report is in the logs folder.",
                L"NativeDNS diagnostics",
                MB_OK | MB_SETFOREGROUND | MB_TOPMOST |
                    (code ? MB_ICONERROR : MB_ICONINFORMATION));
        }
        return code;
    } catch (const std::exception& error) {
        const std::string text = error.what();
        report(std::wstring(text.begin(), text.end()), quiet);
        return 5;
    }
}
