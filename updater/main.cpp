#include "apply_update.hpp"

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#pragma comment(linker, \
    "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {

constexpr UINT kMsgProgress = WM_APP + 1;
constexpr UINT kMsgFinished = WM_APP + 2;

struct Options {
    std::wstring mode;
    std::filesystem::path install_dir;
    std::filesystem::path package_path;
    uint32_t wait_pid = 0;
    std::wstring relaunch_args;
    bool russian = false;
    bool cleanup_package = false;
    bool quiet = false;
    bool layout_check = false;
};

struct UiState {
    HWND hwnd = nullptr;
    HWND label = nullptr;
    HWND bar = nullptr;
    HFONT font = nullptr;
    std::mutex mutex;
    std::wstring status_text;
    int percent = 0;
    bool failed = false;
    std::wstring error_text;
};

std::wstring widen_utf8(const std::string& text) {
    if (text.empty())
        return {};
    const int n = MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (n <= 0)
        return std::wstring(text.begin(), text.end());
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n);
    return out;
}

void write_stdout(const char* text) {
    const HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        (void)WriteFile(h, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
    }
}

void schedule_self_cleanup() {
    wchar_t path[32768]{};
    const DWORD n = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    if (!n || n >= std::size(path))
        return;
    const std::filesystem::path exe(path, path + n);
    const auto parent = exe.parent_path();
    const auto name = parent.filename().wstring();
    if (name.starts_with(L"NativeDNS-Updater-")) {
        (void)MoveFileExW(exe.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        (void)MoveFileExW(parent.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* state = reinterpret_cast<UiState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
        case WM_CREATE: {
            const auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
            return 0;
        }
        case kMsgProgress: {
            if (state) {
                std::wstring text;
                int pct = 0;
                {
                    std::lock_guard lock(state->mutex);
                    text = state->status_text;
                    pct = state->percent;
                }
                if (state->label)
                    SetWindowTextW(state->label, text.c_str());
                if (state->bar) {
                    if (pct < 0) {
                        const LONG_PTR style = GetWindowLongPtrW(state->bar, GWL_STYLE);
                        if ((style & PBS_MARQUEE) == 0) {
                            SetWindowLongPtrW(state->bar, GWL_STYLE, style | PBS_MARQUEE);
                            SendMessageW(state->bar, PBM_SETMARQUEE, TRUE, 30);
                        }
                    } else {
                        const LONG_PTR style = GetWindowLongPtrW(state->bar, GWL_STYLE);
                        if ((style & PBS_MARQUEE) != 0) {
                            SendMessageW(state->bar, PBM_SETMARQUEE, FALSE, 0);
                            SetWindowLongPtrW(state->bar, GWL_STYLE, style & ~PBS_MARQUEE);
                        }
                        SendMessageW(state->bar, PBM_SETPOS, static_cast<WPARAM>(pct), 0);
                    }
                }
            }
            return 0;
        }
        case kMsgFinished: {
            DestroyWindow(hwnd);
            return 0;
        }
        case WM_CLOSE:
            // Do not allow closing mid-update while files are being swapped.
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

Options parse_options() {
    Options opt;
    int argc = 0;
    auto** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        throw std::runtime_error("Cannot parse updater command line");
    std::vector<std::wstring> args;
    for (int i = 1; i < argc; ++i)
        args.emplace_back(argv[i]);
    LocalFree(argv);

    for (size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == L"--layout-check" || a == L"--version")
            opt.layout_check = true;
        else if (a == L"--quiet")
            opt.quiet = true;
        else if (a == L"--cleanup-package")
            opt.cleanup_package = true;
        else if (a == L"--mode" && i + 1 < args.size())
            opt.mode = args[++i];
        else if (a == L"--install-dir" && i + 1 < args.size())
            opt.install_dir = args[++i];
        else if (a == L"--package" && i + 1 < args.size())
            opt.package_path = args[++i];
        else if (a == L"--wait-pid" && i + 1 < args.size())
            opt.wait_pid = static_cast<uint32_t>(std::stoul(args[++i]));
        else if (a == L"--relaunch-args" && i + 1 < args.size())
            opt.relaunch_args = args[++i];
        else if (a == L"--lang" && i + 1 < args.size())
            opt.russian = (args[++i] == L"ru");
    }
    return opt;
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    Options opt;
    try {
        opt = parse_options();
    } catch (const std::exception& e) {
        MessageBoxW(nullptr, widen_utf8(e.what()).c_str(), L"NativeDNS Updater", MB_OK | MB_ICONERROR);
        return 2;
    }

    if (opt.layout_check) {
        write_stdout("NativeDNS Updater\n");
        return 0;
    }

    if ((opt.mode != L"portable" && opt.mode != L"executable") || opt.install_dir.empty() ||
        opt.package_path.empty()) {
        if (!opt.quiet) {
            const wchar_t* msg =
                opt.russian
                    ? L"Updater.exe запускается автоматически из окна «Проверить обновления» в NativeDNS."
                    : L"Updater.exe is launched automatically from NativeDNS Check for updates.";
            MessageBoxW(nullptr, msg, L"NativeDNS Updater", MB_OK | MB_ICONINFORMATION);
        }
        return 1;
    }

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&icc);

    UiState ui;
    const wchar_t* cls_name = L"NativeDNSUpdaterWindow";
    WNDCLASSEXW wc{sizeof(wc)};
    wc.lpfnWndProc = &window_proc;
    wc.hInstance = instance;
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1));
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = cls_name;
    RegisterClassExW(&wc);

    const int width = 440;
    const int height = 135;
    const int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
    const int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;
    const wchar_t* title = opt.russian ? L"Обновление NativeDNS" : L"Updating NativeDNS";

    ui.hwnd = CreateWindowExW(WS_EX_APPWINDOW,
                              cls_name,
                              title,
                              WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                              x,
                              y,
                              width,
                              height,
                              nullptr,
                              nullptr,
                              instance,
                              &ui);

    ui.font = CreateFontW(-14,
                          0,
                          0,
                          0,
                          FW_NORMAL,
                          FALSE,
                          FALSE,
                          FALSE,
                          DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS,
                          CLIP_DEFAULT_PRECIS,
                          CLEARTYPE_QUALITY,
                          DEFAULT_PITCH | FF_SWISS,
                          L"Segoe UI");

    const wchar_t* initial = opt.russian ? L"Ожидание закрытия NativeDNS..." : L"Waiting for NativeDNS to close...";
    ui.label = CreateWindowExW(0,
                               L"STATIC",
                               initial,
                               WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                               18,
                               18,
                               width - 44,
                               24,
                               ui.hwnd,
                               nullptr,
                               instance,
                               nullptr);
    ui.bar = CreateWindowExW(0,
                             PROGRESS_CLASSW,
                             nullptr,
                             WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                             18,
                             52,
                             width - 44,
                             24,
                             ui.hwnd,
                             nullptr,
                             instance,
                             nullptr);
    if (ui.font)
        SendMessageW(ui.label, WM_SETFONT, reinterpret_cast<WPARAM>(ui.font), TRUE);
    SendMessageW(ui.bar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

    if (!opt.quiet) {
        ShowWindow(ui.hwnd, SW_SHOWNORMAL);
        UpdateWindow(ui.hwnd);
    }

    auto post_progress = [&](int pct, const std::wstring& status) {
        {
            std::lock_guard lock(ui.mutex);
            ui.percent = pct;
            ui.status_text = status;
        }
        PostMessageW(ui.hwnd, kMsgProgress, 0, 0);
    };

    std::jthread worker([&] {
        try {
            post_progress(5,
                          opt.russian ? L"Ожидание закрытия NativeDNS..."
                                      : L"Waiting for NativeDNS to close...");
            (void)nd::updater::wait_for_process_exit(opt.wait_pid, 15000);
            nd::updater::stop_core_host_gracefully(opt.install_dir, 12000);

            if (opt.mode == L"executable") {
                post_progress(-1,
                              opt.russian ? L"Запуск установщика NativeDNS..."
                                          : L"Running NativeDNS installer...");
                nd::updater::run_executable_installer(opt.package_path, opt.install_dir);
            } else {
                const auto work_dir =
                    std::filesystem::temp_directory_path() /
                    (L"NativeDNS-Updater-Work-" + std::to_wstring(GetCurrentProcessId()));
                nd::updater::apply_portable_update(
                    opt.package_path, opt.install_dir, work_dir, opt.russian, post_progress);
                std::error_code ec;
                std::filesystem::remove_all(work_dir, ec);
            }

            if (opt.cleanup_package) {
                std::error_code ec;
                std::filesystem::remove(opt.package_path, ec);
            }

            post_progress(100,
                          opt.russian ? L"Запуск обновлённого NativeDNS..."
                                      : L"Starting updated NativeDNS...");
            nd::updater::relaunch_application(opt.install_dir, opt.relaunch_args);
        } catch (const std::exception& error) {
            std::lock_guard lock(ui.mutex);
            ui.failed = true;
            ui.error_text = widen_utf8(error.what());
        }
        PostMessageW(ui.hwnd, kMsgFinished, 0, 0);
    });

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (worker.joinable())
        worker.join();
    if (ui.font)
        DeleteObject(ui.font);

    schedule_self_cleanup();

    if (ui.failed) {
        if (!opt.quiet) {
            const std::wstring prefix =
                opt.russian ? L"Не удалось установить обновление:\n\n"
                            : L"Failed to apply the update:\n\n";
            MessageBoxW(nullptr,
                        (prefix + ui.error_text).c_str(),
                        title,
                        MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        }
        return 1;
    }
    return 0;
}
