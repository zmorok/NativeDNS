#include "apply_update.hpp"
#include "zip_extract.hpp"

#include <windows.h>
#include <shellapi.h>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>
#include <stdexcept>
#include <thread>
#include <vector>

namespace nd::updater {
namespace {

std::wstring quote_arg(const std::wstring& value) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') {
            ++slashes;
            continue;
        }
        out.append(ch == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        out.push_back(ch);
        slashes = 0;
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

std::wstring lower_name(const std::filesystem::path& p) {
    std::wstring s = p.filename().wstring();
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>(c + 32) : c;
    });
    return s;
}

std::string narrow_utf8(const std::wstring& value) {
    if (value.empty())
        return {};
    const int n = WideCharToMultiByte(CP_UTF8,
                                      0,
                                      value.data(),
                                      static_cast<int>(value.size()),
                                      nullptr,
                                      0,
                                      nullptr,
                                      nullptr);
    if (n <= 0)
        return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), n, nullptr, nullptr);
    return out;
}

void copy_or_move_entry(const std::filesystem::path& src, const std::filesystem::path& dst) {
    std::error_code ec;
    std::filesystem::rename(src, dst, ec);
    if (!ec)
        return;
    // Cross-volume fallback (e.g. %TEMP% on C: -> portable install on D:).
    std::filesystem::copy(
        src,
        dst,
        std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing,
        ec);
    if (ec)
        throw std::runtime_error("Cannot install updated entry " +
                                 narrow_utf8(dst.filename().wstring()) + ": " + ec.message());
}

void move_with_retry(const std::filesystem::path& src,
                     const std::filesystem::path& dst,
                     int max_attempts = 40,
                     uint32_t retry_delay_ms = 200) {
    std::error_code ec;
    const int attempts = std::max(1, max_attempts);
    for (int attempt = 0; attempt < attempts; ++attempt) {
        ec.clear();
        std::filesystem::rename(src, dst, ec);
        if (!ec)
            return;
        if (attempt + 1 < attempts && retry_delay_ms > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(retry_delay_ms));
    }
    throw std::runtime_error("File or directory is locked and cannot be replaced (" +
                             narrow_utf8(src.filename().wstring()) + "): " + ec.message());
}

bool is_core_host_lock_free() {
    HANDLE mutex = CreateMutexW(nullptr, FALSE, L"Global\\NativeDNS.CoreHost.Instance.v1");
    if (!mutex) {
        if (GetLastError() == ERROR_ACCESS_DENIED)
            return false;
        return true;
    }
    const bool free_now = GetLastError() != ERROR_ALREADY_EXISTS;
    CloseHandle(mutex);
    return free_now;
}

std::wstring text(bool ru, const wchar_t* en, const wchar_t* ru_text) {
    return ru ? std::wstring(ru_text) : std::wstring(en);
}

} // namespace

bool wait_for_process_exit(uint32_t pid, uint32_t timeout_ms) {
    if (!pid || pid == GetCurrentProcessId())
        return true;
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!process)
        return true;
    const DWORD result = WaitForSingleObject(process, timeout_ms);
    CloseHandle(process);
    return result == WAIT_OBJECT_0;
}

void stop_core_host_gracefully(const std::filesystem::path& install_dir, uint32_t timeout_ms) {
    if (is_core_host_lock_free())
        return;
    const auto entry = install_dir / L"NativeDNS.exe";
    std::error_code ec;
    if (std::filesystem::is_regular_file(entry, ec)) {
        std::wstring cmd = quote_arg(entry.wstring()) + L" --cli core shutdown --quiet";
        STARTUPINFOW si{sizeof(si)};
        PROCESS_INFORMATION pi{};
        if (CreateProcessW(entry.c_str(),
                           cmd.data(),
                           nullptr,
                           nullptr,
                           FALSE,
                           CREATE_NO_WINDOW,
                           nullptr,
                           install_dir.c_str(),
                           &si,
                           &pi)) {
            WaitForSingleObject(pi.hProcess, 8000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (is_core_host_lock_free()) {
            // Brief settle pause so WinDivert64.sys and binary handles fully close.
            std::this_thread::sleep_for(std::chrono::milliseconds(400));
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void apply_portable_update(const std::filesystem::path& zip_path,
                           const std::filesystem::path& install_dir,
                           const std::filesystem::path& temp_work_dir,
                           bool russian_ui,
                           const StatusProgressCallback& progress,
                           int move_retries,
                           uint32_t retry_delay_ms) {
    auto report = [&](int pct, const std::wstring& msg) {
        if (progress)
            progress(pct, msg);
    };

    std::error_code ec;
    if (!std::filesystem::is_directory(install_dir, ec))
        throw std::runtime_error("Target installation directory does not exist.");

    const auto staged_dir = temp_work_dir / L"staged";
    std::filesystem::remove_all(staged_dir, ec);
    std::filesystem::create_directories(staged_dir);

    report(15, text(russian_ui, L"Extracting update archive...", L"Распаковка архива обновления..."));
    extract_zip_archive(zip_path, staged_dir, [&](const ExtractProgress& p) {
        const int frac =
            p.bytes_total > 0
                ? static_cast<int>((p.bytes_done * 50ULL) / p.bytes_total)
                : (p.files_total > 0 ? static_cast<int>((p.files_done * 50ULL) / p.files_total) : 0);
        report(15 + std::clamp(frac, 0, 50),
               text(russian_ui, L"Extracting update archive...", L"Распаковка архива обновления..."));
    });

    const auto package_root = locate_package_root(staged_dir);
    for (const auto& required : {std::filesystem::path(L"NativeDNS.exe"),
                                 std::filesystem::path(L"bin") / L"NativeDNS.GUI.dll",
                                 std::filesystem::path(L"bin") / L"NativeDNS.CoreHost.dll",
                                 std::filesystem::path(L"bin") / L"drivers" / L"WinDivert64.sys"}) {
        if (!std::filesystem::is_regular_file(package_root / required, ec))
            throw std::runtime_error("Extracted update package is missing " +
                                     narrow_utf8(required.wstring()));
    }

    // Ensure portable distribution marker is present in the staged payload.
    {
        std::ofstream marker(package_root / L"bin" / L"distribution", std::ios::binary | std::ios::trunc);
        marker << "portable\n";
    }

    report(70, text(russian_ui, L"Applying update files...", L"Применение файлов обновления..."));

    // Collect managed top-level entries from the new package (never touch logs/).
    std::vector<std::filesystem::path> new_entries;
    std::set<std::wstring> managed_names;
    for (const auto& item : std::filesystem::directory_iterator(package_root)) {
        const auto lname = lower_name(item.path());
        if (lname == L"logs" || lname == L"._update_backup")
            continue;
        new_entries.push_back(item.path());
        managed_names.insert(lname);
    }

    // Also retire legacy 0.4.x layout items when upgrading to the unified bin/ layout.
    static const std::set<std::wstring> legacy_managed = {
        L"nativedns.debug.exe",
        L"app",
        L"licenses",
        L"examples",
        L"platforms",
        L"styles",
        L"iconengines",
        L"imageformats",
        L"tls",
        L"generic",
        L"networkinformation"};
    for (const auto& legacy : legacy_managed)
        managed_names.insert(legacy);

    const auto backup_dir = install_dir / L"._update_backup";
    std::filesystem::remove_all(backup_dir, ec);
    std::filesystem::create_directories(backup_dir);

    std::vector<std::wstring> backed_up;
    std::vector<std::wstring> installed;
    try {
        // Phase 1: Move existing managed entries into backup (preserving logs/ and user files).
        for (const auto& item : std::filesystem::directory_iterator(install_dir)) {
            const auto name = item.path().filename().wstring();
            const auto lname = lower_name(item.path());
            if (lname == L"logs" || lname == L"._update_backup")
                continue;
            if (!managed_names.contains(lname))
                continue;
            move_with_retry(item.path(), backup_dir / name, move_retries, retry_delay_ms);
            backed_up.push_back(name);
        }

        report(82, text(russian_ui, L"Installing new version...", L"Установка новой версии..."));

        // Phase 2: Move or copy staged package entries into install_dir.
        for (const auto& src : new_entries) {
            const auto name = src.filename().wstring();
            installed.push_back(name);
            copy_or_move_entry(src, install_dir / name);
        }
    } catch (...) {
        // Rollback: remove partially installed entries and restore everything from backup_dir.
        for (const auto& name : installed)
            std::filesystem::remove_all(install_dir / name, ec);
        for (const auto& name : backed_up) {
            ec.clear();
            std::filesystem::rename(backup_dir / name, install_dir / name, ec);
        }
        std::filesystem::remove_all(backup_dir, ec);
        std::filesystem::remove_all(staged_dir, ec);
        throw;
    }

    report(94, text(russian_ui, L"Cleaning up temporary files...", L"Очистка временных файлов..."));
    std::filesystem::remove_all(backup_dir, ec);
    std::filesystem::remove_all(staged_dir, ec);
}

std::wstring build_inno_setup_arguments(const std::filesystem::path& install_dir) {
    return L"/SILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /DIR=" +
           quote_arg(install_dir.wstring());
}

void run_executable_installer(const std::filesystem::path& setup_exe,
                              const std::filesystem::path& install_dir) {
    const std::wstring params = build_inno_setup_arguments(install_dir);
    SHELLEXECUTEINFOW info{sizeof(info)};
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = L"open";
    info.lpFile = setup_exe.c_str();
    info.lpParameters = params.c_str();
    info.lpDirectory = setup_exe.parent_path().c_str();
    info.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&info)) {
        const DWORD err = GetLastError();
        if (err == ERROR_CANCELLED)
            throw std::runtime_error("Installer elevation was cancelled by the user.");
        throw std::runtime_error("Cannot start NativeDNS installer: Win32=" + std::to_string(err));
    }
    if (!info.hProcess)
        throw std::runtime_error("Installer did not return a process handle.");

    WaitForSingleObject(info.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(info.hProcess, &exit_code);
    CloseHandle(info.hProcess);
    if (exit_code != 0)
        throw std::runtime_error("NativeDNS installer exited with code " +
                                 std::to_string(exit_code));
}

void relaunch_application(const std::filesystem::path& install_dir,
                          const std::wstring& extra_args) {
    const auto exe = install_dir / L"NativeDNS.exe";
    std::wstring cmd = quote_arg(exe.wstring());
    if (!extra_args.empty()) {
        cmd.push_back(L' ');
        cmd += extra_args;
    }
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.c_str(),
                        cmd.data(),
                        nullptr,
                        nullptr,
                        FALSE,
                        0,
                        nullptr,
                        install_dir.c_str(),
                        &si,
                        &pi)) {
        throw std::runtime_error("Updated NativeDNS could not be restarted: Win32=" +
                                 std::to_string(GetLastError()));
    }
    (void)AllowSetForegroundWindow(pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

} // namespace nd::updater
