#include "apply_update.hpp"
#include "zip_extract.hpp"

#include <windows.h>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

void write_file(const fs::path& path, const std::string& content) {
    if (path.has_parent_path())
        fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
        throw std::runtime_error("Cannot create test file");
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("Cannot read test file");
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void append_u16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
}

void append_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
}

struct StoredZipEntry {
    std::string name;
    std::string data;
    bool corrupt_crc = false;
};

void write_stored_zip(const fs::path& zip_path, const std::vector<StoredZipEntry>& entries) {
    std::vector<uint8_t> archive;
    struct CentralRecord {
        std::string name;
        uint32_t crc;
        uint32_t size;
        uint32_t offset;
    };
    std::vector<CentralRecord> records;
    for (const auto& entry : entries) {
        const uint32_t offset = static_cast<uint32_t>(archive.size());
        uint32_t crc = nd::updater::crc32_bytes(
            reinterpret_cast<const uint8_t*>(entry.data.data()), entry.data.size());
        if (entry.corrupt_crc)
            crc ^= 0x12345678u;
        const uint32_t size = static_cast<uint32_t>(entry.data.size());

        append_u32(archive, 0x04034B50u);
        append_u16(archive, 20);
        append_u16(archive, 0);
        append_u16(archive, 0); // STORED
        append_u16(archive, 0);
        append_u16(archive, 0);
        append_u32(archive, crc);
        append_u32(archive, size);
        append_u32(archive, size);
        append_u16(archive, static_cast<uint16_t>(entry.name.size()));
        append_u16(archive, 0);
        archive.insert(archive.end(), entry.name.begin(), entry.name.end());
        archive.insert(archive.end(), entry.data.begin(), entry.data.end());

        records.push_back({entry.name, crc, size, offset});
    }

    const uint32_t cd_offset = static_cast<uint32_t>(archive.size());
    for (const auto& rec : records) {
        append_u32(archive, 0x02014B50u);
        append_u16(archive, 20);
        append_u16(archive, 20);
        append_u16(archive, 0);
        append_u16(archive, 0);
        append_u16(archive, 0);
        append_u16(archive, 0);
        append_u32(archive, rec.crc);
        append_u32(archive, rec.size);
        append_u32(archive, rec.size);
        append_u16(archive, static_cast<uint16_t>(rec.name.size()));
        append_u16(archive, 0);
        append_u16(archive, 0);
        append_u16(archive, 0);
        append_u16(archive, 0);
        append_u32(archive, 0);
        append_u32(archive, rec.offset);
        archive.insert(archive.end(), rec.name.begin(), rec.name.end());
    }
    const uint32_t cd_size = static_cast<uint32_t>(archive.size()) - cd_offset;

    append_u32(archive, 0x06054B50u);
    append_u16(archive, 0);
    append_u16(archive, 0);
    append_u16(archive, static_cast<uint16_t>(records.size()));
    append_u16(archive, static_cast<uint16_t>(records.size()));
    append_u32(archive, cd_size);
    append_u32(archive, cd_offset);
    append_u16(archive, 0);

    std::ofstream out(zip_path, std::ios::binary | std::ios::trunc);
    if (!out)
        throw std::runtime_error("Cannot create stored ZIP");
    out.write(reinterpret_cast<const char*>(archive.data()),
              static_cast<std::streamsize>(archive.size()));
}

void create_deflate_zip_via_powershell(const fs::path& source_dir, const fs::path& zip_path) {
    std::wstring cmd =
        L"powershell.exe -NoProfile -NonInteractive -Command \""
        L"Add-Type -AssemblyName System.IO.Compression.FileSystem; "
        L"[System.IO.Compression.ZipFile]::CreateFromDirectory('" +
        source_dir.wstring() + L"', '" + zip_path.wstring() +
        L"', [System.IO.Compression.CompressionLevel]::Optimal, $true)\"";
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr,
                        cmd.data(),
                        nullptr,
                        nullptr,
                        FALSE,
                        CREATE_NO_WINDOW,
                        nullptr,
                        nullptr,
                        &si,
                        &pi))
        throw std::runtime_error("Failed to launch PowerShell ZipFile helper");
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (exit_code != 0)
        throw std::runtime_error("PowerShell ZipFile creation failed with exit code " +
                                 std::to_string(exit_code));
}

struct TempDirGuard {
    fs::path path;
    explicit TempDirGuard(const std::wstring& prefix) {
        path = fs::temp_directory_path() /
               (prefix + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(GetTickCount64()));
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path);
    }
    ~TempDirGuard() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

void test_zip_slip_and_crc_rejection(const fs::path& root) {
    const auto slip_zip = root / L"slip.zip";
    write_stored_zip(slip_zip, {{"../escape.txt", "bad"}});
    bool threw = false;
    try {
        nd::updater::extract_zip_archive(slip_zip, root / L"out-slip");
    } catch (const std::exception&) {
        threw = true;
    }
    if (!threw)
        throw std::runtime_error("Expected Zip Slip archive to be rejected");

    const auto bad_crc_zip = root / L"bad-crc.zip";
    write_stored_zip(bad_crc_zip, {{"pkg/file.txt", "hello world", true}});
    threw = false;
    try {
        nd::updater::extract_zip_archive(bad_crc_zip, root / L"out-crc");
    } catch (const std::exception&) {
        threw = true;
    }
    if (!threw)
        throw std::runtime_error("Expected corrupt CRC-32 archive to be rejected");
}

void test_deflate_extract_and_portable_apply(const fs::path& root) {
    // Build a v2 package tree with compressible content so Compress-Archive emits real DEFLATE.
    const auto pkg_src = root / L"NativeDNS-0.5.0-windows-x64-portable";
    std::string large_text;
    for (int i = 0; i < 400; ++i)
        large_text += "NativeDNS version 0.5.0 release line " + std::to_string(i) + "\n";

    write_file(pkg_src / L"NativeDNS.exe", "v2-launcher-" + large_text);
    write_file(pkg_src / L"Updater.exe", "v2-updater");
    write_file(pkg_src / L"bin" / L"NativeDNS.GUI.dll", "v2-gui-" + large_text);
    write_file(pkg_src / L"bin" / L"NativeDNS.CoreHost.dll", "v2-core");
    write_file(pkg_src / L"bin" / L"drivers" / L"WinDivert64.sys", "v2-driver");
    write_file(pkg_src / L"docs" / L"README.md", "v2-readme");
    fs::create_directories(pkg_src / L"logs");

    const auto zip_path = root / L"NativeDNS-0.5.0-windows-x64-portable.zip";
    create_deflate_zip_via_powershell(pkg_src, zip_path);

    // Prepare mock v1 installation with logs/, custom user file, and legacy 0.4.x artifacts.
    const auto install_dir = root / L"install";
    write_file(install_dir / L"NativeDNS.exe", "v1-launcher");
    write_file(install_dir / L"NativeDNS.Debug.exe", "legacy-debug");
    write_file(install_dir / L"app" / L"bin" / L"NativeDNS.CoreHost.exe", "legacy-core");
    write_file(install_dir / L"bin" / L"NativeDNS.GUI.dll", "v1-gui");
    write_file(install_dir / L"bin" / L"NativeDNS.CoreHost.dll", "v1-core");
    write_file(install_dir / L"docs" / L"README.md", "v1-readme");
    write_file(install_dir / L"logs" / L"NativeDNS-2026-11-27.log", "preserve-this-log");
    write_file(install_dir / L"custom-user-note.txt", "preserve-user-file");

    int last_pct = -1;
    nd::updater::apply_portable_update(
        zip_path,
        install_dir,
        root / L"work",
        false,
        [&](int pct, const std::wstring&) { last_pct = pct; },
        3,
        10);

    if (last_pct < 90)
        throw std::runtime_error("Expected progress callbacks to advance through cleanup");
    if (read_file(install_dir / L"NativeDNS.exe") != "v2-launcher-" + large_text)
        throw std::runtime_error("NativeDNS.exe was not updated to v2");
    if (read_file(install_dir / L"bin" / L"NativeDNS.GUI.dll") != "v2-gui-" + large_text)
        throw std::runtime_error("bin/NativeDNS.GUI.dll was not updated to v2");
    if (read_file(install_dir / L"bin" / L"distribution") != "portable\n")
        throw std::runtime_error("bin/distribution marker missing or wrong");
    if (read_file(install_dir / L"logs" / L"NativeDNS-2026-11-27.log") != "preserve-this-log")
        throw std::runtime_error("Existing log file was not preserved");
    if (read_file(install_dir / L"custom-user-note.txt") != "preserve-user-file")
        throw std::runtime_error("Custom user file was not preserved");
    if (fs::exists(install_dir / L"NativeDNS.Debug.exe") || fs::exists(install_dir / L"app"))
        throw std::runtime_error("Legacy 0.4.x files were not retired");
    if (fs::exists(install_dir / L"._update_backup"))
        throw std::runtime_error("Backup directory was not cleaned up");
}

void test_rollback_when_file_locked(const fs::path& root) {
    const auto zip_path = root / L"v2-stored.zip";
    write_stored_zip(zip_path,
                     {{"NativeDNS-0.5.0/NativeDNS.exe", "v2-launcher"},
                      {"NativeDNS-0.5.0/Updater.exe", "v2-updater"},
                      {"NativeDNS-0.5.0/bin/NativeDNS.GUI.dll", "v2-gui"},
                      {"NativeDNS-0.5.0/bin/NativeDNS.CoreHost.dll", "v2-core"},
                      {"NativeDNS-0.5.0/bin/drivers/WinDivert64.sys", "v2-driver"},
                      {"NativeDNS-0.5.0/docs/README.md", "v2-readme"}});

    const auto install_dir = root / L"install-locked";
    write_file(install_dir / L"NativeDNS.exe", "v1-launcher");
    write_file(install_dir / L"bin" / L"NativeDNS.GUI.dll", "v1-gui");
    write_file(install_dir / L"bin" / L"NativeDNS.CoreHost.dll", "v1-core");
    write_file(install_dir / L"docs" / L"README.md", "v1-readme");
    write_file(install_dir / L"logs" / L"keep.log", "keep-log");

    // Hold an exclusive non-shared lock on bin/NativeDNS.CoreHost.dll so moving bin/ fails.
    const auto locked_path = install_dir / L"bin" / L"NativeDNS.CoreHost.dll";
    HANDLE lock = CreateFileW(locked_path.c_str(),
                              GENERIC_READ | GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (lock == INVALID_HANDLE_VALUE)
        throw std::runtime_error("Failed to open exclusive test lock");

    bool threw = false;
    try {
        nd::updater::apply_portable_update(
            zip_path, install_dir, root / L"work-locked", false, {}, 2, 10);
    } catch (const std::exception&) {
        threw = true;
    }
    CloseHandle(lock);

    if (!threw)
        throw std::runtime_error("Expected update to fail while bin/CoreHost.dll is locked");
    if (read_file(install_dir / L"NativeDNS.exe") != "v1-launcher")
        throw std::runtime_error("Rollback failed to restore NativeDNS.exe");
    if (read_file(install_dir / L"bin" / L"NativeDNS.GUI.dll") != "v1-gui")
        throw std::runtime_error("Rollback failed to restore bin/NativeDNS.GUI.dll");
    if (read_file(install_dir / L"docs" / L"README.md") != "v1-readme")
        throw std::runtime_error("Rollback failed to restore docs/README.md");
    if (read_file(install_dir / L"logs" / L"keep.log") != "keep-log")
        throw std::runtime_error("Rollback damaged logs/keep.log");
    if (fs::exists(install_dir / L"._update_backup"))
        throw std::runtime_error("Rollback left ._update_backup behind");
}

void test_inno_setup_arguments() {
    const auto args = nd::updater::build_inno_setup_arguments(L"C:\\Program Files\\NativeDNS");
    const std::wstring expected =
        L"/SILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /DIR=\"C:\\Program Files\\NativeDNS\"";
    if (args != expected)
        throw std::runtime_error("Unexpected Inno Setup argument formatting");
}

} // namespace

int main() {
    try {
        TempDirGuard temp(L"NativeDNS-UpdaterTest-");
        test_zip_slip_and_crc_rejection(temp.path);
        test_deflate_extract_and_portable_apply(temp.path);
        test_rollback_when_file_locked(temp.path);
        test_inno_setup_arguments();
        std::cout << "updater_tests: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "updater_tests FAILED: " << error.what() << '\n';
        return 1;
    }
}
