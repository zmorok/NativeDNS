#include "platform_launcher.hpp"
#include <windows.h>
#include <shellapi.h>
#include <nativedns/platform.hpp>
#include <QFileInfo>

namespace {
std::wstring quote(const QString& value) {
    std::wstring s = value.toStdWString(), out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'\"') {
            out.append(slashes * 2 + 1, L'\\');
            out.push_back(c);
            slashes = 0;
            continue;
        }
        out.append(slashes, L'\\');
        slashes = 0;
        out.push_back(c);
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'\"');
    return out;
}

std::wstring joinArguments(const QStringList& arguments) {
    std::wstring params;
    for (const auto& arg : arguments) {
        if (!params.empty())
            params.push_back(L' ');
        params += quote(arg);
    }
    return params;
}

QString shellError(DWORD code) {
    if (code == ERROR_CANCELLED)
        return "Administrator approval was cancelled.";
    return QString("ShellExecuteEx failed: %1").arg(code);
}
} // namespace

bool launchNativeDnsCore(const QString& executable,
                         const QStringList& arguments,
                         bool elevated,
                         QString* error) {
    QString program = executable;
    QStringList effectiveArguments = arguments;
    const auto root = nd::platform::application_root_directory();
    const auto fileName = QFileInfo(executable).fileName();
    std::error_code ec;
    const bool unified =
        fileName.compare("NativeDNS.exe", Qt::CaseInsensitive) == 0 &&
        std::filesystem::is_regular_file(root / L"bin" / L"NativeDNS.CoreHost.dll", ec);
    const bool legacyStructured =
        fileName.compare("NativeDNS.CoreHost.exe", Qt::CaseInsensitive) == 0 &&
        std::filesystem::is_regular_file(root / L"NativeDNS.exe", ec) &&
        std::filesystem::is_directory(root / L"app" / L"lib", ec);
    if (unified || legacyStructured) {
        program = QString::fromStdWString((root / L"NativeDNS.exe").wstring());
        if (effectiveArguments.isEmpty() || effectiveArguments.first() != "--core-host")
            effectiveArguments.prepend("--core-host");
        if (!effectiveArguments.contains("--quiet"))
            effectiveArguments.append("--quiet");
    }
    const auto params = joinArguments(effectiveArguments);
    const auto file = program.toStdWString();

    SHELLEXECUTEINFOW info{sizeof(info)};
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = elevated ? L"runas" : L"open";
    info.lpFile = file.c_str();
    info.lpParameters = params.c_str();
    info.nShow = SW_HIDE;

    if (!ShellExecuteExW(&info)) {
        if (error)
            *error = shellError(GetLastError());
        return false;
    }
    if (info.hProcess)
        CloseHandle(info.hProcess);
    return true;
}

bool runNativeDnsHelper(const QString& executable,
                        const QStringList& arguments,
                        bool elevated,
                        int* exitCode,
                        QString* error,
                        int timeoutMs) {
    QString program = executable;
    QStringList effectiveArguments = arguments;
    const auto root = nd::platform::application_root_directory();
    const auto fileName = QFileInfo(executable).fileName();
    std::error_code ec;
    const bool unified =
        fileName.compare("NativeDNS.exe", Qt::CaseInsensitive) == 0 &&
        std::filesystem::is_regular_file(root / L"bin" / L"NativeDNS.CoreHost.dll", ec);
    const bool legacyStructured =
        fileName.compare("NativeDNS.CoreHost.exe", Qt::CaseInsensitive) == 0 &&
        std::filesystem::is_regular_file(root / L"NativeDNS.exe", ec) &&
        std::filesystem::is_directory(root / L"app" / L"lib", ec);
    if (unified || legacyStructured) {
        program = QString::fromStdWString((root / L"NativeDNS.exe").wstring());
        if (effectiveArguments.isEmpty() || effectiveArguments.first() != "--core-host")
            effectiveArguments.prepend("--core-host");
        if (!effectiveArguments.contains("--quiet"))
            effectiveArguments.append("--quiet");
    }
    const auto params = joinArguments(effectiveArguments);
    const auto file = program.toStdWString();

    SHELLEXECUTEINFOW info{sizeof(info)};
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = elevated ? L"runas" : L"open";
    info.lpFile = file.c_str();
    info.lpParameters = params.c_str();
    info.nShow = SW_HIDE;

    if (!ShellExecuteExW(&info)) {
        if (error)
            *error = shellError(GetLastError());
        return false;
    }
    if (!info.hProcess) {
        if (error)
            *error = "Elevated helper did not return a process handle.";
        return false;
    }

    const DWORD wait = WaitForSingleObject(
        info.hProcess, timeoutMs < 0 ? INFINITE : static_cast<DWORD>(timeoutMs));
    if (wait != WAIT_OBJECT_0) {
        const DWORD code = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        if (wait == WAIT_TIMEOUT) {
            TerminateProcess(info.hProcess, ERROR_TIMEOUT);
            WaitForSingleObject(info.hProcess, 5000);
        }
        CloseHandle(info.hProcess);
        if (error)
            *error = QString("Waiting for elevated helper failed: %1").arg(code);
        return false;
    }

    DWORD code = 1;
    if (!GetExitCodeProcess(info.hProcess, &code)) {
        const DWORD winError = GetLastError();
        CloseHandle(info.hProcess);
        if (error)
            *error = QString("Cannot read elevated helper exit code: %1").arg(winError);
        return false;
    }
    CloseHandle(info.hProcess);

    if (exitCode)
        *exitCode = static_cast<int>(code);
    return true;
}
