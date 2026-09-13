#include "platform_launcher.hpp"
#include <windows.h>
#include <shellapi.h>

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
    const auto params = joinArguments(arguments);
    const auto file = executable.toStdWString();

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
                        QString* error) {
    const auto params = joinArguments(arguments);
    const auto file = executable.toStdWString();

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

    const DWORD wait = WaitForSingleObject(info.hProcess, INFINITE);
    if (wait != WAIT_OBJECT_0) {
        const DWORD code = GetLastError();
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
