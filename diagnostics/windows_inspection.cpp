#include "windows_inspection.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <vector>

namespace {
QString registryString(HKEY hive, const wchar_t* key, const wchar_t* name) {
    wchar_t value[4096]{};
    DWORD size = sizeof(value);
    if (RegGetValueW(hive,
                     key,
                     name,
                     RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                     nullptr,
                     value,
                     &size) != ERROR_SUCCESS)
        return {};
    return QString::fromWCharArray(value);
}
} // namespace
QStringList inspectWindowsDiagnostics() {
    QStringList lines{"=== WinDivert driver services ==="};
    const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (manager) {
        DWORD needed = 0, count = 0, resume = 0;
        EnumServicesStatusExW(manager,
                              SC_ENUM_PROCESS_INFO,
                              SERVICE_DRIVER,
                              SERVICE_STATE_ALL,
                              nullptr,
                              0,
                              &needed,
                              &count,
                              &resume,
                              nullptr);
        std::vector<BYTE> buffer(needed);
        resume = 0;
        if (!buffer.empty() && EnumServicesStatusExW(manager,
                                                     SC_ENUM_PROCESS_INFO,
                                                     SERVICE_DRIVER,
                                                     SERVICE_STATE_ALL,
                                                     buffer.data(),
                                                     static_cast<DWORD>(buffer.size()),
                                                     &needed,
                                                     &count,
                                                     &resume,
                                                     nullptr)) {
            const auto* entries =
                reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
            for (DWORD i = 0; i < count; ++i) {
                const auto name = QString::fromWCharArray(entries[i].lpServiceName);
                if (!name.contains("WinDivert", Qt::CaseInsensitive))
                    continue;
                auto text = name + " state=" +
                            QString::number(entries[i].ServiceStatusProcess.dwCurrentState);
                const auto service =
                    OpenServiceW(manager, entries[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (service) {
                    DWORD bytes = 0;
                    QueryServiceConfigW(service, nullptr, 0, &bytes);
                    std::vector<BYTE> config(bytes);
                    if (!config.empty() &&
                        QueryServiceConfigW(service,
                                            reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data()),
                                            bytes,
                                            &bytes))
                        text +=
                            " path=" + QString::fromWCharArray(
                                           reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data())
                                               ->lpBinaryPathName);
                    CloseServiceHandle(service);
                }
                lines << text;
            }
        } else
            lines << "Driver enumeration unavailable";
        CloseServiceHandle(manager);
    } else
        lines << "Cannot read Windows service manager";
    const auto resource =
        registryString(HKEY_LOCAL_MACHINE,
                       L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\System\\WinDivert",
                       L"EventMessageFile");
    if (!resource.isEmpty())
        lines << "Event Log WinDivert message resource=" + resource;
    lines << "=== NativeDNS processes ===";
    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry))
            do {
                const auto name = QString::fromWCharArray(entry.szExeFile);
                if (!name.startsWith("NativeDNS", Qt::CaseInsensitive))
                    continue;
                auto text = name + " pid=" + QString::number(entry.th32ProcessID);
                const auto process =
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
                if (process) {
                    wchar_t path[32768]{};
                    DWORD size = static_cast<DWORD>(std::size(path));
                    if (QueryFullProcessImageNameW(process, 0, path, &size))
                        text += " path=" + QString::fromWCharArray(path);
                    CloseHandle(process);
                }
                lines << text;
            } while (Process32NextW(snapshot, &entry));
        CloseHandle(snapshot);
    }
    lines << "=== Edge Secure DNS preferences ===";
    for (const auto hive : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) {
        const auto mode =
            registryString(hive, L"SOFTWARE\\Policies\\Microsoft\\Edge", L"DnsOverHttpsMode");
        if (!mode.isEmpty())
            lines << (hive == HKEY_CURRENT_USER ? "HKCU mode=" : "HKLM mode=") + mode;
    }
    QFile state(QDir(qEnvironmentVariable("LOCALAPPDATA"))
                    .filePath("Microsoft/Edge/User Data/Local State"));
    if (state.open(QIODevice::ReadOnly) && state.size() <= 16 * 1024 * 1024) {
        const auto object = QJsonDocument::fromJson(state.read(16 * 1024 * 1024 + 1))
                                .object()
                                .value("dns_over_https")
                                .toObject();
        lines << "Local State mode=" + object.value("mode").toString("unspecified") +
                     " templates_configured=" +
                     (object.value("templates").toString().isEmpty() ? "false" : "true");
    } else
        lines << "Local State unavailable or exceeds size limit";
    lines << "An unspecified Edge mode does not prove Secure DNS is disabled.";
    return lines;
}
