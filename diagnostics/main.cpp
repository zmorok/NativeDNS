#include "archive.hpp"
#include "windows_inspection.hpp"
#include <nativedns/config.hpp>
#include <nativedns/platform.hpp>
#include <curl/curl.h>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QHostAddress>
#include <QProcess>
#include <QRegularExpression>
#include <iostream>

namespace {
QString qPath(const std::filesystem::path& path) {
    return QString::fromUtf8(nd::platform::path_to_utf8(path));
}
struct CommandResult {
    int code = -1;
    QString output;
};
CommandResult run(const QString& executable, const QStringList& arguments, int timeout) {
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start(executable, arguments);
    if (!process.waitForStarted(3000))
        return {-1, "Cannot start diagnostic child: " + process.errorString()};
    // Bound both time and output while draining the pipe. Only this owned
    // child is terminated on timeout; no existing GUI/CoreHost is stopped.
    QByteArray output;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    while (process.state() != QProcess::NotRunning && std::chrono::steady_clock::now() < deadline) {
        process.waitForFinished(100);
        const auto chunk = process.readAll();
        if (output.size() + chunk.size() <= 2 * 1024 * 1024)
            output += chunk;
    }
    if (process.state() != QProcess::NotRunning) {
        process.kill();
        process.waitForFinished(3000);
        return {-1,
                QString::fromUtf8(output).replace("\r\n", "\n") + "\nDiagnostic command timed out"};
    }
    output += process.readAll().left(2 * 1024 * 1024 - output.size());
    return {process.exitStatus() == QProcess::NormalExit ? process.exitCode() : -1,
            QString::fromUtf8(output).replace("\r\n", "\n")};
}
QString httpsProbe(const QString& host, const QString& address) {
    CURL* curl = curl_easy_init();
    if (!curl)
        return "HTTPS initialization failed";
    const auto url = ("https://" + host + '/').toUtf8();
    const auto target =
        (host + ":443:" + (address.contains(':') ? '[' + address + ']' : address)).toUtf8();
    auto* resolve = curl_slist_append(nullptr, target.constData());
    if (!resolve) {
        curl_easy_cleanup(curl);
        return "HTTPS initialization failed";
    }
    char error[CURL_ERROR_SIZE]{};
    curl_easy_setopt(curl, CURLOPT_URL, url.constData());
    curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 8000L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
    // HEAD response headers must not reach stdout or enter the report.
    curl_easy_setopt(
        curl, CURLOPT_WRITEFUNCTION, +[](char*, size_t size, size_t count, void*) -> size_t {
            return size * count;
        });
    const auto result = curl_easy_perform(curl);
    long status = 0, verify = 0;
    char* remote = nullptr;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &verify);
    curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &remote);
    const auto text =
        QString("HTTPS address=%1 remote_ip=%2 curl=%3 http_code=%4 ssl_verify_result=%5 %6")
            .arg(address, QString::fromUtf8(remote ? remote : ""))
            .arg(static_cast<int>(result))
            .arg(status)
            .arg(verify)
            .arg(QString::fromUtf8(error));
    curl_easy_cleanup(curl);
    curl_slist_free_all(resolve);
    return text;
}
} // namespace
int main(int argc, char** argv) {
    try {
        nd::platform::initialize_application_paths();
        QCoreApplication app(argc, argv);
        const auto args = app.arguments();
        if (args.size() == 3 && args[1] == "--os-resolve") {
            for (const auto& address : nd::platform::resolve_host(args[2].toStdString()))
                std::cout << "OS address=" << address << '\n';
            return 0;
        }
        QString host, config = qPath(nd::platform::user_config_directory() / "NativeDNS.xml");
        bool offline = false;
        for (int i = 1; i < args.size(); ++i) {
            if (args[i] == "--offline")
                offline = true;
            else if (args[i] == "--host" && i + 1 < args.size())
                host = args[++i];
            else if (args[i] == "--config" && i + 1 < args.size())
                config = args[++i];
            else
                throw std::runtime_error("Usage: NativeDNS.Debug.exe --collect [--host DOMAIN] "
                                         "[--config FILE] [--offline] [--quiet]");
        }
        if (host.isEmpty()) {
            try {
                host = QString::fromStdString(
                    nd::load_config(nd::platform::path_from_utf8(config.toStdString()))
                        .test_target);
            } catch (...) {
                host = "example.com";
            }
        }
        host = QString::fromStdString(nd::normalize_host(host.toStdString()));
        const QDir logs(qPath(nd::platform::application_root_directory() / "logs"));
        if (!QDir().mkpath(logs.path()))
            throw std::runtime_error("Cannot create logs directory");
        const auto stamp = QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss-zzz") + '-' +
                           QString::number(QCoreApplication::applicationPid());
        const auto reportPath = logs.filePath("service-" + stamp + ".log");
        QFile report(reportPath);
        if (!report.open(QIODevice::WriteOnly | QIODevice::NewOnly))
            throw std::runtime_error("Cannot create diagnostic report");
        auto line = [&](const QString& text) {
            const auto bytes = (text + '\n').toUtf8();
            if (report.write(bytes) != bytes.size() || !report.flush())
                throw std::runtime_error("Cannot write diagnostic report");
            std::cout << bytes.constData() << std::flush;
        };
        const auto launcher = qPath(nd::platform::gui_entrypoint());
        auto cli = [&](const QStringList& command, int timeout = 15000) {
            QStringList child{"--cli", "--quiet"};
            child += command;
            const auto result = run(launcher, child, timeout);
            line("exit_code=" + QString::number(result.code) + '\n' + result.output.trimmed());
            return result;
        };
        line("NativeDNS diagnostics time=" +
             QDateTime::currentDateTime().toString(Qt::ISODateWithMs) + " host=" + host);
        line("Read-only collection. System DNS, hosts, browser settings and the configuration file "
             "are not changed.");
        line("HTTPS transport results do not establish service account or region eligibility.");
        line("=== CoreHost status ===");
        cli({"core", "status"}, 5000);
        line("=== Configuration, routes and system DNS inspection ===");
        cli({"diagnose", config, host});
        for (const auto& text : inspectWindowsDiagnostics())
            line(text);
        if (!offline) {
            line("=== Windows resolver (OS cache and encrypted DNS may apply) ===");
            const auto os =
                run(QCoreApplication::applicationFilePath(), {"--os-resolve", host}, 10000);
            line("exit_code=" + QString::number(os.code) + '\n' + os.output.trimmed());
            auto original = QStringLiteral("1.1.1.1");
            const auto resolvers = nd::platform::system_dns_servers();
            if (!resolvers.empty())
                original = QString::fromStdString(resolvers.front());
            line("Probe original resolver=" + original);
            QStringList addresses;
            for (const auto* type : {"A", "AAAA", "HTTPS"}) {
                line("=== Configured route DNS type=" + QString(type) + " ===");
                const auto result =
                    cli({"resolve", config, host, original, "53", "--type", type}, 20000);
                if (result.code != 0)
                    continue;
                for (const auto& text : result.output.split('\n')) {
                    if (!text.startsWith("rule=") || !text.contains("action=process rcode=0"))
                        continue;
                    for (const auto& token : text.split(' ')) {
                        QHostAddress address(token);
                        if (!address.isNull() && !address.isLoopback() &&
                            address != QHostAddress::AnyIPv4 && address != QHostAddress::AnyIPv6)
                            addresses << address.toString();
                    }
                }
            }
            addresses.removeDuplicates();
            if (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK) {
                for (const auto& address : addresses.mid(0, 2))
                    line(httpsProbe(host, address));
                curl_global_cleanup();
            } else
                line("HTTPS initialization failed");
        } else
            line("Offline collection: DNS and HTTPS network probes skipped.");
        const auto archive = logs.filePath("diagnostics-" + stamp + ".zip");
        line("Archive=" + archive);
        QStringList files{reportPath};
        qint64 bytes = report.size();
        const auto candidates = logs.entryInfoList({"NativeDNS-*.log"}, QDir::Files, QDir::Time);
        for (const auto& file : candidates) {
            if (files.size() == 4)
                break;
            if (file.size() > 16 * 1024 * 1024 - 65536 - bytes) {
                line("Skipped oversized log=" + file.fileName());
                continue;
            }
            files << file.absoluteFilePath();
            bytes += file.size();
        }
        report.close();
        writeDiagnosticArchive(archive, files);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "DIAGNOSTICS_ERROR " << error.what() << '\n';
        return 1;
    }
}
