#include "qt_app.hpp"
#include "single_instance.hpp"
#include "window_activation.hpp"
#include "ui_preferences.hpp"
#include <nativedns/logger.hpp>
#include <nativedns/platform.hpp>

#include <QApplication>
#include <QIcon>
#include <QSettings>
#include <QStringList>
#include <QMessageBox>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <exception>

namespace {
void cleanup_stale_updater_dirs() noexcept {
    try {
        std::error_code ec;
        const auto temp = std::filesystem::temp_directory_path(ec);
        if (ec || temp.empty())
            return;
        const auto now = std::filesystem::file_time_type::clock::now();
        for (const auto& entry : std::filesystem::directory_iterator(temp, ec)) {
            if (!entry.is_directory(ec))
                continue;
            const auto name = entry.path().filename().string();
            if (!name.starts_with("NativeDNS-Updater-"))
                continue;
            const auto modified = entry.last_write_time(ec);
            if (!ec && now - modified > std::chrono::seconds(60))
                std::filesystem::remove_all(entry.path(), ec);
        }
    } catch (...) {
    }
}

[[noreturn]] void gui_terminate() noexcept {
    std::string message = "GUI terminated without an active exception";
    if (const auto failure = std::current_exception())
        try {
            std::rethrow_exception(failure);
        } catch (const std::exception& error) {
            message = error.what();
        } catch (...) {
            message = "GUI terminated with an unknown exception";
        }
    try {
        nd::Logger logger(8);
        logger.configure_file(
            true,
            nd::Level::errors_only,
            nd::timestamped_log_path(nd::platform::application_root_directory() / "logs"));
        logger.write(nd::Level::errors_only, "GUI_TERMINATED", message);
    } catch (...) {
    }
    std::abort();
}
} // namespace

int run_gui_main(int argc, char** argv) {
    std::set_terminate(&gui_terminate);
    nd::platform::initialize_application_paths();
    cleanup_stale_updater_dirs();
    {
        std::error_code ec;
        const auto plugins_dir = nd::platform::application_root_directory() / "bin" / "plugins";
        if (std::filesystem::is_directory(plugins_dir, ec))
            QCoreApplication::setLibraryPaths(
                {QString::fromUtf8(nd::platform::path_to_utf8(plugins_dir))});
    }
    // Outlive the window, QApplication and Qt's shutdown callbacks.
    std::jthread exitDeadline;
    QApplication app(argc, argv);
    installWindowActivation(app);
    app.setApplicationName("NativeDNS");
    app.setApplicationVersion(QStringLiteral(NATIVEDNS_VERSION));
    app.setOrganizationName("NativeDNS");
    app.setQuitOnLastWindowClosed(false);
    QSettings settings;
    setUiLanguage(settings.value("ui/language", "en").toString() == "ru" ? UiLanguage::russian
                                                                         : UiLanguage::english);
    applyUiTheme(app, settings.value("ui/darkTheme", false).toBool());
    app.setWindowIcon(QIcon(":/nativedns/nativedns.png"));

    const bool background = app.arguments().contains("--background");
    const bool diagnostics = NATIVEDNS_DIAGNOSTIC_DEFAULT != 0 || app.arguments().contains("--diagnostics");
    if (app.arguments().contains("--layout-check")) {
        std::cout << "root=" << nd::platform::path_to_utf8(nd::platform::application_root_directory())
                  << "\nbinary=" << nd::platform::path_to_utf8(nd::platform::application_binary_directory())
                  << "\nplugins=" << QCoreApplication::libraryPaths().join(';').toUtf8().constData()
                  << "\ndiagnostics=" << (diagnostics ? 1 : 0) << '\n';
        return 0;
    }

    SingleInstanceGuard singleInstance;
    if (!singleInstance.acquire(!background, diagnostics)) {
        return 0;
    }

    NativeDnsWindow window(background, diagnostics);
    exitDeadline = nd::platform::watch_shutdown_deadline(
        [signal = window.exitConfirmedSignal()] { return signal->load(); });
    singleInstance.setActivationHandler([&window, diagnostics](bool requestedDiagnostic) {
        window.showAndActivate();
        if (requestedDiagnostic != diagnostics)
            QMessageBox::information(&window, "NativeDNS", uiText(
                "NativeDNS is already running in another mode. Exit it before switching between normal and diagnostic mode."));
    });

    if (!background || !window.hasSystemTray())
        window.showAndActivate();
    return app.exec();
}

#ifdef NATIVEDNS_GUI_MODULE
extern "C" __declspec(dllexport) int nativedns_run_gui(int argc, char** argv) {
    return run_gui_main(argc, argv);
}
#else
int main(int argc, char** argv) {
    return run_gui_main(argc, argv);
}
#endif
