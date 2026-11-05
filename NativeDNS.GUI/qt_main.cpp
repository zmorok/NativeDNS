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
#include <iostream>
#include <exception>

namespace {
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

int main(int argc, char** argv) {
    std::set_terminate(&gui_terminate);
    nd::platform::initialize_application_paths();
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

    if (!background)
        window.showAndActivate();
    return app.exec();
}
