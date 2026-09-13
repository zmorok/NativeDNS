#include "qt_app.hpp"
#include "single_instance.hpp"
#include "ui_preferences.hpp"
#include <nativedns/logger.hpp>
#include <nativedns/platform.hpp>

#include <QApplication>
#include <QIcon>
#include <QSettings>
#include <QStringList>
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
    QApplication app(argc, argv);
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

    SingleInstanceGuard singleInstance;
    if (!singleInstance.acquire(!background)) {
        return 0;
    }

    NativeDnsWindow window(background);
    singleInstance.setActivationHandler([&window] { window.showAndActivate(); });

    if (!background)
        window.show();
    return app.exec();
}
