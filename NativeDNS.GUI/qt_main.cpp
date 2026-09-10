#include "qt_app.hpp"
#include "single_instance.hpp"
#include "ui_preferences.hpp"

#include <QApplication>
#include <QIcon>
#include <QSettings>
#include <QStringList>

int main(int argc,char** argv){
    QApplication app(argc,argv);
    app.setApplicationName("NativeDNS");
    app.setApplicationVersion(QStringLiteral(NATIVEDNS_VERSION));
    app.setOrganizationName("NativeDNS");
    app.setQuitOnLastWindowClosed(false);
    QSettings settings;
    setUiLanguage(settings.value("ui/language","en").toString()=="ru"?UiLanguage::russian:UiLanguage::english);
    applyUiTheme(app,settings.value("ui/darkTheme",false).toBool());
    app.setWindowIcon(QIcon(":/nativedns/nativedns.png"));

    const bool background=app.arguments().contains("--background");

    SingleInstanceGuard singleInstance;
    if(!singleInstance.acquire(!background)){
        return 0;
    }

    NativeDnsWindow window(background);
    singleInstance.setActivationHandler([&window]{window.showAndActivate();});

    if(!background)window.show();
    return app.exec();
}
