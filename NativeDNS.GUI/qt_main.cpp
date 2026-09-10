#include "qt_app.hpp"
#include "single_instance.hpp"

#include <QApplication>
#include <QColor>
#include <QIcon>
#include <QPalette>
#include <QStyleFactory>
#include <QStringList>

namespace {
QPalette nativeDnsLightPalette(){
    QPalette palette;

    const QColor window(245,245,245);
    const QColor base(255,255,255);
    const QColor alternate(248,248,248);
    const QColor text(32,32,32);
    const QColor disabledText(125,125,125);
    const QColor highlight(0,120,215);

    palette.setColor(QPalette::Window,window);
    palette.setColor(QPalette::WindowText,text);
    palette.setColor(QPalette::Base,base);
    palette.setColor(QPalette::AlternateBase,alternate);
    palette.setColor(QPalette::Text,text);
    palette.setColor(QPalette::Button,window);
    palette.setColor(QPalette::ButtonText,text);
    palette.setColor(QPalette::ToolTipBase,base);
    palette.setColor(QPalette::ToolTipText,text);
    palette.setColor(QPalette::BrightText,QColor(190,0,0));
    palette.setColor(QPalette::Link,QColor(0,102,204));
    palette.setColor(QPalette::Highlight,highlight);
    palette.setColor(QPalette::HighlightedText,Qt::white);
#if QT_VERSION >= QT_VERSION_CHECK(5,12,0)
    palette.setColor(QPalette::PlaceholderText,QColor(120,120,120));
#endif

    palette.setColor(QPalette::Disabled,QPalette::WindowText,disabledText);
    palette.setColor(QPalette::Disabled,QPalette::Text,disabledText);
    palette.setColor(QPalette::Disabled,QPalette::ButtonText,disabledText);
    palette.setColor(QPalette::Disabled,QPalette::HighlightedText,QColor(230,230,230));
    return palette;
}
}

int main(int argc,char** argv){
    QApplication app(argc,argv);
    app.setApplicationName("NativeDNS");
    app.setApplicationVersion(QStringLiteral(NATIVEDNS_VERSION));
    app.setOrganizationName("NativeDNS");
    app.setQuitOnLastWindowClosed(false);
    app.setStyle(QStyleFactory::create("Fusion"));
    app.setPalette(nativeDnsLightPalette());
    app.setWindowIcon(QIcon(":/nativedns/nativedns.png"));

    // Do not inherit white menu/toolbar text from a dark OS palette while
    // forcing NativeDNS to use a light background.
    app.setStyleSheet(
        "QMenuBar, QMenu, QToolBar, QToolButton, QStatusBar { color: #202020; }"
        "QMenuBar, QToolBar, QStatusBar { background-color: #f5f5f5; }"
        "QMenu { background-color: #ffffff; }"
        "QMenuBar::item:selected, QMenu::item:selected { background-color: #0078d7; color: #ffffff; }"
        "QMenu::item:disabled, QToolButton:disabled { color: #7d7d7d; }"
        "QToolButton:hover, QPushButton:hover, QTabBar::tab:hover { background-color: #dcecf9; border-color: #7eb4dd; }"
        "QTableView::item:hover, QListView::item:hover, QTreeView::item:hover { background-color: #e5f1fb; color: #202020; }"
        "QComboBox QAbstractItemView::item:selected { background-color: #0078d7; color: #ffffff; }"
    );

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
