#include "../NativeDNS.GUI/window_activation.hpp"
#include <QApplication>
#include <QDialog>
#include <QMainWindow>
#include <QMessageBox>
#include <QtTest>
#ifdef Q_OS_WIN
#include <windows.h>
namespace {
bool aboveForeground(WId window) {
    const auto target = reinterpret_cast<HWND>(window);
    const auto foreground = GetForegroundWindow();
    // Windows may retain keyboard focus in the user's current process while
    // still allowing a new notification to appear above it. Check actual Z
    // order, rather than requiring an unattended runner to steal input focus.
    auto current = GetTopWindow(nullptr);
    for (int i = 0; current && i < 10000; ++i, current = GetWindow(current, GW_HWNDNEXT)) {
        if (current == target)
            return true;
        if (current == foreground)
            return false;
    }
    return false;
}
} // namespace
#endif

class WindowActivationTests final : public QObject {
    Q_OBJECT
private slots:
    void initTestCase() {
        installWindowActivation(*qApp);
    }
    void shownWindowsAndModalPriority() {
        QMainWindow main;
        main.show();
        QTRY_COMPARE(QApplication::activeWindow(), &main);
#ifdef Q_OS_WIN
        if (QGuiApplication::platformName() == "windows")
            QTRY_VERIFY(aboveForeground(main.winId()));
        QVERIFY((GetWindowLongPtrW(reinterpret_cast<HWND>(main.winId()), GWL_EXSTYLE) &
                 WS_EX_TOPMOST) == 0);
#endif
        QVERIFY(!main.windowFlags().testFlag(Qt::WindowStaysOnTopHint));
        QMessageBox notification(
            QMessageBox::Information, "NativeDNS test", "Notification", QMessageBox::Ok, &main);
        notification.setWindowModality(Qt::ApplicationModal);
        notification.show();
        // Simulate a pending Show callback or a second launcher while the
        // notification is open. Activation belongs to the modal window.
        activateApplicationWindow(main);
        QTRY_COMPARE(QApplication::activeWindow(), &notification);
#ifdef Q_OS_WIN
        if (QGuiApplication::platformName() == "windows")
            QTRY_VERIFY(aboveForeground(notification.winId()));
        QVERIFY((GetWindowLongPtrW(reinterpret_cast<HWND>(notification.winId()), GWL_EXSTYLE) &
                 WS_EX_TOPMOST) == 0);
#endif
        QVERIFY(!notification.windowFlags().testFlag(Qt::WindowStaysOnTopHint));
        notification.close();
        main.showMinimized();
        activateApplicationWindow(main);
        QTRY_VERIFY(!main.isMinimized());
        QTRY_COMPARE(QApplication::activeWindow(), &main);
    }
    void hiddenBackgroundAndShortLivedWindows() {
        QMainWindow background;
        QCoreApplication::processEvents();
        QVERIFY(!background.isVisible());
        auto* dialog = new QDialog;
        dialog->show();
        delete dialog;
        QCoreApplication::processEvents();
        QVERIFY(!background.isVisible());
    }
};
QTEST_MAIN(WindowActivationTests)
#include "window_activation_tests.moc"
