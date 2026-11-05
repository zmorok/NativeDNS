#include "window_activation.hpp"
#include <QApplication>
#include <QDialog>
#include <QEvent>
#include <QMainWindow>
#include <QPointer>
#include <QTimer>

namespace {
class WindowActivation final : public QObject {
public:
    explicit WindowActivation(QApplication& app) : QObject(&app) {
        app.installEventFilter(this);
    }

protected:
    bool eventFilter(QObject* watched, QEvent* event) override {
        if (event->type() == QEvent::Show) {
            auto* widget = qobject_cast<QWidget*>(watched);
            if (widget && widget->isWindow() &&
                (qobject_cast<QMainWindow*>(widget) || qobject_cast<QDialog*>(widget)) &&
                !widget->testAttribute(Qt::WA_ShowWithoutActivating) &&
                !widget->testAttribute(Qt::WA_DontShowOnScreen)) {
                const QPointer<QWidget> window(widget);
                QTimer::singleShot(0, widget, [window] {
                    if (window && window->isVisible())
                        activateApplicationWindow(*window);
                });
            }
        }
        return QObject::eventFilter(watched, event);
    }
};
} // namespace
void installWindowActivation(QApplication& application) {
    static QPointer<WindowActivation> installed;
    if (!installed)
        installed = new WindowActivation(application);
}
void activateApplicationWindow(QWidget& window) {
    if (window.isMinimized())
        window.showNormal();
    if (!window.isVisible())
        window.show();
    // A pending main-window Show must not steal activation back from its
    // message box or another application-modal dialog opened in the meantime.
    QWidget* target = &window;
    if (auto* modal = QApplication::activeModalWidget();
        modal && modal != target && !modal->testAttribute(Qt::WA_DontShowOnScreen))
        target = modal;
    if (target->isMinimized())
        target->showNormal();
    if (!target->isVisible())
        target->show();
    target->raise();
    target->activateWindow();
    window_platform::activate(*target);
}
