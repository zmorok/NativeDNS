#pragma once
#include <QtGlobal>
class QApplication;
class QWidget;

// Promote newly shown main windows/dialogs, leaving background/tray launches hidden.
void installWindowActivation(QApplication& application);
void activateApplicationWindow(QWidget& window);
// The user-triggered secondary launch can grant the existing GUI permission
// to become foreground before sending its activation command.
void allowApplicationForeground(qint64 processId);

namespace window_platform {
void activate(QWidget& window);
}
