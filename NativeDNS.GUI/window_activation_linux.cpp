#include "window_activation.hpp"
#include <QWidget>
#include <QWindow>

void allowApplicationForeground(qint64) {
}
void window_platform::activate(QWidget& window) {
    if (auto* handle = window.windowHandle())
        handle->requestActivate();
}
