#include "window_activation.hpp"
#include <QWidget>
#include <windows.h>
#include <limits>

void allowApplicationForeground(qint64 processId) {
    if (processId > 0 && processId <= std::numeric_limits<DWORD>::max())
        (void)AllowSetForegroundWindow(static_cast<DWORD>(processId));
}
void window_platform::activate(QWidget& window) {
    auto handle = reinterpret_cast<HWND>(window.winId());
    // Native file dialogs belong to a Windows popup rather than the hidden
    // QFileDialog QWidget. Activate that popup without materializing a host.
    if (const auto popup = GetLastActivePopup(handle); popup && IsWindowVisible(popup))
        handle = popup;
    // A background process may be denied keyboard activation. A temporary
    // topmost promotion still presents its window above the current one.
    // Restore its original band immediately, so it remains a normal window.
    const bool topmost = (GetWindowLongPtrW(handle, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
    constexpr UINT flags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;
    (void)SetWindowPos(handle, HWND_TOPMOST, 0, 0, 0, 0, flags);
    (void)SetForegroundWindow(handle);
    if (!topmost)
        (void)SetWindowPos(handle, HWND_NOTOPMOST, 0, 0, 0, 0, flags);
}
