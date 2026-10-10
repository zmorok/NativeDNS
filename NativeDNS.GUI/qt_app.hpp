#pragma once

#include <QElapsedTimer>
#include <QLabel>
#include <QMainWindow>
#include <QPointer>
#include <QPlainTextEdit>
#include <QSystemTrayIcon>
#include <QTimer>
#include <atomic>
#include <filesystem>
#include <memory>
#include <nativedns/config.hpp>

class LogPanel;
class QAction;
class QCloseEvent;
class UpdateDialog;

class NativeDnsWindow final : public QMainWindow {
public:
    explicit NativeDnsWindow(bool background = false);
    ~NativeDnsWindow() override;

    void ensureCoreStarted();
    void showAndActivate();

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void buildUi();
    void retranslateUi();
    void loadConfiguration();
    bool saveConfiguration();
    bool applyConfiguration();
    bool restartCore();
    void requestCoreRestart();
    void applyFileLogging();
    void openServers();
    void openRules();
    void importConfiguration();
    void exportConfiguration();
    void startCore(bool transparent = true, bool reportFailure = true);
    bool shutdownCoreForExit();
    bool waitForCoreShutdown(int timeoutMs);
    void exitApplication();
    void refreshStatus();
    void refreshLogs();
    void setStatusText(const QString& text, bool error = false);
    void appendLocalLog(const QString& message, bool error = false);
    void appendLogLines(const QString& payload);
    std::filesystem::path configPath() const;

    nd::Config config_;
    LogPanel* log_ = nullptr;
    QLabel* coreStatus_ = nullptr;
    QSystemTrayIcon* tray_ = nullptr;
    QAction* hideToTrayAction_ = nullptr;
    QPointer<UpdateDialog> updateDialog_;
    QTimer statusTimer_, logTimer_;
    QElapsedTimer coreLaunchTimer_, networkProbeTimer_, coreHealthyTimer_;
    QString networkSignature_;
    uint64_t logSequence_ = 0;
    bool exiting_ = false;
    bool hideToTray_ = true;
    bool darkTheme_ = false;
    bool trayAvailable_ = false;
    bool coreLaunchPending_ = false;
    bool networkAvailable_ = false;
    bool restartWhenNetworkReturns_ = false;
    bool reloadRejected_ = false;
    bool networkErrorLogged_ = false;
    bool coreShutdownAttempted_ = false;
    bool coreControlErrorLogged_ = false;
    unsigned failedCorePolls_ = 0, automaticRestarts_ = 0;
    std::atomic_bool coreStartOperationPending_ = false;
    std::atomic_bool restartOperationPending_ = false;
    struct CoreLaunchState {
        std::atomic_bool cancelled = false, pending = false, issued = false;
    };
    std::shared_ptr<CoreLaunchState> coreLaunchState_ = std::make_shared<CoreLaunchState>();
    std::atomic_bool statusRefreshPending_ = false;
    std::atomic_bool logRefreshPending_ = false;
};
