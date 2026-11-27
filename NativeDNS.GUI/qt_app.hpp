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
#include <thread>
#include <nativedns/config.hpp>

class LogPanel;
class QAction;
class QCloseEvent;
class QEvent;
class UpdateDialog;
class QMessageBox;

class NativeDnsWindow final : public QMainWindow {
public:
    explicit NativeDnsWindow(bool background = false, bool diagnostic_logging = false);
    ~NativeDnsWindow() override;

    void ensureCoreStarted();
    void showAndActivate();
    bool hasSystemTray() const;
    std::shared_ptr<const std::atomic_bool> exitConfirmedSignal() const {
        return exitConfirmed_;
    }

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
    void buildUi();
    void retranslateUi();
    void loadConfiguration();
    bool saveConfiguration();
    bool applyConfiguration();
    void syncConfigurationActions();
    bool restartCore();
    std::string effectiveFingerprint() const;
    std::string reloadRequest(const std::string& id) const;
    void requestCoreRestart();
    void applyFileLogging();
    void openInterceptionDiagnostics();
    void openServers();
    void openRules();
    void importConfiguration();
    void exportConfiguration();
    void startCore(bool transparent = true, bool reportFailure = true);
    bool shutdownCoreForExit();
    void exitApplication(bool force = false);
    void showCoreControlFailure(const QString& details);
    void refreshStatus();
    void refreshLogs();
    void refreshAutostartAction();
    void attachUpdateInstaller(UpdateDialog* dialog);
    void setStatusText(const QString& text, bool error = false, const QString& tooltip = {});
    void appendLocalLog(const QString& message, bool error = false);
    void appendLogLines(const QString& payload);
    std::filesystem::path configPath() const;

    nd::Config config_;
    bool diagnosticLogging_ = false;
    LogPanel* log_ = nullptr;
    QLabel* coreStatus_ = nullptr;
    QSystemTrayIcon* tray_ = nullptr;
    QAction* hideToTrayAction_ = nullptr;
    QAction* autostartAction_ = nullptr;
    QAction* prepareSystemDnsAction_ = nullptr;
    QPointer<UpdateDialog> updateDialog_;
    QPointer<QMessageBox> coreControlDialog_;
    QString lastCoreStatus_, lastCoreContact_;
    QTimer statusTimer_, logTimer_;
    QElapsedTimer coreLaunchTimer_, networkProbeTimer_, coreHealthyTimer_, coreFailureTimer_;
    QString networkSignature_;
    uint64_t logSequence_ = 0;
    bool exiting_ = false;
    bool autostartNeedsRepair_ = false;
    bool hideToTray_ = true;
    bool darkTheme_ = false;
    bool trayAvailable_ = false;
    bool coreLaunchPending_ = false;
    bool networkAvailable_ = false;
    bool restartWhenNetworkReturns_ = false;
    bool reloadRejected_ = false;
    bool configurationConfirmed_ = false;
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
    std::shared_ptr<std::atomic_bool> exitConfirmed_ = std::make_shared<std::atomic_bool>(false);
    std::jthread shutdownWorker_;
};
