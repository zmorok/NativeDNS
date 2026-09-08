#pragma once

#include <QElapsedTimer>
#include <QLabel>
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QSystemTrayIcon>
#include <QTimer>
#include <filesystem>
#include <nativedns/config.hpp>

class QAction;
class QCloseEvent;

class NativeDnsWindow final : public QMainWindow {
public:
    explicit NativeDnsWindow(bool background=false);
    ~NativeDnsWindow() override;

    void ensureCoreStarted();
    void showAndActivate();

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void buildUi();
    void loadConfiguration();
    void saveConfiguration();
    void openServers();
    void openRules();
    void importConfiguration();
    void exportConfiguration();
    void startCore(bool transparent=true);
    void stopCore();
    void shutdownCoreForExit();
    bool waitForCoreShutdown(int timeoutMs);
    void exitApplication();
    void refreshStatus();
    void refreshLogs();
    void setStatusText(const QString& text,bool error=false);
    void applyLogLine(const QString& line,unsigned level);
    std::filesystem::path configPath() const;

    nd::Config config_;
    QPlainTextEdit* log_=nullptr;
    QLabel* coreStatus_=nullptr;
    QSystemTrayIcon* tray_=nullptr;
    QAction* hideToTrayAction_=nullptr;
    QTimer statusTimer_,logTimer_;
    QElapsedTimer coreLaunchTimer_;
    uint64_t logSequence_=0;
    bool exiting_=false;
    bool background_=false;
    bool hideToTray_=true;
    bool trayAvailable_=false;
    bool coreLaunchPending_=false;
    bool coreShutdownAttempted_=false;
};
