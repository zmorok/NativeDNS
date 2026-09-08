#pragma once

#include <QObject>
#include <QLocalServer>
#include <QLockFile>
#include <functional>

class SingleInstanceGuard final : public QObject {
public:
    explicit SingleInstanceGuard(QObject* parent = nullptr);

    // Returns true only for the primary GUI instance. Secondary instances
    // notify the primary process and must exit immediately.
    bool acquire(bool activateExisting);
    void setActivationHandler(std::function<void()> handler);

private:
    static QString lockFilePath();
    static QString serverName();
    bool notifyExisting(bool activateExisting) const;
    void acceptPendingConnections();

    QLockFile lock_;
    QLocalServer server_;
    std::function<void()> activationHandler_;
};
