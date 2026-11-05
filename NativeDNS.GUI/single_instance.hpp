#pragma once

#include <QObject>
#include <QLocalServer>
#include <QLockFile>
#include <functional>
#include <optional>

class SingleInstanceGuard final : public QObject {
public:
    explicit SingleInstanceGuard(QObject* parent = nullptr);

    // Returns true only for the primary GUI instance. Secondary instances
    // notify the primary process and must exit immediately.
    bool acquire(bool activateExisting, bool diagnostic = false);
    void setActivationHandler(std::function<void(bool)> handler);

private:
    static QString lockFilePath();
    static QString serverName();
    bool notifyExisting(bool activateExisting, bool diagnostic) const;
    void acceptPendingConnections();

    QLockFile lock_;
    QLocalServer server_;
    std::function<void(bool)> activationHandler_;
    std::optional<bool> pendingActivation_;
};
