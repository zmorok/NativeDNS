#include "single_instance.hpp"

#include <QCryptographicHash>
#include <QDir>
#include <QLocalSocket>
#include <QStandardPaths>
#include <QThread>

namespace {
QString instanceDirectory() {
    auto directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (directory.isEmpty()) {
        directory = QDir::tempPath() + "/NativeDNS";
    }
    QDir().mkpath(directory);
    return directory;
}
} // namespace

QString SingleInstanceGuard::lockFilePath() {
    return instanceDirectory() + "/gui-instance.lock";
}

QString SingleInstanceGuard::serverName() {
    const auto identity = QDir::cleanPath(instanceDirectory()).toUtf8();
    const auto digest =
        QCryptographicHash::hash(identity, QCryptographicHash::Sha256).toHex().left(16);
    return QStringLiteral("NativeDNS.GUI.Instance.v2.") + QString::fromLatin1(digest);
}

SingleInstanceGuard::SingleInstanceGuard(QObject* parent) : QObject(parent), lock_(lockFilePath()) {
    // PID/host based stale-lock detection remains active; do not expire a
    // healthy long-running NativeDNS instance just because it is old.
    lock_.setStaleLockTime(0);
}

bool SingleInstanceGuard::notifyExisting(bool activateExisting) const {
    const QByteArray command = activateExisting ? QByteArray("ACTIVATE\n") : QByteArray("PING\n");

    // The primary instance may own the lock a little before its local server
    // begins listening. Retry briefly rather than starting a duplicate GUI.
    for (int attempt = 0; attempt < 30; ++attempt) {
        QLocalSocket socket;
        socket.connectToServer(serverName(), QIODevice::WriteOnly);
        if (socket.waitForConnected(50)) {
            socket.write(command);
            socket.flush();
            socket.waitForBytesWritten(100);
            socket.disconnectFromServer();
            return true;
        }
        QThread::msleep(50);
    }
    return false;
}

bool SingleInstanceGuard::acquire(bool activateExisting) {
    if (!lock_.tryLock(0)) {
        if (notifyExisting(activateExisting)) {
            return false;
        }

        // Recover only a lock that QLockFile can prove stale. Never remove a
        // live owner's lock merely because its activation endpoint is busy.
        if (!lock_.removeStaleLockFile() || !lock_.tryLock(0)) {
            return false;
        }
    }

    QLocalServer::removeServer(serverName());
    server_.setSocketOptions(QLocalServer::UserAccessOption);

    if (server_.listen(serverName())) {
        connect(
            &server_, &QLocalServer::newConnection, this, [this] { acceptPendingConnections(); });
    }

    // Even if the activation endpoint cannot be created, the lock still
    // guarantees a single GUI process. Secondary launches will simply exit.
    return true;
}

void SingleInstanceGuard::setActivationHandler(std::function<void()> handler) {
    activationHandler_ = std::move(handler);
    if (server_.hasPendingConnections()) {
        acceptPendingConnections();
    }
}

void SingleInstanceGuard::acceptPendingConnections() {
    while (server_.hasPendingConnections()) {
        QLocalSocket* socket = server_.nextPendingConnection();
        if (!socket) {
            continue;
        }

        if (socket->bytesAvailable() == 0) {
            socket->waitForReadyRead(100);
        }
        const auto command = socket->readAll();
        if (command.startsWith("ACTIVATE") && activationHandler_) {
            activationHandler_();
        }

        socket->disconnectFromServer();
        socket->deleteLater();
    }
}
