#include "single_instance.hpp"
#include "window_activation.hpp"

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

bool SingleInstanceGuard::notifyExisting(bool activateExisting, bool diagnostic) const {
    if (activateExisting) {
        qint64 owner = 0;
        QString host, application;
        if (lock_.getLockInfo(&owner, &host, &application)) allowApplicationForeground(owner);
    }
    const QByteArray command = activateExisting ? QByteArray(diagnostic ? "ACTIVATE DEBUG\n" : "ACTIVATE NORMAL\n") : QByteArray("PING\n");

    // The primary instance may own the lock a little before its local server
    // begins listening. Retry briefly rather than starting a duplicate GUI.
    for (int attempt = 0; attempt < 30; ++attempt) {
        QLocalSocket socket;
        socket.connectToServer(serverName(), QIODevice::ReadWrite);
        if (socket.waitForConnected(50)) {
            socket.write(command);
            socket.flush();
            socket.waitForBytesWritten(500);
            // Keep the pipe alive until the owner has consumed the command.
            // Closing immediately after a buffered write can lose activation
            // on Windows, especially for simultaneous normal/Debug launches.
            if (socket.bytesAvailable() == 0) socket.waitForReadyRead(1000);
            (void)socket.readAll();
            socket.disconnectFromServer();
            // Earlier versions do not send an acknowledgement. A live owner
            // still prevents another instance, without replaying activation.
            return true;
        }
        QThread::msleep(50);
    }
    return false;
}

bool SingleInstanceGuard::acquire(bool activateExisting, bool diagnostic) {
    if (!lock_.tryLock(0)) {
        if (notifyExisting(activateExisting, diagnostic)) {
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

void SingleInstanceGuard::setActivationHandler(std::function<void(bool)> handler) {
    activationHandler_ = std::move(handler);
    if (pendingActivation_ && activationHandler_) {
        activationHandler_(*pendingActivation_); pendingActivation_.reset();
    }
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

        connect(socket, &QLocalSocket::disconnected, socket, &QObject::deleteLater);
        auto consume = [this, socket] {
            if (!socket->canReadLine()) {
                if (socket->bytesAvailable() > 128) socket->disconnectFromServer();
                return;
            }
            const auto command = socket->readLine(128);
            socket->write("OK\n"); socket->flush();
            socket->disconnectFromServer();
            if (command.startsWith("ACTIVATE")) {
                const bool diagnostic = command.startsWith("ACTIVATE DEBUG");
                if (activationHandler_) activationHandler_(diagnostic);
                else pendingActivation_ = diagnostic;
            }
        };
        connect(socket, &QLocalSocket::readyRead, this, consume);
        consume();
    }
}
