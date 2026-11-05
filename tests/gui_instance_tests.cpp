#include "../NativeDNS.GUI/single_instance.hpp"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QProcess>
#include <QThread>
#include <QTimer>
#include <iostream>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    const bool secondary = args.size() > 1;
    app.setOrganizationName("NativeDNS.Tests");
    app.setApplicationName(
        secondary ? args[1] : "Instance-" + QString::number(QCoreApplication::applicationPid()));
    SingleInstanceGuard guard;
    if (secondary) {
        const bool owner = guard.acquire(true, args[2] == "debug");
        std::cout << "secondary mode=" << args[2].toStdString() << " owner=" << owner << '\n';
        return owner ? 1 : 0;
    }
    if (!guard.acquire(true, false))
        return 2;
    int normal = 0, debug = 0;
    guard.setActivationHandler([&](bool diagnostic) {
        if (diagnostic)
            ++debug;
        else
            ++normal;
    });
    QList<QProcess*> children;
    for (const auto* mode : {"normal", "debug", "normal", "debug"}) {
        auto* child = new QProcess(&app);
        child->start(QCoreApplication::applicationFilePath(), {app.applicationName(), mode});
        children << child;
    }
    QElapsedTimer deadline;
    deadline.start();
    while ((normal != 2 || debug != 2) && deadline.elapsed() < 10000) {
        QCoreApplication::processEvents();
        QThread::msleep(5);
    }
    for (auto* child : children) {
        if (!child->waitForFinished(1000) && child->state() != QProcess::NotRunning) {
            child->kill();
            child->waitForFinished();
            return 3;
        }
        std::cout << child->readAllStandardOutput().constData()
                  << child->readAllStandardError().constData();
        if (child->exitStatus() != QProcess::NormalExit || child->exitCode())
            return 4;
    }
    if (normal != 2 || debug != 2) {
        std::cerr << "activations normal=" << normal << " debug=" << debug << '\n';
        return 5;
    }
    std::cout
        << "Normal/Debug concurrent launches share one GUI owner and preserve requested mode\n";
    return 0;
}
