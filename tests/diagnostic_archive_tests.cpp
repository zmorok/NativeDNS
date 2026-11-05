#include "archive.hpp"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <iostream>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QTemporaryDir temp;
    const auto name = temp.filePath(QString::fromUtf8("журнал.log"));
    QFile input(name);
    if (!input.open(QIODevice::WriteOnly) || input.write("diagnostic sample\n") != 18)
        return 1;
    input.close();
    const auto archive = temp.filePath("test.zip");
    writeDiagnosticArchive(archive, {name});
    QFile output(archive);
    if (!output.open(QIODevice::ReadOnly))
        return 2;
    const auto bytes = output.readAll();
    if (!bytes.startsWith("PK\3\4") || !bytes.contains("diagnostic sample\n") ||
        bytes.lastIndexOf("PK\5\6") != bytes.size() - 22)
        return 3;
    bool rejected = false;
    try {
        writeDiagnosticArchive(temp.filePath("duplicate.zip"), {name, name});
    } catch (...) {
        rejected = true;
    }
    if (!rejected || QFile::exists(temp.filePath("duplicate.zip")))
        return 4;
    QFile huge(temp.filePath("huge.log"));
    if (!huge.open(QIODevice::WriteOnly) || !huge.resize(16 * 1024 * 1024 + 1))
        return 5;
    huge.close();
    rejected = false;
    try {
        writeDiagnosticArchive(temp.filePath("oversize.zip"), {huge.fileName()});
    } catch (...) {
        rejected = true;
    }
    if (!rejected || QFile::exists(temp.filePath("oversize.zip")))
        return 6;
    std::cout << "Bounded UTF-8 ZIP and atomic failure behavior passed\n";
    return 0;
}
