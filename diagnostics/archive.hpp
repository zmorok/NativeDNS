#pragma once
#include <QString>
#include <QStringList>
// Stored ZIP with UTF-8 basenames. Input and output are bounded; no ZIP64.
void writeDiagnosticArchive(const QString& destination, const QStringList& files);
