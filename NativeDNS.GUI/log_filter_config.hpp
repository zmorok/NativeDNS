#pragma once
#include <QList>
#include <QString>

struct SavedLogFilter {
    QString id, name, expression;
    bool operator==(const SavedLogFilter&) const = default;
};

void validateLogFilterConfig(const QList<SavedLogFilter>& filters);
QList<SavedLogFilter> loadLogFilterConfig(const QString& path);
void saveLogFilterConfig(const QString& path, const QList<SavedLogFilter>& filters);
