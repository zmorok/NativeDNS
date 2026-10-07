#pragma once
#include <QDateTime>
#include <QList>
#include <QString>
#include <memory>
#include <optional>

struct LogRecord {
    quint64 sequence = 0;
    QDateTime timestamp;
    QString code, message, address, dnsType, rule, action;
    bool error = false;
};

class LogFilter {
public:
    struct Node;
    static std::optional<LogFilter> compile(const QString& expression, QString& error);
    bool matches(const LogRecord& record) const;

private:
    std::shared_ptr<const Node> root_;
};

QList<LogRecord> decodeLogRecords(const QString& payload);
