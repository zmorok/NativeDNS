#include "archive.hpp"
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QSet>
#include <QRegularExpression>
#include <QDateTime>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {
void put(QByteArray& output, quint32 value, int bytes) {
    for (int i = 0; i < bytes; ++i)
        output.append(static_cast<char>((value >> (i * 8)) & 255));
}
quint32 crc32(const QByteArray& data) {
    quint32 crc = 0xffffffff;
    for (const auto c : data) {
        crc ^= static_cast<unsigned char>(c);
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
} // namespace
QString redactDiagnosticText(const QString& text) {
    auto result = text;
    // Reports intentionally omit configuration XML and redact credentials from text logs.
    result.replace(QRegularExpression(R"((https?://)[^\s/@]+:[^\s/@]+@)",
                                      QRegularExpression::CaseInsensitiveOption),
                   "\\1[REDACTED]@");
    result.replace(QRegularExpression(R"((https?://[^\s?]+)\?[^\s]+)",
                                      QRegularExpression::CaseInsensitiveOption),
                   "\\1?[REDACTED]");
    result.replace(
        QRegularExpression(
            R"(\b(authorization|token|password|secret|private[_-]?key|api[_-]?key)\s*[:=]\s*[^\r\n]+)",
            QRegularExpression::CaseInsensitiveOption),
        "\\1=[REDACTED]");
    return result;
}
void writeDiagnosticArchive(const QString& destination, const QStringList& files) {
    constexpr qint64 limit = 16 * 1024 * 1024;
    struct Entry {
        QByteArray name;
        quint32 crc, size, offset;
    };
    std::vector<Entry> entries;
    QSet<QString> names;
    QSaveFile output(destination);
    if (!output.open(QIODevice::WriteOnly))
        throw std::runtime_error("Cannot create diagnostic archive");
    qint64 total = 0;
    for (const auto& path : files) {
        QFile input(path);
        if (!input.open(QIODevice::ReadOnly))
            throw std::runtime_error("Cannot read archive input");
        const auto name = QFileInfo(path).fileName();
        if (name.isEmpty() || name.contains('/') || name.contains('\\') || names.contains(name))
            throw std::runtime_error("Unsafe or duplicate diagnostic filename");
        if (input.size() < 0 || input.size() > limit - total)
            throw std::runtime_error("Diagnostic archive exceeds 16 MiB");
        auto data = input.read(limit - total + 1);
        if (input.error() != QFileDevice::NoError || data.size() > limit - total)
            throw std::runtime_error("Cannot read bounded archive input");
        if (QFileInfo(path).suffix() == "log")
            data = redactDiagnosticText(QString::fromUtf8(data)).toUtf8();
        if (data.size() > limit - total)
            throw std::runtime_error("Redacted diagnostic archive exceeds 16 MiB");
        total += data.size();
        names.insert(name);
        Entry entry{name.toUtf8(),
                    crc32(data),
                    static_cast<quint32>(data.size()),
                    static_cast<quint32>(output.pos())};
        if (entry.name.size() > 65535 || entries.size() >= 65535)
            throw std::runtime_error("ZIP entry limit exceeded");
        QByteArray header;
        put(header, 0x04034b50, 4);
        put(header, 20, 2);
        put(header, 0x800, 2);
        put(header, 0, 2);
        put(header, 0, 2);
        put(header, 0x21, 2);
        put(header, entry.crc, 4);
        put(header, entry.size, 4);
        put(header, entry.size, 4);
        put(header, static_cast<quint32>(entry.name.size()), 2);
        put(header, 0, 2);
        header += entry.name;
        if (output.write(header) != header.size() || output.write(data) != data.size())
            throw std::runtime_error("Cannot write ZIP entry");
        entries.push_back(entry);
    }
    const auto centralOffset = static_cast<quint32>(output.pos());
    QByteArray central;
    for (const auto& entry : entries) {
        put(central, 0x02014b50, 4);
        put(central, 20, 2);
        put(central, 20, 2);
        put(central, 0x800, 2);
        put(central, 0, 2);
        put(central, 0, 2);
        put(central, 0x21, 2);
        put(central, entry.crc, 4);
        put(central, entry.size, 4);
        put(central, entry.size, 4);
        put(central, static_cast<quint32>(entry.name.size()), 2);
        put(central, 0, 2);
        put(central, 0, 2);
        put(central, 0, 2);
        put(central, 0, 2);
        put(central, 0, 4);
        put(central, entry.offset, 4);
        central += entry.name;
    }
    QByteArray end;
    put(end, 0x06054b50, 4);
    put(end, 0, 2);
    put(end, 0, 2);
    put(end, static_cast<quint32>(entries.size()), 2);
    put(end, static_cast<quint32>(entries.size()), 2);
    put(end, static_cast<quint32>(central.size()), 4);
    put(end, centralOffset, 4);
    put(end, 0, 2);
    if (output.write(central) != central.size() || output.write(end) != end.size() ||
        !output.commit())
        throw std::runtime_error("Cannot finish diagnostic archive");
}
