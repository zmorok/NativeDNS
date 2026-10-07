#include "log_filter_config.hpp"
#include "log_filter.hpp"
#include "ui_preferences.hpp"
#include <QFile>
#include <QSaveFile>
#include <QSet>
#include <QUuid>
#include <QXmlStreamReader>
#include <QXmlStreamWriter>
#include <stdexcept>

namespace {
constexpr qint64 maximumConfigBytes = 1024 * 1024;
[[noreturn]] void fail(const QString& message) {
    throw std::runtime_error(message.toUtf8().constData());
}
[[noreturn]] void invalidConfig() {
    fail(uiText("Invalid log filter configuration."));
}
} // namespace

void validateLogFilterConfig(const QList<SavedLogFilter>& filters) {
    if (filters.size() > 256)
        fail(uiText("Maximum 256 saved filters."));
    QSet<QString> ids;
    for (const auto& filter : filters) {
        if (filter.id.isEmpty() || filter.id.size() > 128 || ids.contains(filter.id))
            fail(uiText("Filter IDs must be unique and nonempty."));
        ids.insert(filter.id);
        if (filter.name.trimmed().isEmpty() || filter.name.size() > 256)
            fail(uiText("Filter name must contain 1..256 characters."));
        QString error;
        if (!LogFilter::compile(filter.expression, error))
            fail(uiText("Filter %1: %2").arg(filter.name, error));
    }
}

QList<SavedLogFilter> loadLogFilterConfig(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        fail(file.errorString());
    const auto bytes = file.read(maximumConfigBytes + 1);
    if (file.error() != QFileDevice::NoError)
        fail(file.errorString());
    if (bytes.size() > maximumConfigBytes)
        fail(uiText("Filter configuration exceeds 1 MiB."));
    QXmlStreamReader xml(bytes);
    while (!xml.atEnd()) {
        const auto token = xml.readNext();
        if (token == QXmlStreamReader::DTD)
            invalidConfig();
        if (token == QXmlStreamReader::StartElement)
            break;
    }
    if (xml.name() != QLatin1String("NativeDNSLogFilters") ||
        xml.attributes().value("schemaVersion") != QLatin1String("1"))
        invalidConfig();
    QList<SavedLogFilter> filters;
    bool foundFilters = false;
    while (xml.readNextStartElement()) {
        if (foundFilters || xml.name() != QLatin1String("Filters"))
            invalidConfig();
        foundFilters = true;
        while (xml.readNextStartElement()) {
            if (xml.name() != QLatin1String("Filter") || filters.size() >= 256)
                invalidConfig();
            SavedLogFilter filter;
            filter.id = xml.attributes().value("id").toString();
            if (filter.id.isEmpty())
                filter.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
            bool foundName = false, foundExpression = false;
            while (xml.readNextStartElement()) {
                if (xml.name() == QLatin1String("Name") && !foundName) {
                    foundName = true;
                    filter.name = xml.readElementText().trimmed();
                } else if (xml.name() == QLatin1String("Expression") && !foundExpression) {
                    foundExpression = true;
                    filter.expression = xml.readElementText().trimmed();
                } else
                    invalidConfig();
            }
            if (!foundName || !foundExpression)
                invalidConfig();
            filters.push_back(std::move(filter));
        }
    }
    while (!xml.atEnd())
        xml.readNext();
    if (!foundFilters || xml.hasError())
        fail(uiText("Invalid log filter configuration.") + ' ' + xml.errorString());
    validateLogFilterConfig(filters);
    return filters;
}

void saveLogFilterConfig(const QString& path, const QList<SavedLogFilter>& filters) {
    validateLogFilterConfig(filters);
    QByteArray bytes;
    QXmlStreamWriter xml(&bytes);
    xml.setAutoFormatting(true);
    xml.writeStartDocument();
    xml.writeStartElement("NativeDNSLogFilters");
    xml.writeAttribute("schemaVersion", "1");
    xml.writeStartElement("Filters");
    for (const auto& filter : filters) {
        xml.writeStartElement("Filter");
        xml.writeAttribute("id", filter.id);
        xml.writeTextElement("Name", filter.name);
        xml.writeTextElement("Expression", filter.expression);
        xml.writeEndElement();
    }
    xml.writeEndElement();
    xml.writeEndElement();
    xml.writeEndDocument();
    if (xml.hasError())
        invalidConfig();
    if (bytes.size() > maximumConfigBytes)
        fail(uiText("Filter configuration exceeds 1 MiB."));
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit())
        fail(file.errorString());
}
