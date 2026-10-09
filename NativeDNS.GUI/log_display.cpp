#include "log_display.hpp"
#include "ui_preferences.hpp"
#include <QHeaderView>
#include <QAbstractTextDocumentLayout>
#include <QEvent>
#include <QPlainTextEdit>
#include <QRegularExpression>
#include <QScrollBar>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTextBlock>
#include <QTextCursor>
#include <QToolButton>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <algorithm>

namespace {
struct TextRecord final : QTextBlockUserData {
    explicit TextRecord(const LogRecord& value) : record(value) {
    }
    LogRecord record;
};
QString capture(const QString& message, const QRegularExpression& pattern) {
    return pattern.match(message).captured(1);
}
struct Presentation {
    QString domain, action, server, duration, failure, briefFailure, summary;
};
Presentation present(const LogRecord& record) {
    static const QRegularExpression serverPattern("server=(.*?)[, ]+rule=");
    static const QRegularExpression transportPattern(" \\(DNS over [^)]+\\)$");
    static const QRegularExpression repeatedTransportPattern(" (\\([^)]+\\))(?: \\1)+$");
    static const QRegularExpression durationPattern("(?:^|, )time=([0-9.]+) ms");
    static const QRegularExpression errorPattern("(?:^|, )error=(.*)$");
    Presentation p;
    p.domain = record.address;
    if (!record.dnsType.isEmpty())
        p.domain += " [" + record.dnsType + ']';
    if (record.action == "process")
        p.action = uiText("Process");
    else if (record.action == "bypass")
        p.action = uiText("Bypass");
    else if (record.action == "block")
        p.action = uiText("Block");
    p.server = capture(record.message, serverPattern);
    p.server.remove(transportPattern);
    p.server.replace(repeatedTransportPattern, " \\1");
    p.duration = capture(record.message, durationPattern);
    p.failure = capture(record.message, errorPattern);
    if (record.error && p.failure.isEmpty())
        p.failure = record.message;
    p.briefFailure = p.failure;
    const auto timeout = p.failure.lastIndexOf("TIMEOUT:");
    if (timeout >= 0)
        p.briefFailure = p.failure.mid(timeout);
    if (record.code == "NETWORK_CHANGED") {
        p.summary = uiText("Network interfaces updated");
    } else if (record.code == "CORE_STARTED") {
        p.summary = uiText("CoreHost is running");
    } else if (p.server.isEmpty()) {
        p.summary = record.message;
    } else {
        QStringList parts{p.domain, p.action, p.server};
        if (!record.rule.isEmpty())
            parts << uiText("Rule: %1").arg(record.rule);
        if (!p.duration.isEmpty())
            parts << p.duration + " ms";
        if (record.message.contains("cache hit", Qt::CaseInsensitive))
            parts << uiText("Cache");
        parts.removeAll(QString{});
        p.summary = parts.join("  ·  ");
    }
    return p;
}
QString detailsText(const LogRecord& record, const Presentation& p) {
    QStringList lines{uiText("Time") + ": " + record.timestamp.toString("dd.MM.yyyy HH:mm:ss.zzz"),
                      uiText("Event") + ": " + record.code};
    if (!p.domain.isEmpty())
        lines << uiText("Domain / type") + ": " + p.domain;
    if (!p.action.isEmpty())
        lines << uiText("Action") + ": " + p.action;
    if (!p.server.isEmpty())
        lines << uiText("DNS server") + ": " + p.server;
    if (!record.rule.isEmpty())
        lines << uiText("Rule") + ": " + record.rule;
    if (!p.duration.isEmpty())
        lines << uiText("Time, ms") + ": " + p.duration;
    if (!p.failure.isEmpty())
        lines << uiText("Error") + ": " + p.failure;
    lines << QString{} << uiText("Original record") + ":" << record.message;
    return lines.join('\n');
}
} // namespace

QString logViewKey(LogView view) {
    switch (view) {
        case LogView::table:
            return "table";
        case LogView::details:
            return "details";
        default:
            return "compact";
    }
}
LogView logViewFromKey(const QString& key) {
    if (key == "table")
        return LogView::table;
    if (key == "details")
        return LogView::details;
    return LogView::compact;
}
const char* logViewTextKey(LogView view) {
    switch (view) {
        case LogView::table:
            return "Table";
        case LogView::details:
            return "Line with details";
        default:
            return "Short line";
    }
}

LogDisplay::LogDisplay(QWidget* parent)
    : QWidget(parent), stack_(new QStackedWidget(this)), text_(new QPlainTextEdit(this)),
      table_(new QTableWidget(this)), tree_(new QTreeWidget(this)),
      inspector_(new QPlainTextEdit(this)), detailsButton_(new QToolButton(this)) {
    text_->setObjectName("logDisplay");
    text_->setReadOnly(true);
    text_->setUndoRedoEnabled(false);
    text_->setLineWrapMode(QPlainTextEdit::NoWrap);
    table_->setObjectName("logTable");
    table_->setColumnCount(7);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->hide();
    auto* header = table_->horizontalHeader();
    header->setSectionResizeMode(QHeaderView::Interactive);
    header->setStretchLastSection(true);
    table_->setColumnWidth(0, 110);
    table_->setColumnWidth(1, 185);
    table_->setColumnWidth(2, 85);
    table_->setColumnWidth(3, 180);
    table_->setColumnWidth(4, 120);
    table_->setColumnWidth(5, 75);
    tree_->setObjectName("logDetailsTree");
    tree_->setHeaderHidden(true);
    tree_->setColumnCount(1);
    tree_->setSelectionMode(QAbstractItemView::SingleSelection);
    tree_->setUniformRowHeights(false);
    tree_->setWordWrap(true);
    tree_->header()->setSectionResizeMode(QHeaderView::Stretch);
    inspector_->setObjectName("logRecordDetails");
    inspector_->setReadOnly(true);
    inspector_->setUndoRedoEnabled(false);
    inspector_->setMaximumHeight(160);
    inspector_->hide();
    detailsButton_->setObjectName("logDetailsToggle");
    detailsButton_->setCheckable(true);
    detailsButton_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    detailsButton_->setArrowType(Qt::RightArrow);
    connect(detailsButton_, &QToolButton::toggled, this, [this](bool checked) {
        const auto* scroll = verticalScrollBar();
        const int previousPosition = scroll->value();
        const bool followBottom = previousPosition == scroll->maximum();
        const bool paintingEnabled = updatesEnabled();
        setUpdatesEnabled(false);
        inspector_->setVisible(checked);
        detailsButton_->setArrowType(checked ? Qt::DownArrow : Qt::RightArrow);
        // Restore the position against the resized viewport before it is painted.
        layout()->activate();
        finishUpdate(followBottom, previousPosition);
        setUpdatesEnabled(paintingEnabled);
    });
    stack_->addWidget(text_);
    stack_->addWidget(table_);
    stack_->addWidget(tree_);
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(3);
    layout->addWidget(stack_, 1);
    layout->addWidget(detailsButton_);
    layout->addWidget(inspector_);
    connect(text_, &QPlainTextEdit::cursorPositionChanged, this, [this] {
        if (!rendering_)
            if (const auto* data =
                    dynamic_cast<TextRecord*>(text_->textCursor().block().userData()))
                inspect(data->record);
    });
    connect(table_, &QTableWidget::currentCellChanged, this, [this](int row) {
        if (!rendering_ && row >= 0 && row < static_cast<int>(records_.size()))
            inspect(records_[row]);
    });
    connect(tree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item) {
        if (!rendering_ && item) {
            if (item->parent())
                item = item->parent();
            const int row = tree_->indexOfTopLevelItem(item);
            if (row >= 0 && row < static_cast<int>(records_.size()))
                inspect(records_[row]);
        }
    });
    retranslateUi();
}
void LogDisplay::inspect(const LogRecord& record) {
    inspected_ = record;
    inspector_->setPlainText(detailsText(record, present(record)));
}
void LogDisplay::retranslateUi() {
    table_->setHorizontalHeaderLabels({uiText("Time"),
                                       uiText("Domain / type"),
                                       uiText("Action"),
                                       uiText("DNS server"),
                                       uiText("Rule"),
                                       uiText("Time, ms"),
                                       uiText("Error")});
    detailsButton_->setText(uiText("Selected record details"));
    detailsButton_->setToolTip(uiText("Select a record to read its complete original text."));
    rebuild();
}
void LogDisplay::changeEvent(QEvent* event) {
    QWidget::changeEvent(event);
    if (event->type() == QEvent::PaletteChange && stack_)
        rebuild();
}
QScrollBar* LogDisplay::verticalScrollBar() const {
    if (mode_ == LogView::table)
        return table_->verticalScrollBar();
    if (mode_ == LogView::details)
        return tree_->verticalScrollBar();
    return text_->verticalScrollBar();
}
void LogDisplay::finishUpdate(bool followBottom, int previousPosition) {
    // Item views defer geometry updates. Finish them before re-enabling painting,
    // so the new rows and their final scroll position appear in the same frame.
    if (mode_ == LogView::table) {
        table_->doItemsLayout();
        if (followBottom)
            table_->scrollToBottom();
    } else if (mode_ == LogView::details) {
        tree_->doItemsLayout();
        if (followBottom)
            tree_->scrollToBottom();
    } else {
        text_->document()->documentLayout()->blockBoundingRect(text_->document()->lastBlock());
        if (followBottom)
            text_->verticalScrollBar()->setValue(text_->verticalScrollBar()->maximum());
    }
    if (!followBottom) {
        auto* scroll = verticalScrollBar();
        scroll->setValue(std::min(previousPosition, scroll->maximum()));
    }
}
void LogDisplay::setView(LogView view) {
    if (mode_ == view)
        return;
    mode_ = view;
    stack_->setCurrentWidget(view == LogView::table     ? static_cast<QWidget*>(table_)
                             : view == LogView::details ? static_cast<QWidget*>(tree_)
                                                        : static_cast<QWidget*>(text_));
    rebuild();
}
void LogDisplay::clear() {
    rendering_ = true;
    records_.clear();
    text_->clear();
    table_->setRowCount(0);
    tree_->clear();
    inspector_->clear();
    inspected_.reset();
    rendering_ = false;
}
void LogDisplay::rebuild() {
    const auto saved = records_;
    setUpdatesEnabled(false);
    clear();
    for (const auto& record : saved)
        appendRecord(record);
    finishUpdate(true);
    setUpdatesEnabled(true);
}
void LogDisplay::appendRecord(const LogRecord& record) {
    records_.push_back(record);
    rendering_ = true;
    renderRecord(record);
    rendering_ = false;
    if (records_.size() == 1)
        inspect(record);
}
void LogDisplay::renderRecord(const LogRecord& record) {
    const auto p = present(record);
    const bool dark = palette().color(QPalette::Window).lightness() < 128;
    const QColor color = record.error ? (dark ? QColor(255, 105, 105) : QColor(190, 0, 0))
                                      : palette().color(QPalette::Text);
    const auto time = record.timestamp.toString("dd.MM HH:mm:ss");
    if (mode_ == LogView::table) {
        const int row = table_->rowCount();
        table_->insertRow(row);
        const QStringList cells{time,
                                p.domain.isEmpty() ? p.summary : p.domain,
                                p.action,
                                p.server,
                                record.rule,
                                p.duration,
                                p.briefFailure};
        const auto details = detailsText(record, p);
        for (int col = 0; col < cells.size(); ++col) {
            auto* item = new QTableWidgetItem(cells[col]);
            item->setForeground(color);
            item->setToolTip(details);
            if (col == 5)
                item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            table_->setItem(row, col, item);
        }
    } else if (mode_ == LogView::details) {
        auto summary = '[' + time + "] " + p.summary;
        if (record.error && p.failure != p.summary)
            summary += '\n' + p.briefFailure;
        const auto details = detailsText(record, p);
        auto* item = new QTreeWidgetItem(tree_, {summary});
        item->setForeground(0, color);
        item->setToolTip(0, details);
        auto* child = new QTreeWidgetItem(item, {details});
        child->setForeground(0, color);
        child->setToolTip(0, details);
    } else {
        QStringList lines;
        lines << '[' + time + "] " + p.summary;
        if (record.error && p.failure != p.summary)
            lines << "    " + p.briefFailure;
        QTextCursor cursor(text_->document());
        cursor.movePosition(QTextCursor::End);
        QTextCharFormat format;
        format.setForeground(color);
        for (const auto& line : lines) {
            cursor.insertText(line, format);
            cursor.block().setUserData(new TextRecord(record));
            cursor.insertText("\n", format);
        }
    }
}
void LogDisplay::removeFirstRecord() {
    if (records_.empty())
        return;
    rendering_ = true;
    const bool evictInspected = inspected_ && inspected_->sequence == records_.front().sequence &&
                                inspected_->timestamp == records_.front().timestamp &&
                                inspected_->message == records_.front().message;
    if (mode_ == LogView::table)
        table_->removeRow(0);
    else if (mode_ == LogView::details)
        delete tree_->takeTopLevelItem(0);
    else {
        // Each line of a displayed record carries its source; a trailing empty block does not.
        const auto p = present(records_.front());
        int lines = 1;
        if (records_.front().error && p.failure != p.summary)
            ++lines;
        QTextCursor cursor(text_->document());
        cursor.movePosition(QTextCursor::Start);
        for (int i = 0; i < lines; ++i)
            cursor.movePosition(QTextCursor::NextBlock, QTextCursor::KeepAnchor);
        cursor.removeSelectedText();
    }
    records_.pop_front();
    if (mode_ == LogView::compact && !records_.empty())
        text_->document()->firstBlock().setUserData(new TextRecord(records_.front()));
    if (evictInspected) {
        inspector_->clear();
        inspected_.reset();
    }
    rendering_ = false;
}
