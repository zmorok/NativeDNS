#pragma once
#include "log_filter.hpp"
#include <QWidget>
#include <deque>

class QPlainTextEdit;
class QStackedWidget;
class QTableWidget;
class QTreeWidget;
class QToolButton;
class QScrollBar;

enum class LogView { compact, details, table };
QString logViewKey(LogView view);
LogView logViewFromKey(const QString& key);
const char* logViewTextKey(LogView view);

// Presentation only: the original records remain available to filters and the inspector.
class LogDisplay final : public QWidget {
    Q_OBJECT
public:
    explicit LogDisplay(QWidget* parent = nullptr);
    void setView(LogView view);
    LogView view() const {
        return mode_;
    }
    void appendRecord(const LogRecord& record);
    void removeFirstRecord();
    void clear();
    void retranslateUi();
    QScrollBar* verticalScrollBar() const;
    void finishUpdate(bool followBottom, int previousPosition = 0);
    bool selectedRecordVisible() const {
        return selectedRecordVisible_;
    }
    void setSelectedRecordVisible(bool visible);
    int recordCount() const {
        return static_cast<int>(records_.size());
    }

protected:
    void changeEvent(QEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void renderRecord(const LogRecord& record);
    void rebuild();
    void inspect(const LogRecord& record);
    QStackedWidget* stack_;
    QPlainTextEdit* text_;
    QTableWidget* table_;
    QTreeWidget* tree_;
    QPlainTextEdit* inspector_;
    QToolButton* detailsButton_;
    LogView mode_ = LogView::compact;
    std::deque<LogRecord> records_;
    std::optional<LogRecord> inspected_;
    bool rendering_ = false;
    bool selectedRecordVisible_ = true;
    bool automaticInspection_ = true;
};
