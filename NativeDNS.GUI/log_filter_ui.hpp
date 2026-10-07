#pragma once
#include "log_filter.hpp"
#include "log_filter_config.hpp"
#include <QDialog>
#include <QSettings>
#include <QWidget>
#include <deque>

class QLabel;
class QLineEdit;
class QMenu;
class QPlainTextEdit;
class QTableWidget;
class QToolButton;

class SavedFiltersDialog final : public QDialog {
public:
    SavedFiltersDialog(QWidget* parent, const QList<SavedLogFilter>& filters);
    const QList<SavedLogFilter>& filters() const {
        return filters_;
    }

private:
    void appendFilter(const SavedLogFilter& filter);
    QList<SavedLogFilter> workingFilters() const;
    void refreshChangedRows();
    QTableWidget* table_;
    QList<SavedLogFilter> filters_;
};

class LogPanel final : public QWidget {
public:
    explicit LogPanel(QWidget* parent = nullptr, QSettings* settings = nullptr);
    QLabel* countLabel() const {
        return count_;
    }
    void appendRecords(const QList<LogRecord>& records);
    void clear();
    void retranslateUi();
    bool applyFilter();
    const QList<SavedLogFilter>& savedFilters() const {
        return saved_;
    }

protected:
    void changeEvent(QEvent* event) override;

private:
    void validateDraft();
    void rebuild();
    void renderRecord(const LogRecord& record);
    void updateCount();
    void populateMenu();
    bool persist(const QList<SavedLogFilter>& filters);
    void saveFilter();
    void deleteFilter();
    void manageFilters();
    std::unique_ptr<QSettings> ownedSettings_;
    QSettings* settings_;
    QLineEdit* input_;
    QToolButton* bookmark_;
    QToolButton* apply_;
    QMenu* menu_;
    QLabel* error_;
    QLabel* count_;
    QPlainTextEdit* view_;
    QList<SavedLogFilter> saved_;
    QString selectedId_, appliedExpression_;
    LogFilter filter_;
    std::deque<LogRecord> records_;
    int visible_ = 0;
};

void showLogFilterHelp(QWidget* parent);
