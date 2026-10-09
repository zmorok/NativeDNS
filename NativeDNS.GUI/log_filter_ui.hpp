#pragma once
#include "log_filter.hpp"
#include "log_filter_config.hpp"
#include "log_display.hpp"
#include <QDialog>
#include <QSettings>
#include <QSet>
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

enum class LogCommandsView { with_records, only, without_commands };

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
    bool filtersShown() const {
        return filtersShown_;
    }
    bool setFiltersShown(bool shown);
    bool selectedRecordShown() const {
        return view_->selectedRecordVisible();
    }
    bool setSelectedRecordShown(bool shown);
    LogView logView() const {
        return view_->view();
    }
    bool setLogView(LogView view);
    const QSet<QString>& shownActions() const {
        return shownActions_;
    }
    bool setShownActions(const QSet<QString>& actions);
    LogCommandsView commandsView() const {
        return commandsView_;
    }
    bool setCommandsView(LogCommandsView view);
    const QList<SavedLogFilter>& savedFilters() const {
        return saved_;
    }

protected:
    void changeEvent(QEvent* event) override;

private:
    void validateDraft();
    bool matches(const LogRecord& record) const;
    bool persistVisibility(const char* key, bool shown);
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
    LogDisplay* view_;
    QWidget* filterControls_;
    QList<SavedLogFilter> saved_;
    QString selectedId_, appliedExpression_;
    LogFilter filter_;
    QSet<QString> shownActions_;
    LogCommandsView commandsView_ = LogCommandsView::with_records;
    std::deque<LogRecord> records_;
    int visible_ = 0;
    bool filtersShown_ = true;
};

void showLogFilterHelp(QWidget* parent);
void addLogViewActions(QMenu* menu, LogPanel& panel);
void addLogActionFilterActions(QMenu* menu, LogPanel& panel);
void addLogCommandFilterActions(QMenu* menu, LogPanel& panel, QMenu* actionMenu = nullptr);
void addLogVisibilityActions(QMenu* menu, LogPanel& panel);
