#include "log_filter_ui.hpp"
#include "action_icons.hpp"
#include "bounded_table_header.hpp"
#include "ui_preferences.hpp"
#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QHeaderView>
#include <QFileDialog>
#include <QSignalBlocker>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QShortcut>
#include <QTableWidget>
#include <QTextBrowser>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QTextTable>
#include <QToolButton>
#include <QUuid>
#include <QVBoxLayout>
#include <algorithm>

namespace {
constexpr size_t maximumLogRecords = 2000;
QString filterPlaceholder() {
    return uiText(
        "addr=\"...\"  dns_type=\"A\"  rule=\"...\"  err=\"*\"  action=\"process\"  (&& / ||)");
}
void loadSaved(QSettings& settings, QList<SavedLogFilter>& filters) {
    const int count = settings.beginReadArray("ui/logFilters");
    for (int row = 0; row < std::min(count, 256); ++row) {
        settings.setArrayIndex(row);
        auto id = settings.value("id").toString();
        if (id.isEmpty() || std::any_of(filters.begin(), filters.end(), [&id](const auto& value) {
                return value.id == id;
            }))
            id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        filters.push_back(
            {id, settings.value("name").toString(), settings.value("expression").toString()});
    }
    settings.endArray();
}
} // namespace

void showLogFilterHelp(QWidget* parent) {
    QDialog dialog(parent);
    dialog.setWindowTitle(uiText("Log filter help"));
    dialog.resize(800, 720);
    auto* text = new QTextBrowser(&dialog);
    text->setOpenExternalLinks(false);
    const bool russian = uiLanguage() == UiLanguage::russian;
    const bool dark = text->palette().color(QPalette::Base).lightness() < 128;
    const auto foreground = text->palette().color(QPalette::Text).name();
    const auto background = text->palette().color(QPalette::Base).name();
    const auto border = dark ? QStringLiteral("#60646b") : QStringLiteral("#a6adb7");
    const auto highlight = dark ? QStringLiteral("#343b46") : QStringLiteral("#e8eef6");
    const auto heading = [&](const QString& title) {
        return "<h3>" + title.toHtmlEscaped() + "</h3>";
    };
    const auto table = [&](const QString& first, const QString& second) {
        return QString(
                   "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"6\" "
                   "style=\"border-collapse:collapse; border-color:%1;\">"
                   "<tr bgcolor=\"%2\"><th align=\"left\">%3</th><th align=\"left\">%4</th></tr>")
            .arg(border, highlight, first.toHtmlEscaped(), second.toHtmlEscaped());
    };
    const auto row = [&](const QString& value, const QString& meaning, bool emphasize = false) {
        return QString("<tr><td width=\"40%\" bgcolor=\"%1\"><code>%2</code></td><td>%3</td></tr>")
            .arg(
                emphasize ? highlight : background, value.toHtmlEscaped(), meaning.toHtmlEscaped());
    };
    QString html = QString("<html><body style=\"color:%1; background-color:%2;\">")
                       .arg(foreground, background);
    html += heading(russian ? "Общее" : "General");
    html += russian ? "<p>Введите условие и нажмите стрелку справа или Enter.<br>"
                      "Пустая строка показывает все записи.</p>"
                    : "<p>Enter a condition and click the arrow or press Enter.<br>"
                      "An empty expression shows all records.</p>";
    html += heading(russian ? "Типы фильтров" : "Filter types");
    html += table(russian ? "Поле" : "Field", russian ? "Значение" : "Meaning");
    html += row("addr=\"example.com\"",
                russian ? "Домен запроса. * — любое число символов, ? — один символ."
                        : "Requested domain. * matches any number of characters; ? matches one.");
    html += row(
        "dns_type=\"AAAA\"",
        russian ? "Тип записи: A, AAAA, HTTPS, TXT, MX, PTR и другие; также номер типа, например 1."
                : "Record type: A, AAAA, HTTPS, TXT, MX, PTR, etc.; or its number, such as 1.");
    html += row("rule=\"Default\"",
                russian ? "Название правила, обработавшего запрос. Допускает * и ?."
                        : "Name of the rule that handled the query. Supports * and ?.");
    html += row("action=\"block\"",
                russian ? "Действие правила: process, bypass или block."
                        : "Rule action: process, bypass or block.");
    html += row("err=\"*\"", russian ? "Все ошибки." : "All errors.");
    html += row("err=\"TIMEOUT\"",
                russian ? "Ошибки, содержащие указанный код или текст."
                        : "Errors containing the specified code or text.");
    html += "</table>";
    html += heading(russian ? "Операторы" : "Operators");
    html += table(russian ? "Оператор" : "Operator", russian ? "Значение" : "Meaning");
    html += row("( ... )",
                russian ? "Группировка: условия в скобках проверяются первыми."
                        : "Grouping: conditions in parentheses are evaluated first.");
    html += row("!",
                russian ? "НЕ — исключает записи, соответствующие условию."
                        : "NOT — excludes records that match the condition.");
    html +=
        row("&&",
            russian ? "И — должны выполняться оба условия." : "AND — both conditions must match.");
    html += row(
        "||", russian ? "ИЛИ — достаточно любого из условий." : "OR — either condition may match.");
    html += "</table>";
    html += heading(russian ? "Примеры" : "Examples");
    html += table(russian ? "Фильтр" : "Filter", russian ? "Пояснение" : "Explanation");
    html += row("addr=\"*.example.com\" && dns_type=\"A\"",
                russian ? "Запросы типа A к поддоменам example.com."
                        : "A queries for subdomains of example.com.",
                true);
    html += row("(dns_type=\"A\" || dns_type=\"AAAA\") && rule=\"Default\"",
                russian ? "Запросы типа A или AAAA, обработанные правилом Default."
                        : "A or AAAA queries handled by the Default rule.",
                true);
    html += row("action=\"process\" && err=\"*\"",
                russian ? "Ошибки запросов с действием process."
                        : "Errors from queries with the process action.",
                true);
    html += row("action=\"block\" && !err=\"*\"",
                russian ? "Записи с действием block без ошибок."
                        : "Records with the block action and no errors.",
                true);
    html += "</table></body></html>";
    text->setHtml(html);
    for (auto* frame : text->document()->rootFrame()->childFrames()) {
        auto* grid = qobject_cast<QTextTable*>(frame);
        if (!grid)
            continue;
        auto format = grid->format();
        format.setBorder(1);
        format.setBorderStyle(QTextFrameFormat::BorderStyle_Solid);
        format.setBorderBrush(QColor(border));
        format.setBorderCollapse(true);
        format.setCellPadding(4);
        grid->setFormat(format);
        for (int rowIndex = 0; rowIndex < grid->rows(); ++rowIndex)
            for (int column = 0; column < grid->columns(); ++column) {
                auto cell = grid->cellAt(rowIndex, column);
                auto cellFormat = cell.format().toTableCellFormat();
                cellFormat.setBorder(1);
                cellFormat.setBorderStyle(QTextFrameFormat::BorderStyle_Solid);
                cellFormat.setBorderBrush(QColor(border));
                cell.setFormat(cellFormat);
            }
    }
    auto* close = new QPushButton(uiText("Close"), &dialog);
    QObject::connect(close, &QPushButton::clicked, &dialog, &QDialog::accept);
    auto* bottom = new QHBoxLayout;
    bottom->addStretch();
    bottom->addWidget(close);
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(text);
    layout->addLayout(bottom);
    dialog.exec();
}

SavedFiltersDialog::SavedFiltersDialog(QWidget* parent, const QList<SavedLogFilter>& filters)
    : QDialog(parent), table_(new QTableWidget(this)), filters_(filters) {
    setWindowTitle(uiText("Manage log filters"));
    resize(880, 480);
    table_->setObjectName("savedFiltersTable");
    table_->setColumnCount(2);
    table_->setHorizontalHeaderLabels({uiText("Filter name"), uiText("Filter expression")});
    new BoundedTableHeader(table_, {150, 250}, 0, 1, 2);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table_->setWordWrap(false);
    table_->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table_->verticalHeader()->setDefaultSectionSize(table_->fontMetrics().height() + 8);
    for (const auto& filter : filters)
        appendFilter(filter);
    connect(table_, &QTableWidget::itemChanged, this, [this] { refreshChangedRows(); });
    auto* add = new QPushButton(uiText("Add"), this);
    auto* clone = new QPushButton(uiText("Clone"), this);
    auto* remove = new QPushButton(uiText("Remove"), this);
    auto* importFilters = new QPushButton(uiText("Import"), this);
    auto* exportFilters = new QPushButton(uiText("Export"), this);
    importFilters->setObjectName("importLogFilters");
    exportFilters->setObjectName("exportLogFilters");
    auto* ok = new QPushButton(uiText("OK"), this);
    auto* close = new QPushButton(uiText("Close"), this);
    auto* help = new QPushButton(uiText("Help"), this);
    auto* side = new QVBoxLayout;
    side->addWidget(add);
    side->addWidget(clone);
    side->addWidget(remove);
    side->addSpacing(remove->sizeHint().height());
    side->addWidget(importFilters);
    side->addWidget(exportFilters);
    side->addStretch();
    auto* content = new QHBoxLayout;
    content->addWidget(table_, 1);
    content->addLayout(side);
    auto* bottom = new QHBoxLayout;
    bottom->addWidget(ok);
    bottom->addStretch();
    bottom->addWidget(help);
    bottom->addWidget(close);
    auto* root = new QVBoxLayout(this);
    root->addLayout(content, 1);
    root->addLayout(bottom);
    const auto updateButtons = [this, clone, remove] {
        const auto rows = table_->selectionModel()->selectedRows();
        clone->setEnabled(rows.size() == 1);
        remove->setEnabled(!rows.isEmpty());
    };
    connect(table_, &QTableWidget::itemSelectionChanged, this, updateButtons);
    updateButtons();
    connect(add, &QPushButton::clicked, this, [this] {
        if (table_->rowCount() >= 256) {
            QMessageBox::information(this, "NativeDNS", uiText("Maximum 256 saved filters."));
            return;
        }
        appendFilter(
            {QUuid::createUuid().toString(QUuid::WithoutBraces), uiText("New filter"), {}});
        table_->editItem(table_->item(table_->currentRow(), 0));
    });
    connect(clone, &QPushButton::clicked, this, [this] {
        const auto rows = table_->selectionModel()->selectedRows();
        if (rows.size() != 1 || table_->rowCount() >= 256)
            return;
        const int row = rows.front().row();
        appendFilter({QUuid::createUuid().toString(QUuid::WithoutBraces),
                      table_->item(row, 0)->text() + " (copy)",
                      table_->item(row, 1)->text()});
    });
    connect(remove, &QPushButton::clicked, this, [this] {
        auto rows = table_->selectionModel()->selectedRows();
        std::sort(rows.begin(), rows.end(), [](const auto& left, const auto& right) {
            return left.row() > right.row();
        });
        for (const auto& row : rows)
            table_->removeRow(row.row());
    });
    connect(importFilters, &QPushButton::clicked, this, [this] {
        const auto path = QFileDialog::getOpenFileName(
            this, uiText("Import log filters"), {}, uiText("Log filter configuration (*.xml)"));
        if (path.isEmpty())
            return;
        try {
            const auto imported = loadLogFilterConfig(path);
            table_->setRowCount(0);
            for (const auto& filter : imported)
                appendFilter(filter);
            refreshChangedRows();
        } catch (const std::exception& error) {
            QMessageBox::warning(this, uiText("Import"), QString::fromUtf8(error.what()));
        }
    });
    connect(exportFilters, &QPushButton::clicked, this, [this] {
        try {
            const auto working = workingFilters();
            const auto path =
                QFileDialog::getSaveFileName(this,
                                             uiText("Export log filters"),
                                             "NativeDNS-filters.xml",
                                             uiText("Log filter configuration (*.xml)"));
            if (!path.isEmpty())
                saveLogFilterConfig(path, working);
        } catch (const std::exception& error) {
            QMessageBox::warning(this, uiText("Export"), QString::fromUtf8(error.what()));
        }
    });
    connect(ok, &QPushButton::clicked, this, [this] {
        try {
            filters_ = workingFilters();
            accept();
        } catch (const std::exception& error) {
            QMessageBox::warning(this, uiText("Invalid filter"), QString::fromUtf8(error.what()));
        }
    });
    connect(close, &QPushButton::clicked, this, &QDialog::reject);
    connect(help, &QPushButton::clicked, this, [this] { showLogFilterHelp(this); });
}

void SavedFiltersDialog::appendFilter(const SavedLogFilter& filter) {
    const int row = table_->rowCount();
    table_->insertRow(row);
    auto* name = new QTableWidgetItem(filter.name);
    name->setData(Qt::UserRole, filter.id);
    table_->setItem(row, 0, name);
    table_->setItem(row, 1, new QTableWidgetItem(filter.expression));
    table_->selectRow(row);
}
QList<SavedLogFilter> SavedFiltersDialog::workingFilters() const {
    QList<SavedLogFilter> working;
    for (int row = 0; row < table_->rowCount(); ++row)
        working.push_back({table_->item(row, 0)->data(Qt::UserRole).toString(),
                           table_->item(row, 0)->text().trimmed(),
                           table_->item(row, 1)->text().trimmed()});
    validateLogFilterConfig(working);
    return working;
}
void SavedFiltersDialog::refreshChangedRows() {
    const QSignalBlocker blocker(table_);
    for (int row = 0; row < table_->rowCount(); ++row) {
        auto* name = table_->item(row, 0);
        auto* expression = table_->item(row, 1);
        if (!name || !expression)
            continue;
        const auto id = name->data(Qt::UserRole).toString();
        const auto original = std::find_if(filters_.begin(),
                                           filters_.end(),
                                           [&id](const auto& filter) { return filter.id == id; });
        const bool changed = original == filters_.end() || original->name != name->text() ||
                             original->expression != expression->text();
        for (auto* item : {name, expression}) {
            auto font = item->font();
            if (font.bold() != changed) {
                font.setBold(changed);
                item->setFont(font);
            }
        }
    }
}

LogPanel::LogPanel(QWidget* parent, QSettings* settings)
    : QWidget(parent), ownedSettings_(settings ? nullptr : std::make_unique<QSettings>()),
      settings_(settings ? settings : ownedSettings_.get()), input_(new QLineEdit(this)),
      bookmark_(new QToolButton(this)), apply_(new QToolButton(this)), menu_(new QMenu(this)),
      error_(new QLabel(this)), count_(new QLabel(this)), view_(new LogDisplay(this)) {
    input_->setObjectName("logFilterInput");
    input_->setMaxLength(4096);
    input_->setClearButtonEnabled(true);
    bookmark_->setObjectName("logFilterBookmark");
    bookmark_->setPopupMode(QToolButton::InstantPopup);
    bookmark_->setMenu(menu_);
    apply_->setObjectName("logFilterApply");
    apply_->setArrowType(Qt::RightArrow);
    error_->setObjectName("logFilterError");
    error_->setTextFormat(Qt::PlainText);
    error_->setWordWrap(true);
    error_->hide();
    view_->setView(logViewFromKey(settings_->value("ui/logView", "compact").toString()));
    for (const auto& action : settings_->value("ui/logActions").toStringList())
        if (action == "process" || action == "block" || action == "bypass")
            shownActions_.insert(action);
    commandsView_ = settings_->value("ui/logCommands", "with").toString() == "only"
                        ? LogCommandsView::only
                        : LogCommandsView::with_records;
    auto* bar = new QHBoxLayout;
    bar->setSpacing(3);
    bar->addWidget(bookmark_);
    bar->addWidget(input_, 1);
    bar->addWidget(apply_);
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(3);
    root->addLayout(bar);
    root->addWidget(error_);
    root->addWidget(view_, 1);
    count_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    root->addWidget(count_);
    loadSaved(*settings_, saved_);
    connect(input_, &QLineEdit::textChanged, this, [this] { validateDraft(); });
    connect(input_, &QLineEdit::textEdited, this, [this] { selectedId_.clear(); });
    connect(input_, &QLineEdit::returnPressed, this, [this] { applyFilter(); });
    connect(apply_, &QToolButton::clicked, this, [this] { applyFilter(); });
    connect(menu_, &QMenu::aboutToShow, this, [this] { populateMenu(); });
    auto* focus = new QShortcut(QKeySequence("Ctrl+/"), this);
    connect(focus, &QShortcut::activated, this, [this] {
        input_->setFocus();
        input_->selectAll();
    });
    retranslateUi();
}
void LogPanel::retranslateUi() {
    input_->setPlaceholderText(filterPlaceholder());
    input_->setToolTip(uiText(
        "Use &&, ||, ! and parentheses. Empty input shows all logs. Ctrl+/ focuses this field."));
    bookmark_->setToolTip(uiText("Saved log filters"));
    apply_->setToolTip(uiText("Apply filter (Enter)"));
    bookmark_->setIcon(
        makeActionIcon(ActionIcon::bookmark, palette().color(QPalette::Window).lightness() < 128));
    validateDraft();
    updateCount();
    view_->retranslateUi();
}
void LogPanel::changeEvent(QEvent* event) {
    QWidget::changeEvent(event);
    if (event->type() == QEvent::PaletteChange && input_) {
        retranslateUi();
        rebuild();
    }
}
void LogPanel::validateDraft() {
    QString error;
    const bool valid = LogFilter::compile(input_->text(), error).has_value();
    const bool dark = palette().color(QPalette::Window).lightness() < 128;
    input_->setStyleSheet(
        input_->text().trimmed().isEmpty() ? QString{}
        : valid ? (dark ? "QLineEdit { background-color: #183b29; color: #f0f0f0; }"
                        : "QLineEdit { background-color: #e2f3e7; color: #202020; }")
                : (dark ? "QLineEdit { background-color: #552629; color: #ffffff; }"
                        : "QLineEdit { background-color: #ffe3e3; color: #202020; }"));
    error_->setText(error);
    error_->setStyleSheet(dark ? "color: #ff6969;" : "color: #be0000;");
    error_->setVisible(!valid);
    apply_->setEnabled(valid);
}
bool LogPanel::applyFilter() {
    QString error;
    auto filter = LogFilter::compile(input_->text(), error);
    if (!filter) {
        validateDraft();
        return false;
    }
    filter_ = std::move(*filter);
    appliedExpression_ = input_->text().trimmed();
    const auto selected = std::find_if(saved_.begin(), saved_.end(), [this](const auto& saved) {
        return saved.id == selectedId_ && saved.expression == appliedExpression_;
    });
    if (selected == saved_.end()) {
        selectedId_.clear();
        for (const auto& saved : saved_)
            if (saved.expression == appliedExpression_) {
                selectedId_ = saved.id;
                break;
            }
    }
    rebuild();
    return true;
}
void LogPanel::renderRecord(const LogRecord& record) {
    view_->appendRecord(record);
    ++visible_;
}
bool LogPanel::matches(const LogRecord& record) const {
    if (!filter_.matches(record))
        return false;
    if (isTechnicalLogRecord(record))
        return true;
    return commandsView_ == LogCommandsView::with_records &&
           (shownActions_.isEmpty() || shownActions_.contains(record.action));
}
void LogPanel::appendRecords(const QList<LogRecord>& records) {
    if (records.isEmpty())
        return;
    auto* scroll = view_->verticalScrollBar();
    const int position = scroll->value();
    const bool follow = position == scroll->maximum();
    view_->setUpdatesEnabled(false);
    for (auto record : records) {
        record.message.replace('\n', ' ').replace('\r', ' ');
        if (!record.timestamp.isValid())
            record.timestamp = QDateTime::currentDateTime();
        if (records_.size() == maximumLogRecords) {
            if (matches(records_.front())) {
                view_->removeFirstRecord();
                --visible_;
            }
            records_.pop_front();
        }
        records_.push_back(std::move(record));
        if (matches(records_.back()))
            renderRecord(records_.back());
    }
    view_->finishUpdate(follow, position);
    view_->setUpdatesEnabled(true);
    updateCount();
}
void addLogViewActions(QMenu* menu, LogPanel& panel) {
    auto* group = new QActionGroup(menu);
    group->setExclusive(true);
    for (const auto view : {LogView::compact, LogView::details, LogView::table}) {
        const char* key = logViewTextKey(view);
        auto* action = menu->addAction(uiText(key));
        action->setProperty("uiTextKey", QString::fromUtf8(key));
        action->setCheckable(true);
        action->setData(static_cast<int>(view));
        group->addAction(action);
        action->setChecked(panel.logView() == view);
        QObject::connect(action, &QAction::triggered, &panel, [&panel, view, group] {
            panel.setLogView(view);
            for (auto* candidate : group->actions())
                candidate->setChecked(candidate->data().toInt() ==
                                      static_cast<int>(panel.logView()));
        });
    }
}
void addLogActionFilterActions(QMenu* menu, LogPanel& panel) {
    auto* all = menu->addAction(uiText("All"));
    all->setProperty("uiTextKey", "All");
    all->setData("all");
    all->setCheckable(true);
    menu->addSeparator();
    for (const auto* key : {"Process", "Block", "Bypass"}) {
        auto* action = menu->addAction(uiText(key));
        action->setProperty("uiTextKey", QString::fromUtf8(key));
        action->setData(QString::fromUtf8(key).toLower());
        action->setCheckable(true);
    }
    const auto refresh = [menu, &panel] {
        for (auto* action : menu->actions())
            if (!action->isSeparator())
                action->setChecked(action->data().toString() == "all"
                                       ? panel.shownActions().isEmpty()
                                       : panel.shownActions().contains(action->data().toString()));
    };
    refresh();
    QObject::connect(menu, &QMenu::aboutToShow, &panel, refresh);
    for (auto* action : menu->actions()) {
        if (action->isSeparator())
            continue;
        QObject::connect(
            action, &QAction::triggered, &panel, [&panel, action, refresh](bool checked) {
                auto selected = panel.shownActions();
                const auto value = action->data().toString();
                if (value == "all")
                    selected.clear();
                else if (checked)
                    selected.insert(value);
                else
                    selected.remove(value);
                panel.setShownActions(selected);
                refresh();
            });
    }
}
void addLogCommandFilterActions(QMenu* menu, LogPanel& panel, QMenu* actionMenu) {
    auto* group = new QActionGroup(menu);
    group->setExclusive(true);
    for (const auto* key : {"Only", "With"}) {
        auto* action = menu->addAction(uiText(key));
        action->setProperty("uiTextKey", QString::fromUtf8(key));
        action->setData(QString::fromUtf8(key) == "Only"
                            ? static_cast<int>(LogCommandsView::only)
                            : static_cast<int>(LogCommandsView::with_records));
        action->setCheckable(true);
        group->addAction(action);
    }
    const auto refresh = [group, &panel, actionMenu] {
        for (auto* action : group->actions())
            action->setChecked(action->data().toInt() == static_cast<int>(panel.commandsView()));
        if (actionMenu)
            actionMenu->menuAction()->setEnabled(panel.commandsView() ==
                                                 LogCommandsView::with_records);
    };
    refresh();
    QObject::connect(menu, &QMenu::aboutToShow, &panel, refresh);
    for (auto* action : group->actions())
        QObject::connect(action, &QAction::triggered, &panel, [&panel, action, refresh] {
            panel.setCommandsView(static_cast<LogCommandsView>(action->data().toInt()));
            refresh();
        });
}
bool LogPanel::setCommandsView(LogCommandsView view) {
    settings_->setValue("ui/logCommands", view == LogCommandsView::only ? "only" : "with");
    settings_->sync();
    if (settings_->status() != QSettings::NoError) {
        QMessageBox::warning(this, "NativeDNS", uiText("Cannot save log commands view."));
        return false;
    }
    commandsView_ = view;
    rebuild();
    return true;
}
bool LogPanel::setShownActions(const QSet<QString>& actions) {
    QStringList selected;
    for (const auto* action : {"process", "block", "bypass"})
        if (actions.contains(QString::fromLatin1(action)))
            selected << QString::fromLatin1(action);
    settings_->setValue("ui/logActions", selected);
    settings_->sync();
    if (settings_->status() != QSettings::NoError) {
        QMessageBox::warning(this, "NativeDNS", uiText("Cannot save log action filter."));
        return false;
    }
    shownActions_ = QSet<QString>(selected.begin(), selected.end());
    rebuild();
    return true;
}
bool LogPanel::setLogView(LogView view) {
    settings_->setValue("ui/logView", logViewKey(view));
    settings_->sync();
    if (settings_->status() != QSettings::NoError) {
        QMessageBox::warning(this, "NativeDNS", uiText("Cannot save log view."));
        return false;
    }
    view_->setView(view);
    return true;
}
void LogPanel::rebuild() {
    view_->setUpdatesEnabled(false);
    view_->clear();
    visible_ = 0;
    for (const auto& record : records_)
        if (matches(record))
            renderRecord(record);
    view_->finishUpdate(true);
    view_->setUpdatesEnabled(true);
    updateCount();
}
void LogPanel::clear() {
    records_.clear();
    view_->clear();
    visible_ = 0;
    updateCount();
}
void LogPanel::updateCount() {
    count_->setText(uiText("Shown: %1 of %2").arg(visible_).arg(records_.size()));
    count_->setToolTip(uiText("The buffer retains the latest 2000 received log records."));
}
bool LogPanel::persist(const QList<SavedLogFilter>& filters) {
    settings_->beginWriteArray("ui/logFilters", static_cast<int>(filters.size()));
    for (int row = 0; row < filters.size(); ++row) {
        settings_->setArrayIndex(row);
        settings_->setValue("id", filters[row].id);
        settings_->setValue("name", filters[row].name);
        settings_->setValue("expression", filters[row].expression);
    }
    settings_->endArray();
    settings_->sync();
    if (settings_->status() != QSettings::NoError) {
        QMessageBox::warning(this, "NativeDNS", uiText("Cannot save log filters."));
        return false;
    }
    saved_ = filters;
    return true;
}
void LogPanel::populateMenu() {
    menu_->clear();
    auto* save = menu_->addAction(uiText("Save this filter"));
    auto* remove = menu_->addAction(uiText("Delete this filter"));
    auto* manage = menu_->addAction(uiText("Manage filters"));
    QString error;
    save->setEnabled(saved_.size() < 256 && LogFilter::compile(input_->text(), error).has_value() &&
                     std::none_of(saved_.begin(), saved_.end(), [this](const auto& saved) {
                         return saved.expression == input_->text().trimmed();
                     }));
    remove->setEnabled(std::any_of(saved_.begin(), saved_.end(), [this](const auto& saved) {
        return saved.id == selectedId_;
    }));
    connect(save, &QAction::triggered, this, [this] { saveFilter(); });
    connect(remove, &QAction::triggered, this, [this] { deleteFilter(); });
    connect(manage, &QAction::triggered, this, [this] { manageFilters(); });
    menu_->addSeparator();
    for (const auto& saved : saved_) {
        auto* action = menu_->addAction(saved.name + ": " + saved.expression);
        action->setCheckable(true);
        action->setChecked(saved.id == selectedId_);
        connect(action, &QAction::triggered, this, [this, saved] {
            selectedId_ = saved.id;
            input_->setText(saved.expression);
            applyFilter();
        });
    }
}
void LogPanel::saveFilter() {
    QString error;
    const auto expression = input_->text().trimmed();
    if (!LogFilter::compile(expression, error) || saved_.size() >= 256)
        return;
    bool accepted = false;
    const auto name = QInputDialog::getText(this,
                                            uiText("Save this filter"),
                                            uiText("Filter name:"),
                                            QLineEdit::Normal,
                                            expression.isEmpty() ? uiText("All logs") : expression,
                                            &accepted)
                          .trimmed();
    if (!accepted || name.isEmpty())
        return;
    auto next = saved_;
    const auto id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    next.push_back({id, name, expression});
    if (persist(next))
        selectedId_ = id;
}
void LogPanel::deleteFilter() {
    auto next = saved_;
    next.erase(std::remove_if(next.begin(),
                              next.end(),
                              [this](const auto& saved) { return saved.id == selectedId_; }),
               next.end());
    if (persist(next))
        selectedId_.clear();
}
void LogPanel::manageFilters() {
    SavedFiltersDialog dialog(this, saved_);
    if (dialog.exec() != QDialog::Accepted || !persist(dialog.filters()))
        return;
    const auto selected = std::find_if(saved_.begin(), saved_.end(), [this](const auto& saved) {
        return saved.id == selectedId_;
    });
    if (selected == saved_.end())
        selectedId_.clear();
    else if (input_->text().trimmed() == appliedExpression_) {
        input_->setText(selected->expression);
        applyFilter();
    }
}
