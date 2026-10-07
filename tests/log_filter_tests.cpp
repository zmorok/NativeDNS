#include "../NativeDNS.GUI/log_filter_ui.hpp"
#include "../NativeDNS.GUI/ui_preferences.hpp"
#include <QAction>
#include <QDir>
#include <QFileDialog>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTextBrowser>
#include <QTextBlock>
#include <QTextCursor>
#include <QToolButton>
#include <QtTest>
#include <stdexcept>

namespace {
LogRecord record(QString message = "query", bool error = false) {
    LogRecord value;
    value.timestamp = QDateTime::fromMSecsSinceEpoch(1700000000000);
    value.message = message;
    value.address = "www.example.com";
    value.dnsType = "AAAA";
    value.rule = "AI - OpenAI";
    value.action = "process";
    value.error = error;
    value.code = error ? "DNS_TIMEOUT" : "DNS_ROUTE";
    return value;
}
QPushButton* button(QWidget& widget, const char* name) {
    for (auto* candidate : widget.findChildren<QPushButton*>())
        if (candidate->text() == uiText(name))
            return candidate;
    return nullptr;
}
void openMenu(QMenu* menu) {
    menu->popup(QPoint(0, 0));
    QCoreApplication::processEvents();
    menu->hide();
}
} // namespace

class LogFilterTests final : public QObject {
    Q_OBJECT
private slots:
    void predicates_data() {
        QTest::addColumn<QString>("expression");
        QTest::addColumn<bool>("matches");
        QTest::newRow("empty") << "" << true;
        QTest::newRow("exact address") << "addr=\"www.example.com\"" << true;
        QTest::newRow("address substring rejected") << "addr=\"example.com\"" << false;
        QTest::newRow("wildcard") << "addr=\"*.EXAMPLE.???\"" << true;
        QTest::newRow("record type") << "dns_type=\"aaaa\"" << true;
        QTest::newRow("numeric type") << "dns_type=\"28\"" << true;
        QTest::newRow("rule") << "rule=\"AI - OpenAI\"" << true;
        QTest::newRow("action") << "action=\"PROCESS\"" << true;
        QTest::newRow("other action") << "action=\"block\"" << false;
        QTest::newRow("precedence")
            << "action=\"block\" || dns_type=\"AAAA\" && !err=\"*\"" << true;
        QTest::newRow("grouping") << "(action=\"block\" || dns_type=\"AAAA\") && err=\"*\""
                                  << false;
        QTest::newRow("unquoted syntax inside value") << "rule=\"AI*||*\"" << false;
    }
    void predicates() {
        QFETCH(QString, expression);
        QFETCH(bool, matches);
        QString error;
        const auto filter = LogFilter::compile(expression, error);
        QVERIFY2(filter.has_value(), qPrintable(error));
        QCOMPARE(filter->matches(record()), matches);
    }
    void errorsAndEscaping() {
        QString error;
        auto event = record("connection timed out", true);
        for (const auto& expression : {"err=\"*\"",
                                       "err=\"\"",
                                       "err=\"timeout\"",
                                       "err=\"timed out\"",
                                       "err=\"tim*d out\""}) {
            auto filter = LogFilter::compile(expression, error);
            QVERIFY(filter);
            QVERIFY(filter->matches(event));
            event.error = false;
            QVERIFY(!filter->matches(event));
            event.error = true;
        }
        event.rule = "name \"quoted\" \\ tail, time=1 ms, error=bad";
        const auto filter = LogFilter::compile(
            "rule=\"name \\\"quoted\\\" \\\\ tail, time=1 ms, error=bad\"", error);
        QVERIFY2(filter.has_value(), qPrintable(error));
        QVERIFY(filter->matches(event));
        event.address.clear();
        QVERIFY(!LogFilter::compile("addr=\"*\"", error)->matches(event));
        event.action = "bypass";
        QVERIFY(LogFilter::compile("action=\"bypass\"", error)->matches(event));
        event.action = "block";
        QVERIFY(LogFilter::compile("action=\"block\"", error)->matches(event));
    }
    void invalid_data() {
        QTest::addColumn<QString>("expression");
        for (const auto* expression : {"unknown=\"x\"",
                                       "addr=x",
                                       "addr==\"x\"",
                                       "addr=\"",
                                       "addr=\"x\" rule=\"a\"",
                                       "action=\"default\"",
                                       "dns_type=\"65536\"",
                                       "addr=\"\"",
                                       "(err=\"*\"",
                                       "err=\"*\" &&",
                                       "err=\"\\n\"",
                                       "!"})
            QTest::newRow(expression) << QString(expression);
        QTest::newRow("depth") << QString(34, '(') + "err=\"*\"" + QString(34, ')');
        QTest::newRow("length") << QString(4097, ' ');
        QStringList conditions;
        for (int i = 0; i < 70; ++i)
            conditions << "err=\"*\"";
        QTest::newRow("complexity") << conditions.join(" || ");
    }
    void invalid() {
        QFETCH(QString, expression);
        QString error;
        QVERIFY(!LogFilter::compile(expression, error));
        QVERIFY(!error.isEmpty());
    }
    void decodeWireFormats() {
        const auto decoded = decodeLogRecords(
            "1\t0\t1700000000000\tDNS_TIMEOUT\tfailure\texample.com\tA\tweird, time=1 ms, "
            "error=x\tprocess\n"
            "2\t1\t1700000000000\tCORE_STARTED\tstarted\t\t\t\t\n"
            "3\t1\t1700000000000\tDNS_ROUTE\texample.com [AAAA] - block : server=none, "
            "rule=Default\n"
            "4\t0\tERROR\tlegacy failure\nmalformed\nwrong\t0\tCODE\tinvalid sequence\n");
        QCOMPARE(decoded.size(), 4);
        QCOMPARE(decoded[0].rule, "weird, time=1 ms, error=x");
        QCOMPARE(decoded[0].message, "failure");
        QCOMPARE(decoded[0].address, "example.com");
        QCOMPARE(decoded[0].action, "process");
        QCOMPARE(decoded[0].code, "DNS_TIMEOUT");
        QVERIFY(decoded[0].error);
        QCOMPARE(decoded[0].timestamp.toMSecsSinceEpoch(), 1700000000000LL);
        QVERIFY(decoded[1].action.isEmpty());
        QCOMPARE(decoded[2].action, "block");
        QCOMPARE(decoded[2].rule, "Default");
        QCOMPARE(decoded[2].dnsType, "AAAA");
        QCOMPARE(decoded[3].message, "legacy failure");
    }
    void applyAndRetain() {
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        LogPanel panel(nullptr, &settings);
        panel.resize(900, 400);
        panel.show();
        auto* input = panel.findChild<QLineEdit*>("logFilterInput");
        auto* view = panel.findChild<QPlainTextEdit*>("logDisplay");
        auto* apply = panel.findChild<QToolButton*>("logFilterApply");
        panel.appendRecords({record("success"), record("failed", true)});
        input->setText("err=\"*\"");
        QVERIFY(view->toPlainText().contains("success"));
        apply->click();
        QVERIFY(!view->toPlainText().contains("success"));
        QVERIFY(view->toPlainText().contains("failed"));
        input->setText("bad syntax");
        QVERIFY(!panel.applyFilter());
        QVERIFY(!apply->isEnabled());
        panel.appendRecords({record("new success"), record("new failure", true)});
        QVERIFY(!view->toPlainText().contains("new success"));
        QVERIFY(view->toPlainText().contains("new failure"));
        input->clear();
        QTest::keyClick(input, Qt::Key_Return);
        QVERIFY(view->toPlainText().contains("new success"));
        panel.clear();
        QList<LogRecord> events;
        for (int i = 0; i < 2010; ++i)
            events << record(QString("row %1 end").arg(i), i % 2 == 0);
        panel.appendRecords(events);
        QVERIFY(!view->toPlainText().contains("row 9 end"));
        QVERIFY(view->toPlainText().contains("row 10 end"));
        QCOMPARE(view->document()->blockCount(), 2001);
        input->setText("err=\"*\"");
        QVERIFY(panel.applyFilter());
        panel.appendRecords({record("extra")});
        QVERIFY(!view->toPlainText().contains("row 10 end"));
        QCOMPARE(view->document()->blockCount(), 1000);
        input->clear();
        QVERIFY(panel.applyFilter());
        QCOMPARE(view->document()->blockCount(), 2001);
        QVERIFY(view->toPlainText().contains("extra"));
        panel.clear();
        QVERIFY(view->toPlainText().isEmpty());
    }
    void bookmarkPersistence() {
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        LogPanel panel(nullptr, &settings);
        auto* input = panel.findChild<QLineEdit*>("logFilterInput");
        auto* menu = panel.findChild<QToolButton*>("logFilterBookmark")->menu();
        input->setText("action=\"block\"");
        openMenu(menu);
        QCOMPARE(menu->actions().size(), 4);
        QCOMPARE(menu->actions()[0]->text(), uiText("Save this filter"));
        QVERIFY(menu->actions()[3]->isSeparator());
        QVERIFY(!menu->actions()[1]->isEnabled());
        QTimer::singleShot(0, [] {
            auto* prompt = qobject_cast<QInputDialog*>(QApplication::activeModalWidget());
            QVERIFY(prompt);
            prompt->setTextValue("Blocked");
            prompt->accept();
        });
        menu->actions()[0]->trigger();
        QCOMPARE(panel.savedFilters().size(), 1);
        LogPanel reopened(nullptr, &settings);
        QCOMPARE(reopened.savedFilters(), panel.savedFilters());
        auto* secondMenu = reopened.findChild<QToolButton*>("logFilterBookmark")->menu();
        openMenu(secondMenu);
        secondMenu->actions()[4]->trigger();
        QCOMPARE(reopened.findChild<QLineEdit*>("logFilterInput")->text(), "action=\"block\"");
        openMenu(secondMenu);
        QVERIFY(secondMenu->actions()[4]->isChecked());
        QVERIFY(!secondMenu->actions()[0]->isEnabled());
        QVERIFY(secondMenu->actions()[1]->isEnabled());
        secondMenu->actions()[1]->trigger();
        QVERIFY(reopened.savedFilters().isEmpty());
        LogPanel deleted(nullptr, &settings);
        QVERIFY(deleted.savedFilters().isEmpty());
    }
    void managerAndHelp() {
        const QList<SavedLogFilter> initial{{"id", "Errors", "err=\"*\""}};
        SavedFiltersDialog dialog(nullptr, initial);
        dialog.show();
        auto* table = dialog.findChild<QTableWidget*>("savedFiltersTable");
        table->selectRow(0);
        button(dialog, "Clone")->click();
        QCOMPARE(table->rowCount(), 2);
        QCOMPARE(table->item(1, 1)->text(), "err=\"*\"");
        QVERIFY(table->item(1, 0)->data(Qt::UserRole) != table->item(0, 0)->data(Qt::UserRole));
        button(dialog, "Remove")->click();
        QCOMPARE(table->rowCount(), 1);
        button(dialog, "Add...")->click();
        QCOMPARE(table->rowCount(), 2);
        table->item(1, 0)->setText("Processed");
        table->item(1, 1)->setText("action=\"process\"");
        QVERIFY(button(dialog, "OK")->x() < button(dialog, "Help")->x());
        QVERIFY(button(dialog, "Help")->x() < button(dialog, "Close")->x());
        QTimer::singleShot(0, [&dialog] {
            auto* help = qobject_cast<QDialog*>(QApplication::activeModalWidget());
            QVERIFY(help);
            QVERIFY(help->parentWidget() == &dialog);
            QVERIFY(help->findChild<QTextBrowser*>()->toPlainText().contains("action="));
            help->accept();
        });
        button(dialog, "Help")->click();
        button(dialog, "OK")->click();
        QCOMPARE(dialog.result(), int(QDialog::Accepted));
        QCOMPARE(dialog.filters().size(), 2);
        QCOMPARE(dialog.filters()[1].expression, "action=\"process\"");
        SavedFiltersDialog cancelled(nullptr, initial);
        cancelled.findChild<QTableWidget*>()->item(0, 1)->setText("action=\"block\"");
        button(cancelled, "Close")->click();
        QCOMPARE(cancelled.filters(), initial);
        SavedFiltersDialog invalid(nullptr, initial);
        invalid.findChild<QTableWidget*>()->item(0, 1)->setText("broken");
        QTimer::singleShot(0, [] {
            auto* warning = qobject_cast<QMessageBox*>(QApplication::activeModalWidget());
            QVERIFY(warning);
            warning->accept();
        });
        button(invalid, "OK")->click();
        QCOMPARE(invalid.filters(), initial);
        QCOMPARE(invalid.result(), int(QDialog::Rejected));
    }
    void configRoundTrip() {
        QTemporaryDir directory;
        const auto path = directory.filePath("filters.xml");
        const QList<SavedLogFilter> filters{
            {"one", QString::fromUtf8("Ошибки & DNS"), "err=\"*\""},
            {"two", "Escaped values", "rule=\"R&D <test>\" && !action=\"block\""}};
        saveLogFilterConfig(path, filters);
        QCOMPARE(loadLogFilterConfig(path), filters);
        QFile file(path);
        QVERIFY(file.open(QIODevice::ReadOnly));
        const auto before = file.readAll();
        QVERIFY(before.contains("&amp;&amp;"));
        file.close();
        auto invalid = filters;
        invalid[0].expression = "broken";
        bool rejected = false;
        try {
            saveLogFilterConfig(path, invalid);
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        QVERIFY(rejected);
        QVERIFY(file.open(QIODevice::ReadOnly));
        QCOMPARE(file.readAll(), before);
        file.close();
        saveLogFilterConfig(path, {});
        QVERIFY(loadLogFilterConfig(path).isEmpty());
        const auto example = loadLogFilterConfig(QStringLiteral(LOG_FILTER_EXAMPLE_PATH));
        QCOMPARE(example.size(), 13);
        auto actual = record();
        actual.address = "ipv6.msftconnecttest.com";
        actual.dnsType = "A";
        actual.rule = "Default";
        actual.action = "bypass";
        QString error;
        QVERIFY(LogFilter::compile(example[9].expression, error)->matches(actual));
        QVERIFY(LogFilter::compile(example[10].expression, error)->matches(actual));
        QVERIFY(LogFilter::compile(example[12].expression, error)->matches(actual));
    }
    void invalidConfig_data() {
        QTest::addColumn<QByteArray>("xml");
        QTest::newRow("malformed") << QByteArray("<NativeDNSLogFilters");
        QTest::newRow("other config") << QByteArray("<NativeDNS schemaVersion=\"1\"/>");
        QTest::newRow("version") << QByteArray(
            "<NativeDNSLogFilters schemaVersion=\"2\"><Filters/></NativeDNSLogFilters>");
        QTest::newRow("missing list") << QByteArray("<NativeDNSLogFilters schemaVersion=\"1\"/>");
        QTest::newRow("trailing root") << QByteArray(
            "<NativeDNSLogFilters schemaVersion=\"1\"><Filters/></NativeDNSLogFilters><other/>");
        QTest::newRow("DTD") << QByteArray("<!DOCTYPE NativeDNSLogFilters><NativeDNSLogFilters "
                                           "schemaVersion=\"1\"><Filters/></NativeDNSLogFilters>");
        const QByteArray begin("<NativeDNSLogFilters schemaVersion=\"1\"><Filters>");
        const QByteArray end("</Filters></NativeDNSLogFilters>");
        const QByteArray valid(
            "<Filter "
            "id=\"same\"><Name>Errors</Name><Expression>err=&quot;*&quot;</Expression></Filter>");
        QTest::newRow("duplicate IDs") << begin + valid + valid + end;
        QTest::newRow("missing expression") << begin + "<Filter><Name>Errors</Name></Filter>" + end;
        QTest::newRow("bad expression")
            << begin + "<Filter><Name>Errors</Name><Expression>broken</Expression></Filter>" + end;
        QTest::newRow("too many") << begin + valid.repeated(257) + end;
        QTest::newRow("too large") << QByteArray(1024 * 1024 + 1, ' ');
    }
    void invalidConfig() {
        QFETCH(QByteArray, xml);
        QTemporaryDir directory;
        const auto path = directory.filePath("filters.xml");
        QFile file(path);
        QVERIFY(file.open(QIODevice::WriteOnly));
        QCOMPARE(file.write(xml), qint64(xml.size()));
        file.close();
        bool rejected = false;
        try {
            loadLogFilterConfig(path);
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        QVERIFY(rejected);
    }
    void managerTransactionsAndFiles() {
        QApplication::setAttribute(Qt::AA_DontUseNativeDialogs, true);
        QTemporaryDir directory;
        const auto path = directory.filePath("import.xml");
        const auto exported = directory.filePath("export.xml");
        const QList<SavedLogFilter> initial{{"one", "Errors", "err=\"*\""}};
        const QList<SavedLogFilter> incoming{{"new", "Blocked", "action=\"block\""}};
        saveLogFilterConfig(path, incoming);
        const auto selectFile = [](const QString& selected) {
            QTimer::singleShot(0, [selected] {
                auto* chooser = qobject_cast<QFileDialog*>(QApplication::activeModalWidget());
                QVERIFY(chooser);
                chooser->selectFile(selected);
                static_cast<QDialog*>(chooser)->accept();
            });
        };
        SavedFiltersDialog dialog(nullptr, initial);
        dialog.show();
        auto* table = dialog.findChild<QTableWidget*>("savedFiltersTable");
        QVERIFY(!table->item(0, 0)->font().bold());
        table->item(0, 1)->setText("action=\"process\"");
        QVERIFY(table->item(0, 0)->font().bold());
        QVERIFY(table->item(0, 1)->font().bold());
        table->item(0, 1)->setText(initial[0].expression);
        QVERIFY(!table->item(0, 0)->font().bold());
        selectFile(path);
        button(dialog, "Import")->click();
        QCOMPARE(table->rowCount(), 1);
        QCOMPARE(table->item(0, 0)->text(), incoming[0].name);
        QVERIFY(table->item(0, 0)->font().bold());
        QCOMPARE(dialog.filters(), initial);
        selectFile(exported);
        button(dialog, "Export")->click();
        QCOMPARE(loadLogFilterConfig(exported), incoming);
        QCOMPARE(dialog.filters(), initial);
        button(dialog, "Close")->click();
        QCOMPARE(dialog.filters(), initial);
        SavedFiltersDialog accepted(nullptr, initial);
        selectFile(path);
        button(accepted, "Import")->click();
        button(accepted, "OK")->click();
        QCOMPARE(accepted.filters(), incoming);
        QApplication::setAttribute(Qt::AA_DontUseNativeDialogs, false);
    }
    void managerBoundedHeader() {
        SavedFiltersDialog dialog(nullptr, {{"one", "Errors", "err=\"*\""}});
        dialog.show();
        auto* table = dialog.findChild<QTableWidget*>("savedFiltersTable");
        auto* header = table->horizontalHeader();
        QTRY_COMPARE(header->length(), table->viewport()->width());
        const int initial = header->sectionSize(0);
        const auto drag = [&](int delta) {
            const QPoint edge(header->sectionSize(0) - 1, header->height() / 2);
            QTest::mousePress(header->viewport(), Qt::LeftButton, Qt::NoModifier, edge);
            QTest::mouseMove(header->viewport(), edge + QPoint(delta, 0));
            QTest::mouseRelease(
                header->viewport(), Qt::LeftButton, Qt::NoModifier, edge + QPoint(delta, 0));
            QCOMPARE(header->length(), table->viewport()->width());
        };
        drag(30);
        QCOMPARE(header->sectionSize(0), initial + 30);
        drag(-10000);
        QVERIFY(header->sectionSize(0) >= 150);
        drag(10000);
        QVERIFY(header->sectionSize(1) >= 250);
        dialog.resize(1, dialog.height());
        QTRY_COMPARE(header->length(), table->viewport()->width());
        QVERIFY(header->sectionSize(0) >= 150);
        QVERIFY(header->sectionSize(1) >= 250);
        const auto* importFilters = button(dialog, "Import");
        const auto* remove = button(dialog, "Remove");
        QCOMPARE(importFilters->size(), remove->size());
        QVERIFY(importFilters->y() - (remove->y() + remove->height()) >= remove->height());
    }
    void themesAndLocalization() {
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        LogPanel panel(nullptr, &settings);
        panel.resize(1000, 440);
        panel.show();
        auto* view = panel.findChild<QPlainTextEdit*>("logDisplay");
        auto* input = panel.findChild<QLineEdit*>("logFilterInput");
        panel.appendRecords({record("successful query"), record("connection timed out", true)});
        QVERIFY(!view->isUndoRedoEnabled());
        const auto screenshots = qEnvironmentVariable("NATIVEDNS_TEST_SCREENSHOTS");
        if (!screenshots.isEmpty())
            QVERIFY(QDir().mkpath(screenshots));
        for (const bool dark : {false, true}) {
            applyUiTheme(*qobject_cast<QApplication*>(QCoreApplication::instance()), dark);
            QCoreApplication::processEvents();
            const auto block = view->document()->findBlockByNumber(1);
            QTextCursor cursor(block);
            cursor.movePosition(QTextCursor::NextCharacter, QTextCursor::KeepAnchor);
            QCOMPARE(cursor.charFormat().foreground().color(),
                     dark ? QColor(255, 105, 105) : QColor(190, 0, 0));
            if (!screenshots.isEmpty())
                QVERIFY(
                    panel.grab().save(screenshots + (dark ? "/log-dark.png" : "/log-light.png")));
        }
        setUiLanguage(UiLanguage::russian);
        panel.retranslateUi();
        input->setText("bad");
        QVERIFY(panel.findChild<QLabel*>("logFilterError")
                    ->text()
                    .contains(QString::fromUtf8("Неизвестное поле")));
        input->clear();
        const QList<SavedLogFilter> initial{{"one", "Errors", "err=\"*\""},
                                            {"two", "Blocked", "action=\"block\""}};
        SavedFiltersDialog dialog(nullptr, initial);
        dialog.show();
        QCoreApplication::processEvents();
        QCOMPARE(button(dialog, "Help")->text(), QString::fromUtf8("Справка"));
        if (!screenshots.isEmpty())
            QVERIFY(dialog.grab().save(screenshots + "/filters-ru.png"));
        for (const bool dark : {false, true}) {
            applyUiTheme(*qobject_cast<QApplication*>(QCoreApplication::instance()), dark);
            QTimer::singleShot(0, [screenshots, dark] {
                auto* help = qobject_cast<QDialog*>(QApplication::activeModalWidget());
                QVERIFY(help);
                const auto content = help->findChild<QTextBrowser*>()->toPlainText();
                QVERIFY(content.contains(QString::fromUtf8("Типы фильтров")));
                QVERIFY(content.contains("action="));
                if (!screenshots.isEmpty())
                    QVERIFY(help->grab().save(screenshots +
                                              (dark ? "/help-dark-ru.png" : "/help-light-ru.png")));
                help->accept();
            });
            button(dialog, "Help")->click();
        }
        setUiLanguage(UiLanguage::english);
        applyUiTheme(*qobject_cast<QApplication*>(QCoreApplication::instance()), false);
    }
};
QTEST_MAIN(LogFilterTests)
#include "log_filter_tests.moc"
