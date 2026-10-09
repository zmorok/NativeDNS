#include "../NativeDNS.GUI/log_filter_ui.hpp"
#include "../NativeDNS.GUI/ui_preferences.hpp"
#include <QAction>
#include <QDir>
#include <QFileDialog>
#include <QFontDatabase>
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
#include <QTreeWidget>
#include <QScrollBar>
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
    void initTestCase() {
        const auto fontPath = qEnvironmentVariable("NATIVEDNS_TEST_FONT");
        if (!fontPath.isEmpty()) {
            const int id = QFontDatabase::addApplicationFont(fontPath);
            QVERIFY(id >= 0);
            const auto families = QFontDatabase::applicationFontFamilies(id);
            QVERIFY(!families.isEmpty());
            qApp->setFont(QFont(families.front(), 9));
        }
    }
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
    void fastPathMetadataRecovery() {
        const auto raw =
            QStringLiteral("dns.msftncsi.com [AAAA] - bypass : server=192.168.31.1 "
                           "(UDP) (DNS over UDP), rule=Default, endpoint=192.168.31.1 port=53 "
                           "interface=automatic generation=0");
        const auto wire = "102\t1\t1700000000000\tDNS_ROUTE\t" + raw;
        for (const auto& frame : {wire + "\t\t\t\t\n", wire + "\n", wire + "\t\t\tDefault\t\n"}) {
            const auto decoded = decodeLogRecords(frame);
            QCOMPARE(decoded.size(), 1);
            QCOMPARE(decoded[0].message, raw);
            QCOMPARE(decoded[0].address, "dns.msftncsi.com");
            QCOMPARE(decoded[0].dnsType, "AAAA");
            QCOMPARE(decoded[0].rule, "Default");
            QCOMPARE(decoded[0].action, "bypass");
            QString error;
            QVERIFY(!LogFilter::compile("!action=\"bypass\"", error)->matches(decoded[0]));
            QVERIFY(LogFilter::compile("addr=\"dns.msftncsi.com\" && rule=\"Default\"", error)
                        ->matches(decoded[0]));
            QTemporaryDir directory;
            QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
            LogPanel panel(nullptr, &settings);
            panel.appendRecords(decoded);
            const auto text = panel.findChild<QPlainTextEdit*>("logDisplay")->toPlainText();
            QVERIFY(text.contains("dns.msftncsi.com [AAAA]"));
            QVERIFY(text.contains("Bypass"));
            QVERIFY(text.contains("Rule: Default"));
            auto* input = panel.findChild<QLineEdit*>("logFilterInput");
            input->setText("!action=\"bypass\"");
            QVERIFY(panel.applyFilter());
            QVERIFY(panel.findChild<QPlainTextEdit*>("logDisplay")->toPlainText().isEmpty());
        }
        const auto suppressed =
            decodeLogRecords("104\t0\t1700000000000\tTIMEOUT\tsuppressed=2 " + raw + "\t\t\t\t\n");
        QCOMPARE(suppressed[0].address, "dns.msftncsi.com");
        QCOMPARE(suppressed[0].rule, "Default");
        const auto explicitFields =
            decodeLogRecords(wire + "\tauthoritative.example\tA\tCustom, endpoint=x\tprocess\n");
        QCOMPARE(explicitFields[0].address, "authoritative.example");
        QCOMPARE(explicitFields[0].rule, "Custom, endpoint=x");
        QCOMPARE(explicitFields[0].action, "process");
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
    void logViews_data() {
        QTest::addColumn<int>("mode");
        QTest::newRow("compact") << static_cast<int>(LogView::compact);
        QTest::newRow("table") << static_cast<int>(LogView::table);
        QTest::newRow("details") << static_cast<int>(LogView::details);
    }
    void logViews() {
        QFETCH(int, mode);
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        LogPanel panel(nullptr, &settings);
        panel.resize(1100, 500);
        panel.show();
        QVERIFY(panel.setLogView(static_cast<LogView>(mode)));
        auto success =
            record("www.example.com [AAAA] - process : server=Example DNS (DoH) (DoH) "
                   "(DNS over HTTPS), rule=AI - OpenAI, time=24.51 ms, endpoint=dns.example.com "
                   "port=0 interface=automatic generation=7");
        auto failure = success;
        failure.message +=
            ", error=host=dns.example.com context=|0|0|0|7 upstream bootstrap "
            "failed: resolver=192.0.2.53 type=A error=TIMEOUT: Socket wait deadline exceeded";
        failure.error = true;
        auto bypass = record("www.other.example [A] - bypass : server=192.0.2.53 (UDP) "
                             "(DNS over UDP), rule=Default, endpoint=192.0.2.53 port=53 "
                             "interface=automatic generation=0");
        bypass.address = "www.other.example";
        bypass.dnsType = "A";
        bypass.rule = "Default";
        bypass.action = "bypass";
        auto blocked = record("blocked.example [A] - block : server=none, rule=Block list");
        blocked.address = "blocked.example";
        blocked.dnsType = "A";
        blocked.rule = "Block list";
        blocked.action = "block";
        LogRecord network;
        network.timestamp = success.timestamp;
        network.code = "NETWORK_CHANGED";
        network.message = "generation=8 previous=7 interfaces=71";
        panel.appendRecords({success, failure, bypass, blocked, network});
        auto* input = panel.findChild<QLineEdit*>("logFilterInput");
        auto* display = panel.findChild<LogDisplay*>();
        QCOMPARE(display->recordCount(), 5);
        // Presentation hides technical fields, while err still searches the original record.
        input->setText("err=\"generation=7\"");
        QVERIFY(panel.applyFilter());
        QCOMPARE(display->recordCount(), 1);
        const auto inspector = panel.findChild<QPlainTextEdit*>("logRecordDetails");
        QVERIFY(inspector->toPlainText().contains(failure.message));
        input->setText(
            "addr=\"*.example.com\" && dns_type=\"28\" && rule=\"AI - OpenAI\" && !err=\"*\"");
        QVERIFY(panel.applyFilter());
        QCOMPARE(display->recordCount(), 1);
        QVERIFY(inspector->toPlainText().contains(success.message));
        const auto text = panel.findChild<QPlainTextEdit*>("logDisplay")->toPlainText();
        if (mode == static_cast<int>(LogView::compact)) {
            QVERIFY(text.contains("Example DNS (DoH)"));
            QVERIFY(text.contains("24.51"));
            QVERIFY(!text.contains("generation="));
            QVERIFY(!text.contains("interface="));
            QVERIFY(!text.contains("DNS over HTTPS"));
            QVERIFY(!text.contains("(DoH) (DoH)"));
            QCOMPARE(panel.findChild<QPlainTextEdit*>("logDisplay")->document()->blockCount(), 2);
        } else if (mode == static_cast<int>(LogView::table)) {
            auto* table = panel.findChild<QTableWidget*>("logTable");
            QCOMPARE(table->rowCount(), 1);
            QCOMPARE(table->item(0, 1)->text(), "www.example.com [AAAA]");
            QCOMPARE(table->item(0, 3)->text(), "Example DNS (DoH)");
            QCOMPARE(table->item(0, 5)->text(), "24.51");
        } else {
            auto* tree = panel.findChild<QTreeWidget*>("logDetailsTree");
            QCOMPARE(tree->topLevelItemCount(), 1);
            QVERIFY(!tree->topLevelItem(0)->isExpanded());
            tree->topLevelItem(0)->setExpanded(true);
            QVERIFY(tree->topLevelItem(0)->child(0)->text(0).contains(success.message));
        }
        for (const auto& expression : {"action=\"bypass\"", "action=\"block\"", "!action=\"*\""}) {
            input->setText(expression);
            QVERIFY(panel.applyFilter());
            QCOMPARE(display->recordCount(), 1);
        }
        QVERIFY(inspector->toPlainText().contains(network.message));
        input->setText("err=\"TIMEOUT\"");
        QVERIFY(panel.applyFilter());
        for (const auto view : {LogView::compact, LogView::details, LogView::table}) {
            QVERIFY(panel.setLogView(view));
            QCOMPARE(display->recordCount(), 1);
            QVERIFY(inspector->toPlainText().contains(failure.message));
            LogPanel reopened(nullptr, &settings);
            QCOMPARE(reopened.logView(), view);
        }
        panel.appendRecords({success, failure});
        QCOMPARE(display->recordCount(), 2);
        panel.clear();
        QCOMPARE(display->recordCount(), 0);
        QVERIFY(inspector->toPlainText().isEmpty());
    }
    void logViewBuffer_data() {
        logViews_data();
    }
    void logViewMenuAndAppearance() {
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        settings.setValue("ui/logView", "two_lines");
        LogPanel panel(nullptr, &settings);
        QCOMPARE(panel.logView(), LogView::compact);
        panel.resize(1100, 620);
        panel.show();
        QMenu menu;
        addLogViewActions(&menu, panel);
        QCOMPARE(menu.actions().size(), 3);
        QCOMPARE(menu.actions()[0]->text(), "Short line");
        QCOMPARE(menu.actions()[1]->text(), "Line with details");
        QCOMPARE(menu.actions()[2]->text(), "Table");
        auto* input = panel.findChild<QLineEdit*>("logFilterInput");
        QList<LogRecord> records;
        for (int i = 0; i < 10; ++i) {
            auto event = record(
                QString(
                    "www%1.example.com [AAAA] - process : server=Example DNS (DoH) "
                    "(DNS over HTTPS), rule=AI - OpenAI, time=24.51 ms, endpoint=dns.example.com "
                    "port=0 interface=automatic generation=7")
                    .arg(i),
                i == 8);
            event.address = QString("www%1.example.com").arg(i);
            event.sequence = i + 1;
            if (event.error)
                event.message += ", error=host=dns.example.com context=|0|0|0|7 "
                                 "upstream bootstrap failed: resolver=192.0.2.53 type=A "
                                 "error=TIMEOUT: Socket wait deadline exceeded";
            records << event;
        }
        panel.appendRecords(records);
        const auto screenshots = qEnvironmentVariable("NATIVEDNS_TEST_SCREENSHOTS");
        if (!screenshots.isEmpty())
            QVERIFY(QDir().mkpath(screenshots));
        for (const bool dark : {false, true}) {
            applyUiTheme(*qobject_cast<QApplication*>(QCoreApplication::instance()), dark);
            setUiLanguage(dark ? UiLanguage::russian : UiLanguage::english);
            panel.retranslateUi();
            for (int i = 0; i < menu.actions().size(); ++i) {
                menu.actions()[i]->trigger();
                QCOMPARE(static_cast<int>(panel.logView()), i);
                int checked = 0;
                for (const auto* action : menu.actions())
                    checked += action->isChecked();
                QCOMPARE(checked, 1);
                auto* display = panel.findChild<LogDisplay*>();
                QCOMPARE(display->recordCount(), 10);
                const QColor errorColor = dark ? QColor(255, 105, 105) : QColor(190, 0, 0);
                if (panel.logView() == LogView::table) {
                    auto* table = panel.findChild<QTableWidget*>("logTable");
                    QCOMPARE(table->item(8, 6)->foreground().color(), errorColor);
                    QCOMPARE(table->item(8, 6)->text(), "TIMEOUT: Socket wait deadline exceeded");
                    table->setCurrentCell(8, 0);
                } else if (panel.logView() == LogView::details) {
                    auto* tree = panel.findChild<QTreeWidget*>("logDetailsTree");
                    QCOMPARE(tree->topLevelItem(8)->foreground(0).color(), errorColor);
                    tree->topLevelItem(0)->setExpanded(true);
                    tree->setCurrentItem(tree->topLevelItem(0)->child(0));
                }
                QCoreApplication::processEvents();
                if (!screenshots.isEmpty())
                    QVERIFY(panel.grab().save(screenshots + "/view-" + logViewKey(panel.logView()) +
                                              (dark ? "-dark-ru.png" : "-light-en.png")));
                input->setText("err=\"context=|0|0|0|7\"");
                QVERIFY(panel.applyFilter());
                QCOMPARE(display->recordCount(), 1);
                input->clear();
                QVERIFY(panel.applyFilter());
            }
        }
        setUiLanguage(UiLanguage::english);
        applyUiTheme(*qobject_cast<QApplication*>(QCoreApplication::instance()), false);
    }
    void logViewBuffer() {
        QFETCH(int, mode);
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        LogPanel panel(nullptr, &settings);
        QVERIFY(panel.setLogView(static_cast<LogView>(mode)));
        QList<LogRecord> records;
        for (int i = 0; i < 2002; ++i) {
            auto event = record(QString("row%1.example [AAAA] - process : server=Example (UDP), "
                                        "rule=AI - OpenAI, time=1.23 ms, endpoint=192.0.2.53 "
                                        "interface=automatic generation=2")
                                    .arg(i),
                                i % 2 == 0);
            event.sequence = i + 1;
            event.address = QString("row%1.example").arg(i);
            if (event.error)
                event.message += ", error=TIMEOUT: test deadline";
            records << event;
        }
        panel.appendRecords(records);
        auto* display = panel.findChild<LogDisplay*>();
        QCOMPARE(display->recordCount(), 2000);
        auto* inspector = panel.findChild<QPlainTextEdit*>("logRecordDetails");
        // Selecting the new first row after eviction must inspect that row, not the removed one.
        if (mode == static_cast<int>(LogView::compact)) {
            auto* text = panel.findChild<QPlainTextEdit*>("logDisplay");
            QTextCursor cursor(text->document());
            cursor.movePosition(QTextCursor::End);
            text->setTextCursor(cursor);
            cursor.movePosition(QTextCursor::Start);
            text->setTextCursor(cursor);
        } else if (mode == static_cast<int>(LogView::table)) {
            auto* table = panel.findChild<QTableWidget*>("logTable");
            QCOMPARE(table->rowCount(), 2000);
            table->setCurrentCell(0, 0);
        } else {
            auto* tree = panel.findChild<QTreeWidget*>("logDetailsTree");
            QCOMPARE(tree->topLevelItemCount(), 2000);
            tree->setCurrentItem(tree->topLevelItem(0));
        }
        QVERIFY(inspector->toPlainText().contains(records[2].message));
        QVERIFY(!inspector->toPlainText().contains(records[0].message));
        auto* input = panel.findChild<QLineEdit*>("logFilterInput");
        input->setText("err=\"*\"");
        QVERIFY(panel.applyFilter());
        QCOMPARE(display->recordCount(), 1000);
        panel.appendRecords({record("new success")});
        QCOMPARE(display->recordCount(), 999);
        for (const auto view : {LogView::compact, LogView::details, LogView::table}) {
            QVERIFY(panel.setLogView(view));
            QCOMPARE(display->recordCount(), 999);
        }
        input->clear();
        QVERIFY(panel.applyFilter());
        QCOMPARE(display->recordCount(), 2000);
    }
    void actionSelection_data() {
        logViews_data();
    }
    void actionSelection() {
        QFETCH(int, mode);
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        LogPanel panel(nullptr, &settings);
        QVERIFY(panel.setLogView(static_cast<LogView>(mode)));
        QMenu menu;
        addLogActionFilterActions(&menu, panel);
        QCOMPARE(menu.actions().size(), 5);
        auto* all = menu.actions()[0];
        auto* process = menu.actions()[2];
        auto* block = menu.actions()[3];
        auto* bypass = menu.actions()[4];
        QVERIFY(all->isChecked());
        QVERIFY(!process->isChecked() && !block->isChecked() && !bypass->isChecked());
        auto blocked = record("blocked");
        blocked.action = "block";
        auto bypassed = record("bypassed");
        bypassed.action = "bypass";
        auto service = record("core event");
        service.code = "CORE_INITIALIZING";
        service.address.clear();
        service.dnsType.clear();
        service.rule.clear();
        service.action.clear();
        panel.appendRecords({record("processed"), blocked, bypassed, service});
        auto* display = panel.findChild<LogDisplay*>();
        QCOMPARE(display->recordCount(), 4);
        process->trigger();
        QVERIFY(process->isChecked() && !all->isChecked());
        QCOMPARE(panel.shownActions(), QSet<QString>{"process"});
        QCOMPARE(display->recordCount(), 2);
        block->trigger();
        QVERIFY(process->isChecked() && block->isChecked());
        QCOMPARE(display->recordCount(), 3);
        LogPanel reopened(nullptr, &settings);
        QCOMPARE(reopened.shownActions(), panel.shownActions());
        QMenu restoredMenu;
        addLogActionFilterActions(&restoredMenu, reopened);
        QVERIFY(restoredMenu.actions()[2]->isChecked());
        QVERIFY(restoredMenu.actions()[3]->isChecked());
        auto* input = panel.findChild<QLineEdit*>("logFilterInput");
        input->setText("action=\"block\"");
        QVERIFY(panel.applyFilter());
        QCOMPARE(display->recordCount(), 1);
        bypass->trigger();
        QCOMPARE(display->recordCount(), 1);
        all->trigger();
        QVERIFY(all->isChecked());
        QVERIFY(!process->isChecked() && !block->isChecked() && !bypass->isChecked());
        QVERIFY(panel.shownActions().isEmpty());
        QCOMPARE(input->text(), "action=\"block\"");
        QCOMPARE(display->recordCount(), 1); // All clears only the menu restriction.
        input->clear();
        QVERIFY(panel.applyFilter());
        QCOMPARE(display->recordCount(), 4);
        all->trigger();
        QVERIFY(all->isChecked());
        process->trigger();
        process->trigger();
        QVERIFY(all->isChecked()); // Removing the last selection restores All.
        block->trigger();
        bypass->trigger();
        QCOMPARE(display->recordCount(), 3);
        panel.appendRecords({record("new processed"), blocked, bypassed, service});
        QCOMPARE(display->recordCount(), 6);
        QVERIFY(panel.setLogView(LogView::compact));
        QCOMPARE(display->recordCount(), 6);
        all->trigger();
        QCOMPARE(display->recordCount(), 8);
        panel.clear();
        QVERIFY(panel.setShownActions({"process"}));
        QList<LogRecord> traffic;
        for (int i = 0; i < 2002; ++i)
            traffic << (i % 2 ? bypassed : record("processed"));
        panel.appendRecords(traffic);
        QCOMPARE(display->recordCount(), 1000);
        panel.appendRecords({blocked}); // The first retained Process row is evicted.
        QCOMPARE(display->recordCount(), 999);
        all->trigger();
        QCOMPARE(display->recordCount(), 2000);
    }
    void technicalRecordClassification() {
        LogRecord technical;
        for (const auto* code : {"CORE_INITIALIZING",
                                 "CORE_STARTED",
                                 "CONFIG_RELOADED",
                                 "NETWORK_CHANGED",
                                 "NETWORK_INTERFACE",
                                 "SYSTEM_ENVIRONMENT",
                                 "DNS_CACHE_CLEARED",
                                 "WINDIVERT_STARTED",
                                 "WINDIVERT_DRIVER_STOPPED",
                                 "CORE_START_FAILED",
                                 "FILE_LOG_CONFIGURED",
                                 ""}) {
            technical.code = code;
            QVERIFY2(isTechnicalLogRecord(technical), code);
        }
        for (const auto* code : {"DNS_ROUTE",
                                 "DNS_CAPTURE",
                                 "DNS_UPSTREAM",
                                 "DNS_REPLY_DETAIL",
                                 "WINDIVERT_RULE_FAST_PATH",
                                 "WINDIVERT_TCP_REFLECT",
                                 "WINDIVERT_UPSTREAM_BYPASS",
                                 "TCP_PROXY_ACCEPT",
                                 "TCP_PROXY_REJECT",
                                 "CAPTIVE_PORTAL_BYPASS"}) {
            technical.code = code;
            QVERIFY2(!isTechnicalLogRecord(technical), code);
        }
        QVERIFY(!isTechnicalLogRecord(record("query failed", true)));
    }
    void commandSelection_data() {
        logViews_data();
    }
    void commandSelection() {
        QFETCH(int, mode);
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        LogPanel panel(nullptr, &settings);
        QVERIFY(panel.setLogView(static_cast<LogView>(mode)));
        QMenu actionsMenu, commandsMenu;
        addLogActionFilterActions(&actionsMenu, panel);
        addLogCommandFilterActions(&commandsMenu, panel, &actionsMenu);
        QCOMPARE(commandsMenu.actions().size(), 2);
        auto* only = commandsMenu.actions()[0];
        auto* with = commandsMenu.actions()[1];
        QCOMPARE(only->text(), uiText("Only"));
        QCOMPARE(with->text(), uiText("With"));
        QVERIFY(with->isChecked() && !only->isChecked());
        QVERIFY(actionsMenu.menuAction()->isEnabled());
        LogRecord technical;
        technical.timestamp = QDateTime::currentDateTime();
        technical.code = "CORE_INITIALIZING";
        technical.message = "Core host initialization started";
        auto reloaded = technical;
        reloaded.code = "CONFIG_RELOADED";
        reloaded.message = "Configuration reloaded";
        auto network = technical;
        network.code = "NETWORK_CHANGED";
        network.message = "generation=2 previous=1 interfaces=71";
        auto cache = technical;
        cache.code = "DNS_CACHE_CLEARED";
        cache.message = "System DNS cache cleared";
        auto coreError = technical;
        coreError.code = "CORE_START_FAILED";
        coreError.message = "failed to initialize interception";
        coreError.error = true;
        auto trace = technical;
        trace.code = "DNS_CAPTURE";
        trace.message = "transport=udp name=example.com action=process";
        auto fastPath = trace;
        fastPath.code = "WINDIVERT_RULE_FAST_PATH";
        auto blocked = record("blocked");
        blocked.action = "block";
        auto bypassed = record("bypassed");
        bypassed.action = "bypass";
        panel.appendRecords({record("processed"),
                             record("query failed", true),
                             blocked,
                             bypassed,
                             technical,
                             reloaded,
                             network,
                             cache,
                             coreError,
                             trace,
                             fastPath});
        auto* display = panel.findChild<LogDisplay*>();
        QCOMPARE(display->recordCount(), 11);
        actionsMenu.actions()[2]->trigger(); // Process + technical events.
        QCOMPARE(display->recordCount(), 7);
        with->trigger(); // Clicking the active item hides technical events.
        QVERIFY(!only->isChecked() && !with->isChecked());
        QCOMPARE(panel.commandsView(), LogCommandsView::without_commands);
        QVERIFY(actionsMenu.menuAction()->isEnabled());
        QCOMPARE(display->recordCount(), 2);
        LogPanel hiddenReopened(nullptr, &settings);
        QCOMPARE(hiddenReopened.commandsView(), LogCommandsView::without_commands);
        QCOMPARE(hiddenReopened.shownActions(), QSet<QString>{"process"});
        QMenu hiddenActions, hiddenCommands;
        addLogActionFilterActions(&hiddenActions, hiddenReopened);
        addLogCommandFilterActions(&hiddenCommands, hiddenReopened, &hiddenActions);
        QVERIFY(!hiddenCommands.actions()[0]->isChecked());
        QVERIFY(!hiddenCommands.actions()[1]->isChecked());
        QVERIFY(hiddenActions.menuAction()->isEnabled());
        hiddenReopened.appendRecords({record("processed"), blocked, technical});
        QCOMPARE(hiddenReopened.findChild<LogDisplay*>()->recordCount(), 1);
        auto* input = panel.findChild<QLineEdit*>("logFilterInput");
        input->setText("err=\"*\"");
        QVERIFY(panel.applyFilter());
        QCOMPARE(display->recordCount(), 1); // Query failure, without CoreHost failure.
        input->clear();
        QVERIFY(panel.applyFilter());
        only->trigger();
        QVERIFY(only->isChecked() && !with->isChecked());
        QCOMPARE(display->recordCount(), 5);
        only->trigger(); // Only can also be unchecked without selecting With.
        QVERIFY(!only->isChecked() && !with->isChecked());
        QVERIFY(actionsMenu.menuAction()->isEnabled());
        QCOMPARE(display->recordCount(), 2);
        actionsMenu.actions()[0]->trigger(); // All actions still excludes technical events.
        QCOMPARE(display->recordCount(), 6);
        actionsMenu.actions()[2]->trigger();
        with->trigger();
        QVERIFY(with->isChecked() && !only->isChecked());
        QCOMPARE(display->recordCount(), 7);
        only->trigger();
        QVERIFY(only->isChecked() && !with->isChecked());
        QVERIFY(!actionsMenu.menuAction()->isEnabled());
        QCOMPARE(display->recordCount(), 5);
        QCOMPARE(panel.shownActions(), QSet<QString>{"process"});
        LogPanel reopened(nullptr, &settings);
        QCOMPARE(reopened.commandsView(), LogCommandsView::only);
        QCOMPARE(reopened.shownActions(), panel.shownActions());
        QMenu restoredActions, restoredCommands;
        addLogActionFilterActions(&restoredActions, reopened);
        addLogCommandFilterActions(&restoredCommands, reopened, &restoredActions);
        QVERIFY(restoredCommands.actions()[0]->isChecked());
        QVERIFY(!restoredActions.menuAction()->isEnabled());
        input->setText("err=\"*\"");
        QVERIFY(panel.applyFilter());
        QCOMPARE(display->recordCount(), 1);
        with->trigger();
        QVERIFY(with->isChecked() && !only->isChecked());
        QVERIFY(actionsMenu.menuAction()->isEnabled());
        QCOMPARE(display->recordCount(), 2);
        input->clear();
        QVERIFY(panel.applyFilter());
        QCOMPARE(display->recordCount(), 7);
        actionsMenu.actions()[0]->trigger();
        QCOMPARE(display->recordCount(), 11);
        only->trigger();
        panel.appendRecords({technical, record("new query"), trace});
        QCOMPARE(display->recordCount(), 6);
        for (const auto view : {LogView::compact, LogView::details, LogView::table}) {
            QVERIFY(panel.setLogView(view));
            QCOMPARE(display->recordCount(), 6);
        }
        panel.clear();
        QList<LogRecord> events;
        for (int i = 0; i < 2002; ++i)
            events << (i % 2 ? record("query") : technical);
        panel.appendRecords(events);
        QCOMPARE(display->recordCount(), 1000);
        panel.appendRecords({record("new query")});
        QCOMPARE(display->recordCount(), 999);
        with->trigger();
        QCOMPARE(display->recordCount(), 2000);
        with->trigger();
        QCOMPARE(display->recordCount(), 1001);
        panel.appendRecords({technical}); // Retained, but hidden until With is selected.
        QCOMPARE(display->recordCount(), 1000);
        with->trigger();
        QCOMPARE(display->recordCount(), 2000);
    }
    void immediateAutoScroll_data() {
        logViews_data();
    }
    void immediateAutoScroll() {
        QFETCH(int, mode);
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        LogPanel panel(nullptr, &settings);
        panel.resize(700, 240);
        panel.show();
        QVERIFY(panel.setLogView(static_cast<LogView>(mode)));
        QCoreApplication::processEvents();
        auto* display = panel.findChild<LogDisplay*>();
        auto* scroll = display->verticalScrollBar();
        QList<LogRecord> records;
        for (int i = 0; i < 100; ++i)
            records << record(QString("row %1").arg(i), i % 7 == 0);
        panel.appendRecords(records);
        QVERIFY(scroll->maximum() > 0);
        QCOMPARE(scroll->value(), scroll->maximum());
        const int previousMaximum = scroll->maximum();
        panel.appendRecords({record("last error", true)});
        // These assertions run without timers, processEvents or QTRY waiting.
        QVERIFY(scroll->maximum() > previousMaximum);
        QCOMPARE(scroll->value(), scroll->maximum());
        const auto visibleLastRecord = [&] {
            if (panel.logView() == LogView::table) {
                auto* table = panel.findChild<QTableWidget*>("logTable");
                return table->visualItemRect(table->item(table->rowCount() - 1, 0)).bottom() <=
                       table->viewport()->height();
            }
            if (panel.logView() == LogView::details) {
                auto* tree = panel.findChild<QTreeWidget*>("logDetailsTree");
                return tree->visualItemRect(tree->topLevelItem(tree->topLevelItemCount() - 1))
                           .bottom() <= tree->viewport()->height();
            }
            auto* text = panel.findChild<QPlainTextEdit*>("logDisplay");
            QTextCursor cursor(text->document()->lastBlock().previous());
            return text->cursorRect(cursor).bottom() <= text->viewport()->height();
        };
        QVERIFY(visibleLastRecord());
        QCoreApplication::processEvents();
        QCOMPARE(scroll->value(), scroll->maximum());
        scroll->setValue(scroll->maximum() / 3);
        const int readingPosition = scroll->value();
        panel.appendRecords({record("do not jump"), record("another row")});
        QCOMPARE(scroll->value(), readingPosition);
        QCoreApplication::processEvents();
        QCOMPARE(scroll->value(), readingPosition);
        scroll->setValue(scroll->maximum());
        if (panel.logView() == LogView::details) {
            auto* tree = panel.findChild<QTreeWidget*>("logDetailsTree");
            tree->topLevelItem(0)->setExpanded(true);
            tree->doItemsLayout();
            scroll->setValue(scroll->maximum());
        }
        panel.appendRecords({record("follow resumes")});
        QCOMPARE(scroll->value(), scroll->maximum());
        QVERIFY(visibleLastRecord());
        QCoreApplication::processEvents();
        QCOMPARE(scroll->value(), scroll->maximum());
    }
    void inspectorScrollPosition_data() {
        logViews_data();
    }
    void inspectorScrollPosition() {
        QFETCH(int, mode);
        QTemporaryDir directory;
        QSettings settings(directory.filePath("settings.ini"), QSettings::IniFormat);
        LogPanel panel(nullptr, &settings);
        panel.resize(700, 420);
        panel.show();
        QVERIFY(panel.setLogView(static_cast<LogView>(mode)));
        QCoreApplication::processEvents();
        auto* display = panel.findChild<LogDisplay*>();
        auto* toggle = panel.findChild<QToolButton*>("logDetailsToggle");
        auto* inspector = panel.findChild<QPlainTextEdit*>("logRecordDetails");
        auto* scroll = display->verticalScrollBar();
        auto* text = panel.findChild<QPlainTextEdit*>("logDisplay");
        auto* table = panel.findChild<QTableWidget*>("logTable");
        auto* tree = panel.findChild<QTreeWidget*>("logDetailsTree");
        auto* viewport = mode == int(LogView::table)     ? table->viewport()
                         : mode == int(LogView::details) ? tree->viewport()
                                                         : text->viewport();
        QList<LogRecord> rows;
        for (int i = 0; i < 100; ++i)
            rows << record(QString("row %1").arg(i));
        panel.appendRecords(rows);
        if (mode == int(LogView::table))
            table->setCurrentCell(70, 0);
        else if (mode == int(LogView::details))
            tree->setCurrentItem(tree->topLevelItem(70));
        else
            text->setTextCursor(QTextCursor(text->document()->findBlockByNumber(70)));
        const auto selectedDetails = inspector->toPlainText();
        QVERIFY(selectedDetails.contains("row 70"));
        scroll->setValue(scroll->maximum());
        const int fullHeight = viewport->height();
        const auto checkBottom = [&] {
            QCOMPARE(scroll->value(), scroll->maximum());
            const QRect lastRow =
                mode == int(LogView::table)
                    ? table->visualItemRect(table->item(table->rowCount() - 1, 0))
                : mode == int(LogView::details)
                    ? tree->visualItemRect(tree->topLevelItem(tree->topLevelItemCount() - 1))
                    : text->cursorRect(QTextCursor(text->document()->lastBlock().previous()));
            QVERIFY(lastRow.top() >= 0);
            QVERIFY(lastRow.bottom() <= viewport->height());
            QCOMPARE(inspector->toPlainText(), selectedDetails);
        };
        toggle->click();
        QVERIFY(inspector->isVisible());
        QVERIFY(viewport->height() < fullHeight);
        // Geometry and scroll must be correct before the next event/paint cycle.
        checkBottom();
        QCoreApplication::processEvents();
        checkBottom();
        panel.appendRecords({record("new while open")});
        checkBottom();
        toggle->click();
        QVERIFY(!inspector->isVisible());
        QCOMPARE(viewport->height(), fullHeight);
        checkBottom();
        QCoreApplication::processEvents();
        checkBottom();
        scroll->setValue(scroll->maximum() / 3);
        const int readingPosition = scroll->value();
        toggle->click();
        QCOMPARE(scroll->value(), readingPosition);
        QCoreApplication::processEvents();
        QCOMPARE(scroll->value(), readingPosition);
        panel.appendRecords({record("do not jump while open")});
        QCOMPARE(scroll->value(), readingPosition);
        scroll->setValue(scroll->value() + 2);
        const int movedPosition = scroll->value();
        toggle->click();
        QCOMPARE(scroll->value(), movedPosition);
        QCoreApplication::processEvents();
        QCOMPARE(scroll->value(), movedPosition);
        QCOMPARE(inspector->toPlainText(), selectedDetails);
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
        button(dialog, "Add")->click();
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
