// The dialogs are internal to this translation unit; include them to exercise the
// real widgets without exposing test-only APIs or constructing NativeDnsWindow.
#include "../NativeDNS.GUI/qt_app.cpp"
#include <QtTest>
#include <QScrollBar>

class RulesGuiTests final : public QObject {
    Q_OBJECT

private:
    nd::Config config_;
    std::unique_ptr<RulesDialog> dialog_;
    QTableView* table_ = nullptr;
    int commits_ = 0;
    bool acceptChanges_ = true;

    void click(int row, int column, Qt::KeyboardModifiers modifiers = Qt::NoModifier) {
        QTest::mouseClick(table_->viewport(),
                          Qt::LeftButton,
                          modifiers,
                          table_->visualRect(table_->model()->index(row, column)).center());
    }
    QList<int> selectedRows() const {
        QList<int> rows;
        for (const auto& index : table_->selectionModel()->selectedRows())
            rows.push_back(index.row());
        std::sort(rows.begin(), rows.end());
        return rows;
    }
    QList<QComboBox*> editors() const {
        QList<QComboBox*> result;
        for (auto* combo : table_->findChildren<QComboBox*>())
            if (combo->isVisible())
                result.push_back(combo);
        return result;
    }
    QPushButton* button(const char* text) const {
        for (auto* value : dialog_->findChildren<QPushButton*>())
            if (value->text() == uiText(text))
                return value;
        return nullptr;
    }
    void choose(uint32_t value) {
        QTRY_COMPARE(editors().size(), 1);
        auto* combo = editors().front();
        QTRY_VERIFY(combo->view()->isVisible());
        const int row = combo->findData(value);
        QVERIFY(row >= 0);
        const auto index = combo->model()->index(row, combo->modelColumn());
        combo->view()->scrollTo(index);
        QTest::mouseClick(combo->view()->viewport(),
                          Qt::LeftButton,
                          Qt::NoModifier,
                          combo->view()->visualRect(index).center());
        QTRY_VERIFY(editors().isEmpty());
        QCoreApplication::processEvents();
    }
    uint32_t value(int row, int column) const {
        return table_->model()->index(row, column).data(Qt::UserRole).toUInt();
    }
    static QList<int> columnWidths(QHeaderView* header) {
        QList<int> widths;
        for (int column = 0; column < header->count(); ++column)
            widths.push_back(header->sectionSize(column));
        return widths;
    }
    static void dragDivider(QHeaderView* header, int column, int distance) {
        const QPoint start(header->sectionViewportPosition(column) + header->sectionSize(column) -
                               1,
                           header->height() / 2);
        QTest::mouseMove(header->viewport(), start);
        QTest::mousePress(header->viewport(), Qt::LeftButton, Qt::NoModifier, start);
        QTest::mouseMove(header->viewport(), start + QPoint(distance, 0));
        QTest::mouseRelease(
            header->viewport(), Qt::LeftButton, Qt::NoModifier, start + QPoint(distance, 0));
    }

private slots:
    void init() {
        commits_ = 0;
        acceptChanges_ = true;
        config_ = nd::default_config();
        for (uint32_t id : {10u, 20u}) {
            nd::Server server;
            server.id = id;
            server.name = "Server " + std::to_string(id);
            server.ip = "127.0.0.1";
            config_.servers.push_back(server);
        }
        for (uint32_t id : {2u, 3u, 4u, 5u}) {
            nd::Rule rule;
            rule.id = id;
            rule.name = "Rule " + std::to_string(id);
            rule.patterns = {"example.com"};
            rule.action = id == 4   ? nd::Action::block
                          : id == 5 ? nd::Action::bypass
                                    : nd::Action::process;
            rule.server_id = id == 2 ? 10 : id == 3 ? 20 : 0;
            rule.enabled = id != 3;
            rule.block_mode = nd::BlockMode::refused;
            config_.rules.insert(config_.rules.end() - 1, rule);
        }
        nd::validate(config_);
        dialog_ = std::make_unique<RulesDialog>(nullptr, config_, [this] {
            ++commits_;
            return acceptChanges_;
        });
        table_ = dialog_->findChild<QTableView*>();
        QVERIFY(table_);
        dialog_->show();
        QTRY_VERIFY(table_->isEnabled());
        QCOMPARE(table_->model()->rowCount(), 5);
    }
    void cleanup() {
        dialog_.reset();
        table_ = nullptr;
        QCoreApplication::processEvents();
    }
    void ctrlShiftSelectionAndPopup() {
        click(0, 1);
        click(2, 3, Qt::ControlModifier);
        QCOMPARE(selectedRows(), QList<int>({0, 2}));
        QVERIFY(editors().isEmpty());
        click(4, 3, Qt::ShiftModifier);
        QCOMPARE(selectedRows(), QList<int>({0, 2, 3, 4}));
        QVERIFY(editors().isEmpty());
        click(3, 3, Qt::ControlModifier);
        QCOMPARE(selectedRows(), QList<int>({0, 2, 4}));
        click(2, 3);
        QTRY_COMPARE(editors().size(), 1);
        QCOMPARE(selectedRows(), QList<int>({0, 2, 4}));
        QCOMPARE(editors().front()->geometry(), table_->visualRect(table_->model()->index(2, 3)));
        choose(1);
        QCOMPARE(selectedRows(), QList<int>({0, 2, 4}));
        QCOMPARE(value(0, 3), 1u);
        QCOMPARE(value(2, 3), 1u);
        QCOMPARE(value(4, 3), 1u);
        QCOMPARE(value(1, 3), 0u);
    }
    void mixedServerSelectionAndSameValue() {
        click(0, 1);
        click(4, 1, Qt::ShiftModifier);
        const auto before = config_;
        click(0, 4);
        QTRY_COMPARE(editors().size(), 1);
        QCOMPARE(editors().front()->geometry(), table_->visualRect(table_->model()->index(0, 4)));
        choose(10); // Already selected in the clicked row, but different elsewhere.
        QCOMPARE(selectedRows(), QList<int>({0, 1, 2, 3, 4}));
        QCOMPARE(value(0, 4), 10u);
        QCOMPARE(value(1, 4), 10u);
        QCOMPARE(value(2, 4), 0u);
        QCOMPARE(value(3, 4), 0u);
        QCOMPARE(value(4, 4), 10u);
        QCOMPARE(config_, before); // No publication until OK.
        QVERIFY(!button("Edit...")->isEnabled());
        QVERIFY(!button("Remove")->isEnabled());
        QTest::mouseClick(button("OK"), Qt::LeftButton);
        QCOMPARE(commits_, 1);
        QCOMPARE(dialog_->result(), int(QDialog::Accepted));
        nd::validate(config_);
        QCOMPARE(config_.rules[1].server_id, 10u); // Disabled rules are editable too.
        QVERIFY(!config_.rules[1].enabled);
        QCOMPARE(config_.rules[2], before.rules[2]);
        QCOMPARE(config_.rules[3], before.rules[3]);
        QVERIFY(config_.rules.back().is_default && config_.rules.back().enabled);
    }
    void batchAction_data() {
        QTest::addColumn<uint32_t>("action");
        QTest::newRow("block") << uint32_t(2);
        QTest::newRow("bypass") << uint32_t(1);
    }
    void batchAction() {
        QFETCH(uint32_t, action);
        click(0, 1);
        click(4, 1, Qt::ShiftModifier);
        click(0, 3);
        choose(action);
        for (int row = 0; row < 5; ++row) {
            QCOMPARE(value(row, 3), action);
            QCOMPARE(value(row, 4), 0u);
            QVERIFY(!(table_->model()->index(row, 4).flags() & Qt::ItemIsEditable));
        }
        click(0, 4); // Inapplicable server cells retain selection but cannot open editors.
        QVERIFY(editors().isEmpty());
        QCOMPARE(selectedRows().size(), 5);
        click(2, 3);
        choose(0);
        for (int row = 0; row < 5; ++row) {
            QCOMPARE(value(row, 3), 0u);
            QCOMPARE(value(row, 4), 0u);
            QVERIFY(table_->model()->index(row, 4).flags() & Qt::ItemIsEditable);
        }
        click(4, 4);
        choose(20);
        QTest::mouseClick(button("OK"), Qt::LeftButton);
        QCOMPARE(commits_, 1);
        nd::validate(config_);
        for (const auto& rule : config_.rules) {
            QCOMPARE(rule.action, nd::Action::process);
            QCOMPARE(rule.server_id, 20u);
        }
        QCOMPARE(config_.rules[2].block_mode, nd::BlockMode::refused);
    }
    void sameActionAndUnselectedClick() {
        click(0, 1);
        click(2, 1, Qt::ControlModifier);
        click(0, 3);
        choose(0);
        QCOMPARE(value(2, 3), 0u);
        QCOMPARE(selectedRows(), QList<int>({0, 2}));
        click(1, 4); // Unselected row gets its own edit and replaces the selection.
        QCOMPARE(selectedRows(), QList<int>({1}));
        choose(0);
        QCOMPARE(value(0, 4), 10u);
        QCOMPARE(value(1, 4), 0u);
        QVERIFY(button("Edit...")->isEnabled());
        QVERIFY(button("Clone")->isEnabled());
    }
    void cancelPopupAndDiscard() {
        click(0, 1);
        click(4, 1, Qt::ShiftModifier);
        click(0, 4);
        QTRY_COMPARE(editors().size(), 1);
        auto* combo = editors().front();
        QTRY_VERIFY(combo->view()->isVisible());
        QTest::keyClick(combo->view(), Qt::Key_Escape);
        QTRY_VERIFY(!combo->view()->isVisible());
        button("Close")->setFocus(); // Focus-loss commits must also leave the batch untouched.
        QCoreApplication::processEvents();
        QCOMPARE(value(1, 4), 20u);
        QCOMPARE(value(4, 4), 0u);
        click(0, 3);
        choose(2);
        const auto before = config_;
        QTest::mouseClick(button("Close"), Qt::LeftButton);
        QCOMPARE(config_, before);
        QCOMPARE(commits_, 0);
    }
    void failedCommitRetainsEdits() {
        click(0, 1);
        click(1, 1, Qt::ControlModifier);
        click(0, 4);
        choose(0);
        const auto before = config_;
        acceptChanges_ = false;
        QTest::mouseClick(button("OK"), Qt::LeftButton);
        QCOMPARE(commits_, 1);
        QCOMPARE(config_, before);
        QVERIFY(dialog_->isVisible());
        QCOMPARE(selectedRows(), QList<int>({0, 1}));
        QCOMPARE(value(0, 4), 0u);
        QCOMPARE(value(1, 4), 0u);
        acceptChanges_ = true;
        QTest::mouseClick(button("OK"), Qt::LeftButton);
        QCOMPARE(commits_, 2);
        QCOMPARE(config_.rules[0].server_id, 0u);
        QCOMPARE(config_.rules[1].server_id, 0u);
    }
    void serverHeadersResizable() {
        ServerDialog servers(nullptr, config_, [] { return true; });
        servers.show();
        auto* table = servers.findChild<QTableWidget*>();
        QVERIFY(table);
        auto* header = table->horizontalHeader();
        QTRY_COMPARE(header->length(), table->viewport()->width());
        servers.resize(servers.width() + 240, servers.height());
        QCoreApplication::processEvents();
        QTRY_COMPARE(header->length(), table->viewport()->width());
        const QList<int> minimums{120, 85, 160, 95, 70};
        for (int column = 0; column < 4; ++column) {
            const auto before = columnWidths(header);
            dragDivider(header, column, 30);
            auto after = columnWidths(header);
            QVERIFY(after[column] >= before[column]);
            QCOMPARE(after[column] + after[column + 1], before[column] + before[column + 1]);
            QCOMPARE(header->length(), table->viewport()->width());
            dragDivider(header, column, -10000);
            after = columnWidths(header);
            QVERIFY(after[column] >= minimums[column]);
            QVERIFY(after[column] <= before[column]);
            QCOMPARE(header->length(), table->viewport()->width());
            const auto atMinimum = after;
            dragDivider(header, column, -10000);
            QCOMPARE(columnWidths(header), atMinimum);
            dragDivider(header, column, 10000);
            after = columnWidths(header);
            QVERIFY(after[column + 1] >= minimums[column + 1]);
            QCOMPARE(header->length(), table->viewport()->width());
            const auto atMaximum = after;
            dragDivider(header, column, 10000);
            QCOMPARE(columnWidths(header), atMaximum);
        }
        const auto resized = columnWidths(header);
        dragDivider(header, 4, 10000); // The outside edge cannot move beyond the table.
        QCOMPARE(columnWidths(header), resized);
        table->selectRow(0);
        for (auto* candidate : servers.findChildren<QPushButton*>())
            if (candidate->text() == uiText("Clone"))
                QTest::mouseClick(candidate, Qt::LeftButton);
        QCOMPARE(table->rowCount(), 3);
        QCOMPARE(columnWidths(header), resized);
        servers.resize(1, servers.height());
        QCoreApplication::processEvents();
        QTRY_COMPARE(header->length(), table->viewport()->width());
        for (int column = 0; column < 5; ++column)
            QVERIFY(header->sectionSize(column) >= minimums[column]);
        QVERIFY(!table->horizontalScrollBar()->isVisible());
    }
    void rulesHeadersResizableWithFixedActions() {
        auto* header = table_->horizontalHeader();
        QTRY_COMPARE(header->length(), table_->viewport()->width());
        const auto initial = columnWidths(header);
        dialog_->resize(dialog_->width() + 240, dialog_->height());
        QCoreApplication::processEvents();
        QTRY_COMPARE(header->length(), table_->viewport()->width());
        const QList<int> minimums{75, 140, 180, 100, 100};
        for (int column = 0; column < 2; ++column) {
            const auto before = columnWidths(header);
            dragDivider(header, column, 30);
            auto after = columnWidths(header);
            QVERIFY(after[column] >= before[column]);
            QCOMPARE(after[column] + after[column + 1], before[column] + before[column + 1]);
            QCOMPARE(header->length(), table_->viewport()->width());
            dragDivider(header, column, -10000);
            QVERIFY(header->sectionSize(column) >= minimums[column]);
            QCOMPARE(header->length(), table_->viewport()->width());
            const auto atMinimum = columnWidths(header);
            dragDivider(header, column, -10000);
            QCOMPARE(columnWidths(header), atMinimum);
            dragDivider(header, column, 10000);
            QVERIFY(header->sectionSize(column + 1) >= minimums[column + 1]);
            QCOMPARE(header->length(), table_->viewport()->width());
            const auto atMaximum = columnWidths(header);
            dragDivider(header, column, 10000);
            QCOMPARE(columnWidths(header), atMaximum);
        }
        for (int column : {2, 3, 4}) {
            const auto before = columnWidths(header);
            dragDivider(header, column, 10000);
            QCOMPARE(columnWidths(header), before);
            const QPoint border(header->sectionViewportPosition(column) +
                                    header->sectionSize(column) - 1,
                                header->height() / 2);
            QTest::mouseDClick(header->viewport(), Qt::LeftButton, Qt::NoModifier, border);
            QCOMPARE(columnWidths(header), before);
        }
        const auto resized = columnWidths(header);
        click(0, 1);
        click(1, 1, Qt::ControlModifier);
        click(0, 3);
        choose(2);
        QCOMPARE(columnWidths(header), resized);
        dialog_->resize(1, dialog_->height());
        QCoreApplication::processEvents();
        QTRY_COMPARE(header->length(), table_->viewport()->width());
        for (int column = 0; column < 5; ++column)
            QVERIFY(header->sectionSize(column) >= minimums[column]);
        QCOMPARE(header->sectionSize(3), initial[3]);
        QCOMPARE(header->sectionSize(4), initial[4]);
        QVERIFY(!table_->horizontalScrollBar()->isVisible());
    }
    void headersTrackVerticalScrollbar() {
        auto many = config_;
        for (uint32_t id = 100; id < 140; ++id) {
            auto server = many.servers.front();
            server.id = id;
            many.servers.push_back(server);
            auto rule = many.rules.front();
            rule.id = id;
            many.rules.insert(many.rules.end() - 1, rule);
        }
        RulesDialog rules(nullptr, many, [] { return true; });
        ServerDialog servers(nullptr, many, [] { return true; });
        rules.show();
        servers.show();
        const QList<QTableView*> tables{rules.findChild<QTableView*>(),
                                        servers.findChild<QTableWidget*>()};
        for (auto* table : tables) {
            QVERIFY(table);
            QTRY_VERIFY(table->isEnabled());
            QTRY_VERIFY(table->verticalScrollBar()->isVisible());
            QTRY_COMPARE(table->horizontalHeader()->length(), table->viewport()->width());
        }
        const int actionWidth = tables.front()->columnWidth(3);
        const int serverWidth = tables.front()->columnWidth(4);
        rules.resize(rules.width(), 1600);
        servers.resize(servers.width(), 1600);
        for (auto* table : tables) {
            QTRY_VERIFY(!table->verticalScrollBar()->isVisible());
            QTRY_COMPARE(table->horizontalHeader()->length(), table->viewport()->width());
        }
        QCOMPARE(tables.front()->columnWidth(3), actionWidth);
        QCOMPARE(tables.front()->columnWidth(4), serverWidth);
    }
    void serverClone_data() {
        QTest::addColumn<bool>("save");
        QTest::newRow("save") << true;
        QTest::newRow("discard") << false;
    }
    void serverClone() {
        QFETCH(bool, save);
        auto& source = config_.servers.front();
        source.protocol = nd::Protocol::doh;
        source.enabled = false;
        source.dnssec_supported = true;
        source.port = 443;
        source.hostname = "dns.example.com";
        source.url = "https://dns.example.com/dns-query";
        source.timeout_ms = 6200;
        source.fallback_ids = {20};
        source.bootstrap = {"127.0.0.1", "::1"};
        source.hashes = {"certificate-pin"};
        source.metadata = {{"label", "custom server"}};
        nd::validate(config_);
        const auto before = config_;
        ServerDialog servers(nullptr, config_, [this] {
            ++commits_;
            return true;
        });
        servers.show();
        auto* table = servers.findChild<QTableWidget*>();
        QVERIFY(table);
        const auto findButton = [&servers](const char* text) -> QPushButton* {
            for (auto* candidate : servers.findChildren<QPushButton*>())
                if (candidate->text() == uiText(text))
                    return candidate;
            return nullptr;
        };
        auto* clone = findButton("Clone");
        QVERIFY(clone);
        QVERIFY(!clone->isEnabled());
        const auto select = [table](int row, Qt::KeyboardModifiers modifiers) {
            QTest::mouseClick(table->viewport(),
                              Qt::LeftButton,
                              modifiers,
                              table->visualRect(table->model()->index(row, 0)).center());
        };
        select(0, Qt::NoModifier);
        QVERIFY(clone->isEnabled());
        select(1, Qt::ControlModifier);
        QVERIFY(!clone->isEnabled());
        select(1, Qt::ControlModifier); // Current row can differ from the selected row.
        QVERIFY(clone->isEnabled());
        QTest::mouseClick(clone, Qt::LeftButton);
        QCOMPARE(table->rowCount(), 3);
        QCOMPARE(table->selectionModel()->selectedRows().size(), 1);
        QCOMPARE(table->selectionModel()->selectedRows().front().row(), 2);
        QCOMPARE(table->currentRow(), 2); // Edit must operate on the new copy.
        QCOMPARE(table->item(2, 0)->text(), q(source.name + " (copy)"));
        QCOMPARE(table->item(2, 3)->text(), uiText("Not tested"));
        QCOMPARE(table->item(2, 4)->text(), QStringLiteral("—"));
        QCOMPARE(config_, before);
        QCoreApplication::processEvents();
        QVERIFY(findButton("Edit...")->geometry().bottom() < clone->geometry().top());
        QVERIFY(clone->geometry().bottom() < findButton("Remove")->geometry().top());
        QTest::mouseClick(findButton(save ? "OK" : "Close"), Qt::LeftButton);
        QCOMPARE(commits_, save ? 1 : 0);
        if (save) {
            QCOMPARE(config_.servers.size(), size_t(3));
            auto expected = before.servers.front();
            expected.id = 21;
            expected.name += " (copy)";
            QCOMPARE(config_.servers.back(), expected);
            QCOMPARE(config_.servers[0], before.servers[0]);
            QCOMPARE(config_.servers[1], before.servers[1]);
            QCOMPARE(config_.rules, before.rules);
            nd::validate(config_);
        } else
            QCOMPARE(config_, before);
    }
};

QTEST_MAIN(RulesGuiTests)
#include "rules_gui_tests.moc"
