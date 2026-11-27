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
    void choose(qulonglong value) {
        QTRY_COMPARE(editors().size(), 1);
        auto* combo = editors().front();
        QTRY_VERIFY(combo->view()->isVisible());
        const int row = combo->findData(QVariant::fromValue(value));
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
    qulonglong value(int row, int column) const {
        return table_->model()->index(row, column).data(Qt::UserRole).toULongLong();
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
    void statusPollingToleratesSchedulerDelay() {
#ifdef _WIN32
        const auto endpoint = std::string(R"(\\.\pipe\NativeDNS.GuiPollTest.)") +
                              std::to_string(nd::platform::process_id());
#else
        const auto endpoint = std::string("/tmp/nativedns-gui-poll-") +
                              std::to_string(nd::platform::process_id()) + ".sock";
#endif
        nd::PipeServer delayed(endpoint, [](nd::IpcOperation, const std::string&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            return nd::IpcResponse{0, "RUNNING"};
        });
        delayed.start();
        QCOMPARE(readCoreStatus(endpoint).payload, std::string("RUNNING"));
        delayed.stop();
    }

    void coreControlErrorActions() {
        const QString diagnostics = "IPC_CONNECT: Win32=2\nPID=123; birth=456";
        QPointer<QMessageBox> dialog = coreControlFailureDialog(nullptr, diagnostics);
        QCOMPARE(dialog->icon(), QMessageBox::Critical);
        QCOMPARE(dialog->buttons().size(), 2);
        QVERIFY(dialog->informativeText().contains(diagnostics));
        auto* close = dialog->findChild<QPushButton*>("closeControlError");
        auto* terminate = dialog->findChild<QPushButton*>("terminateApplication");
        QVERIFY(close && terminate);
        QCOMPARE(dialog->defaultButton(), close);
        QCOMPARE(dialog->escapeButton(), close);
        QCOMPARE(dialog->buttonRole(terminate), QMessageBox::DestructiveRole);
        QString action;
        connect(dialog, &QMessageBox::buttonClicked, this, [&action](QAbstractButton* button) {
            action = button->objectName();
        });
        dialog->show();
        close->click();
        QCOMPARE(action, QString("closeControlError"));
        QTRY_VERIFY(dialog.isNull());

        dialog = coreControlFailureDialog(nullptr, diagnostics);
        connect(dialog, &QMessageBox::buttonClicked, this, [&action](QAbstractButton* button) {
            action = button->objectName();
        });
        dialog->show();
        dialog->findChild<QPushButton*>("terminateApplication")->click();
        QCOMPARE(action, QString("terminateApplication"));
        QTRY_VERIFY(dialog.isNull());
    }
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
    void enabledCheckboxes_data() {
        QTest::addColumn<bool>("save");
        QTest::newRow("save") << true;
        QTest::newRow("discard") << false;
    }
    void enabledCheckboxes() {
        QFETCH(bool, save);
        const auto before = config_;
        for (int row = 0; row < table_->model()->rowCount() - 1; ++row) {
            const auto index = table_->model()->index(row, 0);
            const auto initial = config_.rules[static_cast<size_t>(row)].enabled
                                     ? Qt::Checked
                                     : Qt::Unchecked;
            const auto toggled = initial == Qt::Checked ? Qt::Unchecked : Qt::Checked;
            QVERIFY(index.data(Qt::DisplayRole).toString().isEmpty());
            QCOMPARE(index.data(Qt::CheckStateRole).toInt(), int(initial));
            QVERIFY(index.flags() & Qt::ItemIsUserCheckable);
            const auto rect = table_->visualRect(index);
            QTest::mouseClick(table_->viewport(), Qt::LeftButton, Qt::NoModifier,
                              QPoint(rect.left() + 3, rect.center().y()));
            QCOMPARE(index.data(Qt::CheckStateRole).toInt(), int(toggled));
            click(row, 0);
            QCOMPARE(index.data(Qt::CheckStateRole).toInt(), int(initial));
            QTest::mouseClick(table_->viewport(), Qt::LeftButton, Qt::NoModifier,
                              QPoint(rect.right() - 3, rect.center().y()));
            QCOMPARE(index.data(Qt::CheckStateRole).toInt(), int(toggled));
            table_->setCurrentIndex(index);
            table_->setFocus();
            QTest::keyClick(table_, Qt::Key_Space);
            QCOMPARE(index.data(Qt::CheckStateRole).toInt(), int(initial));
            QTest::keyClick(table_, Qt::Key_Space);
            QCOMPARE(index.data(Qt::CheckStateRole).toInt(), int(toggled));
            QKeyEvent repeated(QEvent::KeyPress, Qt::Key_Space, Qt::NoModifier, {}, true);
            QApplication::sendEvent(table_, &repeated);
            QCOMPARE(index.data(Qt::CheckStateRole).toInt(), int(toggled));
            QVERIFY(editors().isEmpty());
        }
        const int last = table_->model()->rowCount() - 1;
        const auto defaultIndex = table_->model()->index(last, 0);
        QVERIFY(!defaultIndex.flags().testFlag(Qt::ItemIsUserCheckable));
        click(last, 0);
        QTest::keyClick(table_, Qt::Key_Space);
        QCOMPARE(defaultIndex.data(Qt::CheckStateRole).toInt(), int(Qt::Checked));
        QVERIFY(!table_->model()->setData(defaultIndex, Qt::Unchecked, Qt::CheckStateRole));
        QCOMPARE(config_, before);
        QTest::mouseClick(button(save ? "OK" : "Close"), Qt::LeftButton);
        QCOMPARE(commits_, save ? 1 : 0);
        auto expected = before;
        if (save)
            for (auto& rule : expected.rules)
                if (!rule.is_default)
                    rule.enabled = !rule.enabled;
        QCOMPARE(config_, expected);
        nd::validate(config_);
    }
    void checkboxChangesOnlyClickedRuleAndSurvivesFailedCommit() {
        const auto before = config_;
        click(0, 1);
        click(2, 1, Qt::ControlModifier);
        QCOMPARE(selectedRows(), QList<int>({0, 2}));
        click(0, 0);
        QCOMPARE(table_->model()->index(0, 0).data(Qt::CheckStateRole).toInt(), int(Qt::Unchecked));
        QCOMPARE(table_->model()->index(2, 0).data(Qt::CheckStateRole).toInt(), int(Qt::Checked));
        acceptChanges_ = false;
        QTest::mouseClick(button("OK"), Qt::LeftButton);
        QCOMPARE(config_, before);
        QCOMPARE(commits_, 1);
        QVERIFY(dialog_->isVisible());
        QCOMPARE(table_->model()->index(0, 0).data(Qt::CheckStateRole).toInt(), int(Qt::Unchecked));
        acceptChanges_ = true;
        QTest::mouseClick(button("OK"), Qt::LeftButton);
        QCOMPARE(commits_, 2);
        auto expected = before;
        expected.rules[0].enabled = false;
        QCOMPARE(config_, expected);
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
        QVERIFY(!button("Edit")->isEnabled());
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
        QVERIFY(button("Edit")->isEnabled());
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
        QVERIFY(findButton("Edit")->geometry().bottom() < clone->geometry().top());
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
    void serverPoolsDialogAndScrollableRulesDropdown() {
        applyUiTheme(*qApp, false);
        // 1) Exercise ServerPoolsDialog with live status fetcher (green RTT + red failed)
        auto poolCfg = config_;
        ServerPoolsDialog poolsDialog(
            nullptr,
            poolCfg,
            [this] {
                ++commits_;
                return true;
            },
            []() -> std::vector<nd::PoolStatusSnapshot> {
                nd::PoolStatusSnapshot snap;
                snap.pool_id = 1;
                snap.active_server_id = 10;
                snap.members = {
                    {10, nd::PoolMemberHealth::healthy, 23.0, {}, 1000},
                    {20, nd::PoolMemberHealth::failed, 0.0, "TIMEOUT", 1000},
                };
                return {snap};
            });
        poolsDialog.show();
        auto* sourceTable = poolsDialog.findChild<QTableWidget*>("poolSourceServersTable");
        auto* tree = poolsDialog.findChild<QTreeWidget*>("serverPoolsTree");
        auto* createBtn = poolsDialog.findChild<QPushButton*>("createPoolButton");
        auto* typeBtn = poolsDialog.findChild<QPushButton*>("poolTypeButton");
        auto* removeBtn = poolsDialog.findChild<QPushButton*>("removePoolButton");
        QVERIFY(sourceTable && tree && createBtn && typeBtn && removeBtn);
        QCOMPARE(sourceTable->columnCount(), 3);
        QCOMPARE(sourceTable->rowCount(), 2);
        QVERIFY(!typeBtn->isEnabled() && !removeBtn->isEnabled());

        QTest::mouseClick(createBtn, Qt::LeftButton);
        QCOMPARE(tree->topLevelItemCount(), 1);
        QVERIFY(tree->topLevelItem(0)->text(0).contains("New Pool [Redundancy]"));
        QVERIFY(typeBtn->isEnabled() && removeBtn->isEnabled());

        QVERIFY(poolsDialog.addServersToPool(1, {10, 20}));
        QCOMPARE(tree->topLevelItem(0)->childCount(), 2);
        // Wait for async live status poll to colorize the members.
        QTRY_VERIFY(tree->topLevelItem(0)->child(0)->text(0).startsWith("23 "));

        for (auto* candidate : poolsDialog.findChildren<QPushButton*>()) {
            if (candidate->text() == uiText("OK")) {
                QTest::mouseClick(candidate, Qt::LeftButton);
                break;
            }
        }
        QCOMPARE(commits_, 1);
        QCOMPARE(poolCfg.pools.size(), size_t(1));
        QCOMPARE(poolCfg.pools.front().server_ids, (std::vector<uint32_t>{10, 20}));

        // 2) Add many servers (including a long name) so the Rules dropdown requires scrolling,
        // widens to display full server names, and fits inside the screen.
        for (uint32_t id = 100; id < 135; ++id) {
            nd::Server extra;
            extra.id = id;
            extra.name = id == 100 ? "Bezmezhau #2 DoH (Long Server Name)"
                                   : "Extra Server " + std::to_string(id);
            extra.ip = "127.0.0.1";
            poolCfg.servers.push_back(extra);
        }
        nd::validate(poolCfg);
        RulesDialog rulesDlg(nullptr, poolCfg, [] { return true; });
        rulesDlg.show();
        auto* rulesTable = rulesDlg.findChild<QTableView*>();
        QVERIFY(rulesTable);
        QTRY_VERIFY(rulesTable->isEnabled());

        // Existing single-server row should render with "S| " prefix.
        QCOMPARE(rulesTable->model()->index(0, 4).data(Qt::DisplayRole).toString(),
                 QString("S| Server 10"));

        // Open dropdown on row 0, column 4 and verify order: P| -> separator -> Original/System -> S|
        QTest::mouseClick(rulesTable->viewport(),
                          Qt::LeftButton,
                          Qt::NoModifier,
                          rulesTable->visualRect(rulesTable->model()->index(0, 4)).center());
        QComboBox* combo = nullptr;
        QTRY_VERIFY([&] {
            for (auto* c : rulesTable->findChildren<QComboBox*>())
                if (c->isVisible()) {
                    combo = c;
                    return true;
                }
            return false;
        }());
        QTRY_VERIFY(combo->view()->isVisible());
        QCOMPARE(combo->itemText(0), QString("P| New Pool"));
        QCOMPARE(combo->itemData(0).toULongLong(), encodeRuleTarget(0, 1));
        QCOMPARE(combo->itemData(1, Qt::AccessibleDescriptionRole).toString(), QString("separator"));
        QCOMPARE(combo->itemText(2), uiText("Original/System"));
        QCOMPARE(combo->itemText(3), QString("S| Server 10"));

        // Scrollable, wide enough for full server names, & bounded within screen availableGeometry
        QTRY_VERIFY(combo->view()->verticalScrollBar()->maximum() > 0);
        const int expectedTextWidth =
            QFontMetrics(combo->view()->font())
                .horizontalAdvance(QStringLiteral("S| Bezmezhau #2 DoH (Long Server Name)"));
        QTRY_VERIFY(combo->view()->window()->width() > combo->width());
        QVERIFY(combo->view()->window()->width() >=
                expectedTextWidth + combo->style()->pixelMetric(QStyle::PM_ScrollBarExtent));
        if (auto* scr = QGuiApplication::primaryScreen()) {
            const QRect popupRect = combo->view()->window()->geometry();
            const QRect avail = scr->availableGeometry();
            QVERIFY(popupRect.top() >= avail.top() && popupRect.bottom() <= avail.bottom());
            QVERIFY(popupRect.left() >= avail.left() && popupRect.right() <= avail.right());
        }

        // Select pool P| New Pool
        const auto poolIdx = combo->model()->index(0, combo->modelColumn());
        combo->view()->scrollTo(poolIdx);
        QTest::mouseClick(combo->view()->viewport(),
                          Qt::LeftButton,
                          Qt::NoModifier,
                          combo->view()->visualRect(poolIdx).center());
        QTRY_COMPARE(rulesTable->model()->index(0, 4).data(Qt::DisplayRole).toString(),
                     QString("P| New Pool"));
        for (auto* candidate : rulesDlg.findChildren<QPushButton*>()) {
            if (candidate->text() == uiText("OK")) {
                QTest::mouseClick(candidate, Qt::LeftButton);
                break;
            }
        }
        QCOMPARE(poolCfg.rules[0].server_id, 0u);
        QCOMPARE(poolCfg.rules[0].pool_id, 1u);
    }
    void serverEditorValidationKeepsDialogOpenAndHighlightsFields() {
        nd::Server server;
        server.id = 99;
        server.name = "My Custom UDP";
        server.protocol = nd::Protocol::udp;

        bool sawDialogStayedOpen = false;
        bool sawIpHighlighted = false;
        bool sawClearedOnEdit = false;
        bool sawDohUrlHighlighted = false;
        bool sawPortHighlighted = false;

        QTimer::singleShot(0, [&] {
            auto* dlg = qobject_cast<QDialog*>(QApplication::activeModalWidget());
            if (!dlg || dlg->objectName() != "serverEditorDialog")
                return;
            auto* nameEdit = dlg->findChild<QLineEdit*>("serverNameEdit");
            auto* ipEdit = dlg->findChild<QLineEdit*>("serverIpEdit");
            auto* portEdit = dlg->findChild<QLineEdit*>("serverPortEdit");
            auto* urlEdit = dlg->findChild<QLineEdit*>("serverUrlEdit");
            auto* protoCombo = dlg->findChild<QComboBox*>("serverProtocolCombo");
            auto* box = dlg->findChild<QDialogButtonBox*>();
            auto* okBtn = box ? box->button(QDialogButtonBox::Ok) : nullptr;
            if (!nameEdit || !ipEdit || !portEdit || !urlEdit || !protoCombo || !okBtn)
                return;

            const auto clickOkAndDismissError = [okBtn](const std::function<void()>& afterDismiss) {
                QTimer::singleShot(0, [afterDismiss] {
                    if (auto* err = qobject_cast<QMessageBox*>(QApplication::activeModalWidget()))
                        err->accept();
                    QTimer::singleShot(0, afterDismiss);
                });
                okBtn->click();
            };

            // 1) Empty IP on UDP must keep editor open, keep entered Name, and highlight IP in red.
            nameEdit->setText("Preserved Server Name");
            clickOkAndDismissError(
                [&, clickOkAndDismissError, dlg, nameEdit, ipEdit, portEdit, urlEdit, protoCombo, okBtn] {
                    sawDialogStayedOpen =
                        dlg->isVisible() && nameEdit->text() == "Preserved Server Name";
                    sawIpHighlighted = ipEdit->property("validationError").toBool() &&
                                       ipEdit->styleSheet().contains("#d32f2f") &&
                                       !nameEdit->property("validationError").toBool();
                    // Editing the invalid field immediately clears the red border.
                    ipEdit->setText("1.1.1.1");
                    sawClearedOnEdit = !ipEdit->property("validationError").toBool() &&
                                       ipEdit->styleSheet().isEmpty();

                    // 2) Switching to DoH with empty URL highlights URL and keeps dialog open.
                    protoCombo->setCurrentIndex(protocolIndex(nd::Protocol::doh));
                    clickOkAndDismissError([&, clickOkAndDismissError, dlg, portEdit, urlEdit, okBtn] {
                        sawDohUrlHighlighted = dlg->isVisible() &&
                                               urlEdit->property("validationError").toBool() &&
                                               urlEdit->styleSheet().contains("#d32f2f");
                        urlEdit->setText("https://dns.example/dns-query");
                        portEdit->setText("99999");

                        // 3) Invalid port highlights Port and keeps dialog open.
                        clickOkAndDismissError([&, dlg, portEdit, okBtn] {
                            sawPortHighlighted = dlg->isVisible() &&
                                                 portEdit->property("validationError").toBool() &&
                                                 portEdit->styleSheet().contains("#d32f2f");
                            portEdit->clear();
                            // 4) Valid inputs now accept cleanly.
                            okBtn->click();
                        });
                    });
                });
        });

        QVERIFY(editServer(nullptr, server));
        QVERIFY(sawDialogStayedOpen);
        QVERIFY(sawIpHighlighted);
        QVERIFY(sawClearedOnEdit);
        QVERIFY(sawDohUrlHighlighted);
        QVERIFY(sawPortHighlighted);
        QCOMPARE(QString::fromStdString(server.name), QString("Preserved Server Name"));
        QCOMPARE(server.protocol, nd::Protocol::doh);
        QCOMPARE(QString::fromStdString(server.url), QString("https://dns.example/dns-query"));
    }
    void ruleAndPoolEditorsValidateInPlaceWithRedBorders() {
        // 1) DNS Rule editor: invalid name + invalid hostname pattern stay open & highlight red.
        nd::Rule rule;
        rule.id = 77;
        rule.name = "Initial";
        rule.patterns = {"example.com"};
        bool ruleStayedOpen = false;
        bool ruleBothHighlighted = false;
        bool ruleClearedOnEdit = false;

        QTimer::singleShot(0, [&] {
            auto* dlg = qobject_cast<QDialog*>(QApplication::activeModalWidget());
            if (!dlg || dlg->objectName() != "ruleEditorDialog")
                return;
            auto* nameEdit = dlg->findChild<QLineEdit*>("ruleNameEdit");
            auto* hostsEdit = dlg->findChild<QPlainTextEdit*>("ruleHostnamesEdit");
            auto* box = dlg->findChild<QDialogButtonBox*>();
            auto* okBtn = box ? box->button(QDialogButtonBox::Ok) : nullptr;
            if (!nameEdit || !hostsEdit || !okBtn)
                return;

            nameEdit->clear();
            hostsEdit->setPlainText("bad..domain");
            QTimer::singleShot(0, [&, dlg, nameEdit, hostsEdit, okBtn] {
                if (auto* err = qobject_cast<QMessageBox*>(QApplication::activeModalWidget()))
                    err->accept();
                QTimer::singleShot(0, [&, dlg, nameEdit, hostsEdit, okBtn] {
                    ruleStayedOpen =
                        dlg->isVisible() && hostsEdit->toPlainText() == "bad..domain";
                    ruleBothHighlighted = nameEdit->property("validationError").toBool() &&
                                          nameEdit->styleSheet().contains("#d32f2f") &&
                                          hostsEdit->property("validationError").toBool() &&
                                          hostsEdit->styleSheet().contains("#d32f2f");
                    nameEdit->setText("Fixed Rule");
                    hostsEdit->setPlainText("good.example");
                    ruleClearedOnEdit = !nameEdit->property("validationError").toBool() &&
                                        !hostsEdit->property("validationError").toBool();
                    okBtn->click();
                });
            });
            okBtn->click();
        });
        QVERIFY(editRule(nullptr, config_, rule));
        QVERIFY(ruleStayedOpen);
        QVERIFY(ruleBothHighlighted);
        QVERIFY(ruleClearedOnEdit);
        QCOMPARE(QString::fromStdString(rule.name), QString("Fixed Rule"));
        QCOMPARE(rule.patterns, (std::vector<std::string>{"good.example"}));

        // 2) Pool Type editor: empty pool name stays open & highlights poolNameEdit in red.
        nd::ServerPool pool;
        pool.id = 1;
        pool.name = "Initial Pool";
        bool poolStayedOpen = false;
        bool poolHighlighted = false;
        QTimer::singleShot(0, [&] {
            auto* dlg = qobject_cast<QDialog*>(QApplication::activeModalWidget());
            if (!dlg || dlg->objectName() != "poolTypeDialog")
                return;
            auto* nameEdit = dlg->findChild<QLineEdit*>("poolNameEdit");
            QPushButton* okBtn = nullptr;
            for (auto* b : dlg->findChildren<QPushButton*>())
                if (b->text() == uiText("OK"))
                    okBtn = b;
            if (!nameEdit || !okBtn)
                return;
            nameEdit->clear();
            QTimer::singleShot(0, [&, dlg, nameEdit, okBtn] {
                if (auto* err = qobject_cast<QMessageBox*>(QApplication::activeModalWidget()))
                    err->accept();
                QTimer::singleShot(0, [&, dlg, nameEdit, okBtn] {
                    poolStayedOpen = dlg->isVisible();
                    poolHighlighted = nameEdit->property("validationError").toBool() &&
                                      nameEdit->styleSheet().contains("#d32f2f");
                    nameEdit->setText("AI Pool");
                    okBtn->click();
                });
            });
            okBtn->click();
        });
        QVERIFY(editPoolType(nullptr, pool));
        QVERIFY(poolStayedOpen);
        QVERIFY(poolHighlighted);
        QCOMPARE(QString::fromStdString(pool.name), QString("AI Pool"));

        // 3) Redundancy Pool Options: invalid hostname + out-of-range interval both highlight red.
        std::string testHost = "iana.org";
        uint32_t recheck = 60;
        bool optStayedOpen = false;
        bool optBothHighlighted = false;
        QTimer::singleShot(0, [&] {
            auto* dlg = qobject_cast<QDialog*>(QApplication::activeModalWidget());
            if (!dlg || dlg->objectName() != "redundancyOptionsDialog")
                return;
            auto* hostEdit = dlg->findChild<QLineEdit*>("redundancyTestHostname");
            auto* recheckEdit = dlg->findChild<QLineEdit*>("redundancyRecheckSeconds");
            QPushButton* okBtn = nullptr;
            for (auto* b : dlg->findChildren<QPushButton*>())
                if (b->text() == uiText("OK"))
                    okBtn = b;
            if (!hostEdit || !recheckEdit || !okBtn)
                return;
            hostEdit->setText("bad..host");
            recheckEdit->setText("2");
            QTimer::singleShot(0, [&, dlg, hostEdit, recheckEdit, okBtn] {
                if (auto* err = qobject_cast<QMessageBox*>(QApplication::activeModalWidget()))
                    err->accept();
                QTimer::singleShot(0, [&, dlg, hostEdit, recheckEdit, okBtn] {
                    optStayedOpen = dlg->isVisible() && hostEdit->text() == "bad..host";
                    optBothHighlighted = hostEdit->property("validationError").toBool() &&
                                         hostEdit->styleSheet().contains("#d32f2f") &&
                                         recheckEdit->property("validationError").toBool() &&
                                         recheckEdit->styleSheet().contains("#d32f2f");
                    hostEdit->setText("example.org");
                    recheckEdit->setText("30");
                    okBtn->click();
                });
            });
            okBtn->click();
        });
        QVERIFY(editRedundancyOptions(nullptr, testHost, recheck));
        QVERIFY(optStayedOpen);
        QVERIFY(optBothHighlighted);
        QCOMPARE(QString::fromStdString(testHost), QString("example.org"));
        QCOMPARE(recheck, 30u);
    }
};

QTEST_MAIN(RulesGuiTests)
#include "rules_gui_tests.moc"
