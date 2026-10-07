// The dialogs are internal to this translation unit; include them to exercise the
// real widgets without exposing test-only APIs or constructing NativeDnsWindow.
#include "../NativeDNS.GUI/qt_app.cpp"
#include <QtTest>

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
};

QTEST_MAIN(RulesGuiTests)
#include "rules_gui_tests.moc"
