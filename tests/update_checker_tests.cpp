#include "../NativeDNS.GUI/update_checker.hpp"
#include "../NativeDNS.GUI/ui_preferences.hpp"
#include <QAction>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMenu>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPushButton>
#include <QScrollBar>
#include <QSettings>
#include <QTemporaryDir>
#include <QTextBrowser>
#include <QTimer>
#include <QtTest>
#include <algorithm>
#include <cstring>

namespace {
const QString hash(40, 'a');
QByteArray manifest(const QString& version = "0.4.3", int count = 1) {
    QJsonArray changes;
    for (int index = 0; index < count; ++index)
        changes.append(QJsonObject{{"commit", hash},
                                   {"text",
                                    QJsonObject{{"en", "Added <script> & improvements."},
                                                {"ru", "Добавлены улучшения."}}}});
    return QJsonDocument(
               QJsonObject{
                   {"schema_version", 1},
                   {"version", version},
                   {"release_url", "https://github.com/zmorok/NativeDNS/releases/tag/v" + version},
                   {"whats_new", changes}})
        .toJson();
}

class StubReply final : public QNetworkReply {
public:
    StubReply(const QNetworkRequest& request, QObject* parent) : QNetworkReply(parent) {
        setRequest(request);
        setUrl(request.url());
        open(QIODevice::ReadOnly | QIODevice::Unbuffered);
    }
    void abort() override {
        aborted = true;
        if (!isFinished()) {
            setError(OperationCanceledError, "Canceled");
            setFinished(true);
            emit finished();
        }
    }
    void complete(const QByteArray& data, int status = 200, NetworkError error = NoError) {
        payload_ = data;
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, status);
        if (error != NoError)
            setError(error, "Connection failed");
        emit readyRead();
        if (!isFinished()) {
            setFinished(true);
            emit finished();
        }
    }
    qint64 bytesAvailable() const override {
        return payload_.size() - offset_ + QNetworkReply::bytesAvailable();
    }
    bool aborted = false;

protected:
    qint64 readData(char* buffer, qint64 maximum) override {
        const auto count = std::min<qint64>(maximum, payload_.size() - offset_);
        if (count <= 0)
            return -1;
        std::memcpy(buffer, payload_.constData() + offset_, static_cast<size_t>(count));
        offset_ += count;
        return count;
    }

private:
    QByteArray payload_;
    qint64 offset_ = 0;
};
class StubNetwork final : public QNetworkAccessManager {
public:
    QPointer<StubReply> last;
    QNetworkRequest request;
    int requests = 0;

protected:
    QNetworkReply* createRequest(Operation, const QNetworkRequest& value, QIODevice*) override {
        ++requests;
        request = value;
        last = new StubReply(value, this);
        return last;
    }
};
} // namespace

class UpdateCheckerTests final : public QObject {
    Q_OBJECT
private slots:
    void initTestCase() {
        QVERIFY(settingsDirectory_.isValid());
        QCoreApplication::setOrganizationName("NativeDNS-Tests");
        QCoreApplication::setApplicationName("update-checker");
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsDirectory_.path());
    }
    void init() {
        QSettings().clear();
        setUiLanguage(UiLanguage::english);
    }
    void startupPreference() {
        QVERIFY(startupUpdateCheckEnabled());
        QMenu menu;
        auto* action = addStartupUpdateCheckAction(&menu);
        QVERIFY(action->isCheckable() && action->isChecked());
        QCOMPARE(action->text(), "Check update on start");
        action->trigger();
        QVERIFY(!action->isChecked() && !startupUpdateCheckEnabled());
        QMenu reopened;
        QVERIFY(!addStartupUpdateCheckAction(&reopened)->isChecked());
        StubNetwork network;
        UpdateDialog dialog("0.4.3", nullptr, &network);
        dialog.checkOnStart();
        QCOMPARE(network.requests, 0);
        QVERIFY(!dialog.isVisible());
        dialog.check(); // The preference never disables manual checks.
        QCOMPARE(network.requests, 1);
        network.last->complete(manifest("0.4.4"));
        QVERIFY(dialog.findChild<QLabel*>("updateStatus")->text().contains("available"));
        action->trigger();
        QVERIFY(action->isChecked() && startupUpdateCheckEnabled());
        QMenu enabled;
        QVERIFY(addStartupUpdateCheckAction(&enabled)->isChecked());
        setUiLanguage(UiLanguage::russian);
        QMenu translated;
        QCOMPARE(addStartupUpdateCheckAction(&translated)->text(), uiText("Check update on start"));
    }
    void startupComparison_data() {
        comparison_data();
    }
    void startupComparison() {
        QFETCH(QString, current);
        QFETCH(QString, release);
        QFETCH(QString, status);
        StubNetwork network;
        UpdateDialog dialog(current, nullptr, &network);
        dialog.checkOnStart();
        dialog.checkOnStart();
        QCOMPARE(network.requests, 1);
        QVERIFY(!dialog.isVisible());
        network.last->complete(manifest(release));
        const bool newer = status == "A new NativeDNS version is available.";
        QCOMPARE(dialog.isVisible(), newer);
        QCOMPARE(dialog.findChild<QLabel*>("updateStatus")->text(), status);
        QCOMPARE(QSettings().value("updates/lastManifest").toByteArray(), manifest(release));
        if (newer)
            QVERIFY(
                dialog.findChild<QTextBrowser*>("releaseNotes")->toPlainText().contains("aaaaaaa"));
    }
    void startupFailures_data() {
        QTest::addColumn<QByteArray>("data");
        QTest::addColumn<int>("http");
        QTest::newRow("offline") << QByteArray{} << 0;
        QTest::newRow("missing") << QByteArray{} << 404;
        QTest::newRow("limited") << QByteArray{} << 429;
        QTest::newRow("invalid") << QByteArray("invalid") << 200;
        QTest::newRow("oversized") << QByteArray(maximumUpdateManifestBytes + 100, ' ') << 200;
    }
    void startupFailures() {
        QFETCH(QByteArray, data);
        QFETCH(int, http);
        // Cached newer metadata must not produce a notification after a failed live check.
        QSettings().setValue("updates/lastManifest", manifest("0.4.4"));
        StubNetwork network;
        QPointer<UpdateDialog> dialog = new UpdateDialog("0.4.3", nullptr, &network);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->checkOnStart();
        network.last->complete(data,
                               http,
                               http == 200 ? QNetworkReply::NoError
                                           : QNetworkReply::ConnectionRefusedError);
        QVERIFY(!dialog || !dialog->isVisible());
        QTRY_VERIFY(!dialog);
    }
    void startupCancellationAndManualTakeover() {
        StubNetwork network;
        UpdateDialog dialog("0.4.3", nullptr, &network);
        dialog.checkOnStart();
        auto* pending = network.last.data();
        dialog.cancelStartupCheck();
        QVERIFY(pending->aborted);
        QVERIFY(!dialog.isVisible());
        dialog.checkOnStart();
        auto* timer = dialog.findChild<QTimer*>();
        const auto timedOut = network.last;
        timer->start(1);
        QTRY_VERIFY(!timedOut || timedOut->aborted);
        QVERIFY(!dialog.isVisible());
        dialog.checkOnStart();
        QCOMPARE(network.requests, 3);
        dialog.showForManualCheck();
        dialog.cancelStartupCheck(); // An opened manual check must remain active.
        QVERIFY(dialog.isVisible());
        QVERIFY(!network.last->aborted);
        network.last->complete({}, 0, QNetworkReply::ConnectionRefusedError);
        QVERIFY(dialog.isVisible());
        QVERIFY(dialog.findChild<QLabel*>("updateStatus")->text().contains("Could not connect"));
        QCOMPARE(network.requests, 3);
    }
    void rejectsInvalidManifest() {
        QString error;
        QVERIFY(!parseReleaseManifest("<html>error</html>", error));
        QVERIFY(!error.isEmpty());
        QVERIFY(!parseReleaseManifest(QByteArray(maximumUpdateManifestBytes + 1, ' '), error));
        for (const auto& version : {"v0.4.3", "0.4", "0.4.3-beta", "00.4.3", "2147483648.0.0"})
            QVERIFY(!parseReleaseManifest(manifest(version), error));
        auto root = QJsonDocument::fromJson(manifest()).object();
        root["schema_version"] = 2;
        QVERIFY(!parseReleaseManifest(QJsonDocument(root).toJson(), error));
        root["schema_version"] = 1;
        root["release_url"] = "https://other.example/v0.4.3";
        QVERIFY(!parseReleaseManifest(QJsonDocument(root).toJson(), error));
        root["release_url"] = "https://github.com/zmorok/NativeDNS/releases/tag/v0.4.2";
        QVERIFY(!parseReleaseManifest(QJsonDocument(root).toJson(), error));
        QVERIFY(!parseReleaseManifest(manifest("0.4.3", 257), error));
        root = QJsonDocument::fromJson(manifest()).object();
        auto entries = root["whats_new"].toArray();
        auto item = entries[0].toObject();
        item["commit"] = "javascript:alert(1)";
        entries[0] = item;
        root["whats_new"] = entries;
        QVERIFY(!parseReleaseManifest(QJsonDocument(root).toJson(), error));
    }
    void comparison_data() {
        QTest::addColumn<QString>("current");
        QTest::addColumn<QString>("release");
        QTest::addColumn<QString>("status");
        QTest::newRow("new") << "0.4.2" << "0.4.3" << "A new NativeDNS version is available.";
        QTest::newRow("numeric") << "0.4.9" << "0.4.10" << "A new NativeDNS version is available.";
        QTest::newRow("equal") << "0.4.3" << "0.4.3" << "NativeDNS is up to date.";
        QTest::newRow("development")
            << "0.5.0" << "0.4.3"
            << "The installed version is newer than the published release.";
    }
    void comparison() {
        QFETCH(QString, current);
        QFETCH(QString, release);
        QFETCH(QString, status);
        StubNetwork network;
        UpdateDialog dialog(current, nullptr, &network);
        dialog.check();
        dialog.check();
        QCOMPARE(network.requests, 1);
        QCOMPARE(network.request.url(), updateManifestUrl());
        QCOMPARE(network.request.attribute(QNetworkRequest::RedirectPolicyAttribute).toInt(),
                 int(QNetworkRequest::NoLessSafeRedirectPolicy));
        network.last->complete(manifest(release));
        QCOMPARE(dialog.findChild<QLabel*>("updateStatus")->text(), status);
        QVERIFY(dialog.findChild<QPushButton*>("openRelease")->isEnabled());
        const auto* browser = dialog.findChild<QTextBrowser*>("releaseNotes");
        QVERIFY(browser->toPlainText().contains("aaaaaaa Added <script> & improvements."));
        QVERIFY(browser->toHtml().contains("https://github.com/zmorok/NativeDNS/commit/" + hash));
        QVERIFY(!browser->openLinks());
        QVERIFY(!browser->openExternalLinks());
        QCOMPARE(QSettings().value("updates/lastManifest").toByteArray(), manifest(release));
    }
    void failureRetryAndCachedNotes() {
        const auto data = manifest();
        QSettings().setValue("updates/lastManifest", data);
        StubNetwork network;
        UpdateDialog dialog("0.4.2", nullptr, &network);
        dialog.check();
        network.last->complete({}, 404, QNetworkReply::ContentNotFoundError);
        QVERIFY(dialog.findChild<QLabel*>("updateStatus")->text().contains("update.json"));
        QVERIFY(dialog.findChild<QPushButton*>("retryUpdate")->isHidden() == false);
        QVERIFY(dialog.findChild<QTextBrowser*>("releaseNotes")->toPlainText().contains("aaaaaaa"));
        QCOMPARE(QSettings().value("updates/lastManifest").toByteArray(), data);
        dialog.check();
        network.last->complete("invalid", 200);
        QVERIFY(dialog.findChild<QLabel*>("updateStatus")
                    ->text()
                    .contains("Invalid update information"));
        QCOMPARE(QSettings().value("updates/lastManifest").toByteArray(), data);
        dialog.check();
        network.last->complete(data);
        QCOMPARE(network.requests, 3);
        QVERIFY(dialog.findChild<QPushButton*>("retryUpdate")->isHidden());
    }
    void errorResponses_data() {
        QTest::addColumn<int>("http");
        QTest::addColumn<QString>("expected");
        QTest::newRow("limited") << 429 << "HTTP 429";
        QTest::newRow("unavailable") << 503 << "HTTP 503";
        QTest::newRow("offline") << 0 << "Could not connect";
    }
    void errorResponses() {
        QFETCH(int, http);
        QFETCH(QString, expected);
        StubNetwork network;
        UpdateDialog dialog("0.4.2", nullptr, &network);
        dialog.check();
        network.last->complete({}, http, QNetworkReply::ConnectionRefusedError);
        QVERIFY(dialog.findChild<QLabel*>("updateStatus")->text().contains(expected));
        QVERIFY(!dialog.findChild<QPushButton*>("openRelease")->isEnabled());
    }
    void boundedResponseAndCancellation() {
        StubNetwork network;
        UpdateDialog dialog("0.4.2", nullptr, &network);
        dialog.check();
        network.last->complete(QByteArray(maximumUpdateManifestBytes + 100, ' '));
        QVERIFY(network.last->aborted);
        QVERIFY(dialog.findChild<QLabel*>("updateStatus")->text().contains("too large"));
        dialog.check();
        auto* timer = dialog.findChild<QTimer*>();
        timer->start(1);
        QTRY_VERIFY(dialog.findChild<QLabel*>("updateStatus")->text().contains("timed out"));
        dialog.check();
        auto* pending = network.last.data();
        dialog.reject();
        QVERIFY(pending->aborted);
    }
    void scrollableNotesAndLanguageFallback() {
        applyUiTheme(*qApp, true);
        setUiLanguage(UiLanguage::russian);
        auto root = QJsonDocument::fromJson(manifest("0.4.3", 120)).object();
        auto changes = root["whats_new"].toArray();
        auto first = changes[0].toObject();
        first["text"] = QJsonObject{{"en", "English fallback"}};
        changes[0] = first;
        root["whats_new"] = changes;
        StubNetwork network;
        UpdateDialog dialog("0.4.2", nullptr, &network);
        dialog.show();
        dialog.check();
        network.last->complete(QJsonDocument(root).toJson());
        auto* browser = dialog.findChild<QTextBrowser*>("releaseNotes");
        QVERIFY(browser->toPlainText().contains("English fallback"));
        QVERIFY(browser->toPlainText().contains("Добавлены улучшения"));
        for (const bool dark : {true, false}) {
            applyUiTheme(*qApp, dark);
            dialog.resize(dialog.minimumSize());
            QTest::qWait(20);
            QVERIFY(browser->verticalScrollBar()->maximum() > 0);
            auto* release = dialog.findChild<QPushButton*>("openRelease");
            auto* close = dialog.findChild<QPushButton*>("closeUpdate");
            const auto position = close->pos();
            browser->verticalScrollBar()->setValue(browser->verticalScrollBar()->maximum());
            QCOMPARE(close->pos(), position);
            QVERIFY(dialog.rect().contains(close->geometry()));
            QVERIFY(dialog.rect().contains(release->geometry()));
            QVERIFY(close->geometry().top() > browser->geometry().bottom());
            const auto previewDirectory = qEnvironmentVariable("NATIVEDNS_UPDATE_PREVIEW_DIR");
            if (!previewDirectory.isEmpty()) {
                browser->verticalScrollBar()->setValue(0);
                QVERIFY(dialog.grab().save(previewDirectory + (dark ? "/updates-dark-min.png"
                                                                    : "/updates-light-min.png")));
                dialog.resize(760, 520);
                QTest::qWait(20);
                QVERIFY(dialog.grab().save(previewDirectory +
                                           (dark ? "/updates-dark.png" : "/updates-light.png")));
            }
        }
    }

private:
    QTemporaryDir settingsDirectory_;
};
QTEST_MAIN(UpdateCheckerTests)
#include "update_checker_tests.moc"
