#include "update_checker.hpp"
#include "ui_preferences.hpp"

#include <QDesktopServices>
#include <QAction>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPushButton>
#include <QRegularExpression>
#include <QSettings>
#include <QTextBrowser>
#include <QTextDocument>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>

namespace {
constexpr auto repositoryUrl = "https://github.com/zmorok/NativeDNS";
std::optional<QVersionNumber> versionNumber(const QString& text) {
    static const QRegularExpression pattern(
        "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$");
    const auto match = pattern.match(text);
    if (!match.hasMatch())
        return std::nullopt;
    QList<int> segments;
    for (int index = 1; index <= 3; ++index) {
        bool valid = false;
        const int value = match.captured(index).toInt(&valid);
        if (!valid)
            return std::nullopt;
        segments.append(value);
    }
    return QVersionNumber(segments);
}
QString commitUrl(const QString& commit) {
    return QString::fromLatin1(repositoryUrl) + "/commit/" + commit;
}
} // namespace

QUrl updateManifestUrl() {
    return QUrl(QString::fromLatin1(repositoryUrl) + "/releases/latest/download/update.json");
}
bool startupUpdateCheckEnabled() {
    return QSettings().value("updates/checkOnStart", true).toBool();
}
QAction* addStartupUpdateCheckAction(QMenu* menu) {
    auto* action = menu->addAction(uiText("Check update on start"));
    action->setProperty("uiTextKey", "Check update on start");
    action->setObjectName("startupUpdateCheck");
    action->setCheckable(true);
    action->setChecked(startupUpdateCheckEnabled());
    QObject::connect(action, &QAction::triggered, menu, [action, menu](bool checked) {
        QSettings settings;
        settings.setValue("updates/checkOnStart", checked);
        settings.sync();
        if (settings.status() != QSettings::NoError)
            QMessageBox::warning(
                menu->parentWidget(), "NativeDNS", uiText("Cannot save update preferences."));
        action->setChecked(startupUpdateCheckEnabled());
    });
    return action;
}

std::optional<ReleaseManifest> parseReleaseManifest(const QByteArray& json, QString& error) {
    error = uiText("Invalid update information.");
    if (json.size() > maximumUpdateManifestBytes)
        return std::nullopt;
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(json, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
        return std::nullopt;
    const auto root = document.object();
    if (root.value("schema_version") != QJsonValue(1)) {
        error = uiText("Unsupported update information format.");
        return std::nullopt;
    }
    const auto version = root.value("version").toString();
    const auto number = versionNumber(version);
    // Restrict all clickable destinations to this repository and this exact version.
    const QUrl expectedUrl(QString::fromLatin1(repositoryUrl) + "/releases/tag/v" + version);
    if (!number || root.value("release_url").toString() != expectedUrl.toString() ||
        !root.value("whats_new").isArray())
        return std::nullopt;
    const auto entries = root.value("whats_new").toArray();
    if (entries.size() > 256)
        return std::nullopt;
    ReleaseManifest manifest{version, *number, expectedUrl, {}};
    static const QRegularExpression categoryPattern("^[a-z][a-z0-9_]{0,63}$");
    if (root.contains("categories")) {
        if (!root.value("categories").isArray())
            return std::nullopt;
        const auto categories = root.value("categories").toArray();
        if (categories.size() > 16)
            return std::nullopt;
        for (const auto& entry : categories) {
            if (!entry.isObject())
                return std::nullopt;
            const auto category = entry.toObject();
            const auto id = category.value("id").toString();
            const auto text = category.value("text").toObject();
            const auto english = text.value("en").toString();
            const auto russian = text.value("ru").toString();
            if (!categoryPattern.match(id).hasMatch() || english.trimmed().isEmpty() ||
                english.size() > 4096 || russian.size() > 4096 ||
                (text.contains("ru") && !text.value("ru").isString()) ||
                std::any_of(manifest.categories.cbegin(),
                            manifest.categories.cend(),
                            [&](const auto& existing) { return existing.id == id; }))
                return std::nullopt;
            manifest.categories.append({id, english, russian});
        }
    }
    static const QRegularExpression commitPattern("^[0-9a-f]{40}$");
    for (const auto& entry : entries) {
        if (!entry.isObject())
            return std::nullopt;
        const auto change = entry.toObject();
        const auto commit = change.value("commit").toString();
        const auto text = change.value("text").toObject();
        const auto english = text.value("en").toString();
        const auto russian = text.value("ru").toString();
        const auto category = change.value("category").toString();
        if (!commitPattern.match(commit).hasMatch() || english.trimmed().isEmpty() ||
            english.size() > 4096 || russian.size() > 4096 ||
            (text.contains("ru") && !text.value("ru").isString()))
            return std::nullopt;
        if (change.contains("category") &&
            (!change.value("category").isString() ||
             std::none_of(manifest.categories.cbegin(),
                          manifest.categories.cend(),
                          [&](const auto& existing) { return existing.id == category; })))
            return std::nullopt;
        manifest.changes.append({commit, english, russian, category});
    }
    error.clear();
    return manifest;
}

UpdateDialog::UpdateDialog(const QString& currentVersion,
                           QWidget* parent,
                           QNetworkAccessManager* network)
    : QDialog(parent), currentVersion_(currentVersion),
      network_(network ? network : new QNetworkAccessManager(this)), deadline_(new QTimer(this)) {
    setWindowTitle(uiText("Check for updates"));
    setMinimumSize(520, 320);
    resize(760, 520);
    auto* layout = new QVBoxLayout(this);
    status_ = new QLabel(this);
    status_->setObjectName("updateStatus");
    status_->setTextFormat(Qt::PlainText);
    status_->setWordWrap(true);
    status_->setMinimumHeight(status_->fontMetrics().height() * 3);
    status_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    versions_ = new QLabel(uiText("Installed version: %1").arg(currentVersion_), this);
    versions_->setObjectName("updateVersions");
    versions_->setTextFormat(Qt::PlainText);
    notesTitle_ = new QLabel(uiText("What's new"), this);
    auto font = notesTitle_->font();
    font.setBold(true);
    notesTitle_->setFont(font);
    notes_ = new QTextBrowser(this);
    notes_->setObjectName("releaseNotes");
    notes_->setOpenLinks(false);
    notes_->setOpenExternalLinks(false);
    notes_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
    notes_->setMinimumHeight(0);
    layout->addWidget(status_);
    layout->addWidget(versions_);
    layout->addWidget(notesTitle_);
    layout->addWidget(notes_, 1);
    auto* buttons = new QHBoxLayout;
    openRelease_ = new QPushButton(uiText("Open release"), this);
    openRelease_->setObjectName("openRelease");
    openRelease_->setEnabled(false);
    retry_ = new QPushButton(uiText("Retry"), this);
    retry_->setObjectName("retryUpdate");
    retry_->hide();
    auto* close = new QPushButton(uiText("Close"), this);
    close->setObjectName("closeUpdate");
    buttons->addStretch();
    buttons->addWidget(openRelease_);
    buttons->addWidget(retry_);
    buttons->addWidget(close);
    layout->addLayout(buttons);
    connect(close, &QPushButton::clicked, this, &QDialog::reject);
    connect(retry_, &QPushButton::clicked, this, [this] { check(); });
    connect(openRelease_, &QPushButton::clicked, this, [this] {
        if (manifest_)
            QDesktopServices::openUrl(manifest_->releaseUrl);
    });
    connect(notes_, &QTextBrowser::anchorClicked, this, [this](const QUrl& url) {
        if (!manifest_)
            return;
        for (const auto& change : manifest_->changes) {
            if (url == QUrl(commitUrl(change.commit))) {
                QDesktopServices::openUrl(url);
                return;
            }
        }
    });
    deadline_->setSingleShot(true);
    deadline_->setInterval(20000);
    connect(deadline_, &QTimer::timeout, this, [this] {
        if (reply_) {
            requestError_ = uiText("The update check timed out.");
            reply_->abort();
        }
    });
    QString error;
    manifest_ =
        parseReleaseManifest(QSettings().value("updates/lastManifest").toByteArray(), error);
    if (manifest_)
        displayManifest(true);
}

UpdateDialog::~UpdateDialog() {
    cancelRequest();
}
void UpdateDialog::done(int result) {
    cancelRequest();
    QDialog::done(result);
}
void UpdateDialog::cancelRequest() {
    deadline_->stop();
    if (reply_) {
        disconnect(reply_, nullptr, this, nullptr);
        reply_->abort();
        reply_->deleteLater();
        reply_ = nullptr;
    }
}
void UpdateDialog::check() {
    quiet_ = false;
    startRequest();
}
void UpdateDialog::checkOnStart() {
    if (!startupUpdateCheckEnabled() || reply_)
        return;
    quiet_ = true;
    startRequest();
}
void UpdateDialog::cancelStartupCheck() {
    if (quiet_)
        reject();
}
void UpdateDialog::showForManualCheck() {
    quiet_ = false;
    show();
    raise();
    activateWindow();
}
void UpdateDialog::startRequest() {
    if (reply_)
        return;
    status_->setStyleSheet({});
    status_->setText(uiText("Checking for updates..."));
    retry_->hide();
    response_.clear();
    requestError_.clear();
    QNetworkRequest request(updateManifestUrl());
    request.setRawHeader("User-Agent", "NativeDNS/" + currentVersion_.toUtf8());
    request.setRawHeader("Accept", "application/json");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    request.setMaximumRedirectsAllowed(5);
    request.setTransferTimeout(10000);
    reply_ = network_->get(request);
    reply_->setReadBufferSize(maximumUpdateManifestBytes + 1);
    connect(reply_, &QNetworkReply::readyRead, this, [this] { readResponse(); });
    connect(reply_, &QNetworkReply::finished, this, [this] { finishRequest(); });
    deadline_->start();
}
void UpdateDialog::readResponse() {
    if (!reply_)
        return;
    response_ += reply_->read(maximumUpdateManifestBytes + 1 - response_.size());
    if (response_.size() > maximumUpdateManifestBytes) {
        requestError_ = uiText("Update information is too large.");
        reply_->abort();
    }
}
void UpdateDialog::finishRequest() {
    if (!reply_)
        return;
    deadline_->stop();
    // Disconnect before reading the final bytes: abort() can emit finished synchronously.
    disconnect(reply_, nullptr, this, nullptr);
    readResponse();
    auto* reply = reply_.data();
    reply_ = nullptr;
    reply->deleteLater();
    if (!requestError_.isEmpty()) {
        showFailure(requestError_);
        return;
    }
    const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (httpStatus != 200) {
        if (httpStatus == 404)
            showFailure(uiText("The latest release does not provide update.json yet."));
        else if (httpStatus)
            showFailure(uiText("The update server returned HTTP %1.").arg(httpStatus));
        else
            showFailure(
                uiText("Could not connect to the update server. %1").arg(reply->errorString()));
        return;
    }
    if (reply->error() != QNetworkReply::NoError) {
        showFailure(uiText("Could not download update information. %1").arg(reply->errorString()));
        return;
    }
    QString error;
    const auto result = parseReleaseManifest(response_, error);
    if (!result) {
        showFailure(error);
        return;
    }
    const auto current = versionNumber(currentVersion_);
    if (!current) {
        showFailure(uiText("The installed version is invalid."));
        return;
    }
    manifest_ = result;
    QSettings().setValue("updates/lastManifest", response_);
    displayManifest(false);
    const int comparison = QVersionNumber::compare(manifest_->number, *current);
    status_->setText(comparison > 0 ? uiText("A new NativeDNS version is available.")
                     : comparison == 0
                         ? uiText("NativeDNS is up to date.")
                         : uiText("The installed version is newer than the published release."));
    if (quiet_) {
        if (comparison > 0)
            showForManualCheck();
        else
            reject();
    }
}
void UpdateDialog::showFailure(const QString& message) {
    if (quiet_) {
        reject();
        return;
    }
    status_->setStyleSheet("color: " + palette().color(QPalette::BrightText).name() + ";");
    status_->setText(uiText("Could not check for updates.") + "\n" + message);
    retry_->show();
    if (manifest_)
        displayManifest(true);
}
void UpdateDialog::displayManifest(bool cached) {
    versions_->setText(uiText("Installed version: %1").arg(currentVersion_) + "\n" +
                       uiText("Release version: %1").arg(manifest_->version));
    notesTitle_->setText(cached ? uiText("What's new (last successful check)")
                                : uiText("What's new"));
    QString html;
    const auto appendChange = [&](const ReleaseChange& change) {
        const auto& text =
            uiLanguage() == UiLanguage::russian && !change.russian.trimmed().isEmpty()
                ? change.russian
                : change.english;
        html += "<li><a href=\"" + commitUrl(change.commit) + "\">" + change.commit.left(7) +
                "</a> " + text.toHtmlEscaped().replace("\n", "<br>") + "</li>";
    };
    for (const auto& category : manifest_->categories) {
        if (std::none_of(manifest_->changes.cbegin(),
                         manifest_->changes.cend(),
                         [&](const auto& change) { return change.category == category.id; }))
            continue;
        const auto& title =
            uiLanguage() == UiLanguage::russian && !category.russian.trimmed().isEmpty()
                ? category.russian
                : category.english;
        html += "<h3>" + title.toHtmlEscaped() + "</h3><ul>";
        for (const auto& change : manifest_->changes)
            if (change.category == category.id)
                appendChange(change);
        html += "</ul>";
    }
    if (std::any_of(manifest_->changes.cbegin(), manifest_->changes.cend(), [](const auto& change) {
            return change.category.isEmpty();
        })) {
        html += "<ul>";
        for (const auto& change : manifest_->changes)
            if (change.category.isEmpty())
                appendChange(change);
        html += "</ul>";
    }
    if (manifest_->changes.isEmpty())
        html = uiText("No release notes were provided.").toHtmlEscaped();
    notes_->document()->setDefaultStyleSheet(
        "li { margin-bottom: 10px; } a { color: " + palette().color(QPalette::Link).name() + "; }");
    notes_->setHtml(html);
    openRelease_->setEnabled(true);
}
