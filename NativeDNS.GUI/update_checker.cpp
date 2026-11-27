#include "update_checker.hpp"
#include "ui_preferences.hpp"
#include "window_activation.hpp"

#include <QAction>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
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
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QSettings>
#include <QTextBrowser>
#include <QTextDocument>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>
#include <cmath>

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

QString formatByteSize(qint64 bytes) {
    if (bytes < 1024)
        return QString("%1 B").arg(bytes);
    const double kb = static_cast<double>(bytes) / 1024.0;
    if (kb < 1024.0)
        return QString("%1 KB").arg(kb, 0, 'f', 1);
    const double mb = kb / 1024.0;
    return QString("%1 MB").arg(mb, 0, 'f', 1);
}

QString formatTransferSpeed(double bytesPerSec) {
    if (bytesPerSec < 1024.0)
        return QString("%1 B/s").arg(static_cast<qint64>(std::llround(bytesPerSec)));
    const double kb = bytesPerSec / 1024.0;
    if (kb < 1024.0)
        return QString("%1 KB/s").arg(kb, 0, 'f', 1);
    return QString("%1 MB/s").arg(kb / 1024.0, 0, 'f', 2);
}

QString formatEta(qint64 seconds) {
    if (seconds < 0)
        return {};
    if (seconds < 60)
        return QString("~%1s").arg(seconds);
    return QString("~%1m %2s").arg(seconds / 60).arg(seconds % 60);
}
} // namespace

QUrl updateManifestUrl() {
    return QUrl(QString::fromLatin1(repositoryUrl) + "/releases/latest/download/update.json");
}

QString currentPlatformAssetKey(nd::platform::DistributionKind kind) {
#ifdef _WIN32
    return kind == nd::platform::DistributionKind::executable ? QStringLiteral("windows-x64-executable")
                                                              : QStringLiteral("windows-x64-portable");
#else
    if (kind == nd::platform::DistributionKind::appimage)
        return QStringLiteral("linux-x64-appimage");
    if (kind == nd::platform::DistributionKind::package)
        return QStringLiteral("linux-x64-deb");
    return QStringLiteral("linux-x64-portable");
#endif
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
    ReleaseManifest manifest{version, *number, expectedUrl, {}, {}, {}};
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
    if (root.contains("assets")) {
        if (!root.value("assets").isObject())
            return std::nullopt;
        const auto assetsObj = root.value("assets").toObject();
        if (assetsObj.size() > 16)
            return std::nullopt;
        static const QRegularExpression keyPattern("^[a-z0-9-]{1,64}$");
        static const QRegularExpression filePattern("^[A-Za-z0-9._-]{1,160}$");
        static const QRegularExpression shaPattern("^[0-9a-f]{64}$");
        const QString expectedPrefix =
            QString::fromLatin1(repositoryUrl) + "/releases/download/v" + version + "/";
        for (auto it = assetsObj.constBegin(); it != assetsObj.constEnd(); ++it) {
            if (!keyPattern.match(it.key()).hasMatch() || !it.value().isObject())
                return std::nullopt;
            const auto assetObj = it.value().toObject();
            const auto filename = assetObj.value("filename").toString();
            const auto urlText = assetObj.value("url").toString();
            const auto sha256 = assetObj.value("sha256").toString();
            const auto sizeVal = assetObj.value("size");
            if (!filePattern.match(filename).hasMatch() || filename.contains("..") ||
                urlText != expectedPrefix + filename || !shaPattern.match(sha256).hasMatch() ||
                !sizeVal.isDouble())
                return std::nullopt;
            const double rawSize = sizeVal.toDouble(-1.0);
            if (!std::isfinite(rawSize) || std::floor(rawSize) != rawSize || rawSize < 1.0 ||
                rawSize > static_cast<double>(maximumUpdateAssetBytes))
                return std::nullopt;
            const auto size = static_cast<qint64>(rawSize);
            manifest.assets.insert(it.key(), {it.key(), filename, QUrl(urlText), size, sha256});
        }
    }
    error.clear();
    return manifest;
}

UpdateDialog::UpdateDialog(const QString& currentVersion,
                           QWidget* parent,
                           QNetworkAccessManager* network)
    : QDialog(parent), currentVersion_(currentVersion),
      distributionKind_(nd::platform::distribution_kind()),
      downloadDirectory_(QString::fromUtf8(
          nd::platform::path_to_utf8(nd::platform::user_config_directory() / "updates"))),
      network_(network ? network : new QNetworkAccessManager(this)),
      deadline_(new QTimer(this)), downloadStallTimer_(new QTimer(this)) {
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

    downloadPanel_ = new QWidget(this);
    downloadPanel_->setObjectName("downloadPanel");
    auto* downloadLayout = new QVBoxLayout(downloadPanel_);
    downloadLayout->setContentsMargins(0, 6, 0, 2);
    downloadLayout->setSpacing(4);
    downloadFile_ = new QLabel(downloadPanel_);
    downloadFile_->setObjectName("downloadFileLabel");
    downloadFile_->setTextFormat(Qt::PlainText);
    downloadBar_ = new QProgressBar(downloadPanel_);
    downloadBar_->setObjectName("downloadProgress");
    downloadBar_->setRange(0, 100);
    downloadBar_->setValue(0);
    downloadStats_ = new QLabel(downloadPanel_);
    downloadStats_->setObjectName("downloadStats");
    downloadStats_->setTextFormat(Qt::PlainText);
    downloadLayout->addWidget(downloadFile_);
    downloadLayout->addWidget(downloadBar_);
    downloadLayout->addWidget(downloadStats_);
    downloadPanel_->hide();
    layout->addWidget(downloadPanel_);

    auto* buttons = new QHBoxLayout;
    updateButton_ = new QPushButton(uiText("Update"), this);
    updateButton_->setObjectName("installUpdate");
    updateButton_->hide();
    cancelDownload_ = new QPushButton(uiText("Cancel"), this);
    cancelDownload_->setObjectName("cancelDownload");
    cancelDownload_->hide();
    openRelease_ = new QPushButton(uiText("Open release"), this);
    openRelease_->setObjectName("openRelease");
    openRelease_->setEnabled(false);
    retry_ = new QPushButton(uiText("Retry"), this);
    retry_->setObjectName("retryUpdate");
    retry_->hide();
    auto* close = new QPushButton(uiText("Close"), this);
    close->setObjectName("closeUpdate");
    buttons->addStretch();
    buttons->addWidget(updateButton_);
    buttons->addWidget(cancelDownload_);
    buttons->addWidget(openRelease_);
    buttons->addWidget(retry_);
    buttons->addWidget(close);
    layout->addLayout(buttons);

    connect(close, &QPushButton::clicked, this, &QDialog::reject);
    connect(retry_, &QPushButton::clicked, this, [this] { check(); });
    connect(updateButton_, &QPushButton::clicked, this, [this] { startDownload(); });
    connect(cancelDownload_, &QPushButton::clicked, this, [this] { cancelDownload(true); });
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
    downloadStallTimer_->setSingleShot(true);
    downloadStallTimer_->setInterval(30000);
    connect(downloadStallTimer_, &QTimer::timeout, this, [this] {
        if (downloadReply_) {
            downloadError_ = uiText("The download timed out.");
            downloadReply_->abort();
        }
    });
    QString error;
    manifest_ =
        parseReleaseManifest(QSettings().value("updates/lastManifest").toByteArray(), error);
    if (manifest_)
        displayManifest(true);
}

UpdateDialog::~UpdateDialog() {
    cancelDownload(false);
    cancelRequest();
}

void UpdateDialog::setDistributionKind(nd::platform::DistributionKind kind) {
    distributionKind_ = kind;
    refreshUpdateButton();
}

void UpdateDialog::setDownloadDirectory(const QString& directory) {
    downloadDirectory_ = directory;
}

void UpdateDialog::setInstallHandler(InstallHandler handler) {
    installHandler_ = std::move(handler);
}

std::optional<ReleaseAsset> UpdateDialog::matchingAsset() const {
    if (!manifest_)
        return std::nullopt;
    const auto key = currentPlatformAssetKey(distributionKind_);
    const auto found = manifest_->assets.constFind(key);
    if (found == manifest_->assets.constEnd())
        return std::nullopt;
    return *found;
}

void UpdateDialog::done(int result) {
    cancelDownload(false);
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

void UpdateDialog::cancelDownload(bool showCanceledStatus) {
    downloadStallTimer_->stop();
    if (downloadReply_) {
        disconnect(downloadReply_, nullptr, this, nullptr);
        downloadReply_->abort();
        downloadReply_->deleteLater();
        downloadReply_ = nullptr;
    }
    if (downloadPartFile_) {
        downloadPartFile_->close();
        downloadPartFile_.reset();
    }
    if (!downloadPartPath_.isEmpty()) {
        QFile::remove(downloadPartPath_);
        downloadPartPath_.clear();
    }
    downloadHash_.reset();
    activeDownload_.reset();
    downloadError_.clear();
    downloadedBytes_ = 0;
    expectedBytes_ = 0;
    cancelDownload_->hide();
    openRelease_->setEnabled(manifest_.has_value());
    if (showCanceledStatus) {
        downloadPanel_->hide();
        status_->setStyleSheet({});
        status_->setText(uiText("Download canceled."));
    }
    refreshUpdateButton();
}

void UpdateDialog::check() {
    quiet_ = false;
    startRequest();
}

void UpdateDialog::checkOnStart() {
    if (!startupUpdateCheckEnabled() || reply_ || downloadReply_)
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
    activateApplicationWindow(*this);
}

void UpdateDialog::startRequest() {
    if (reply_ || downloadReply_)
        return;
    newerAvailable_ = false;
    updateButton_->hide();
    downloadPanel_->hide();
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
    newerAvailable_ = comparison > 0;
    status_->setText(comparison > 0 ? uiText("A new NativeDNS version is available.")
                     : comparison == 0
                         ? uiText("NativeDNS is up to date.")
                         : uiText("The installed version is newer than the published release."));
    refreshUpdateButton();
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
    newerAvailable_ = false;
    updateButton_->hide();
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
    refreshUpdateButton();
}

void UpdateDialog::refreshUpdateButton() {
    const bool busy = downloadReply_ != nullptr;
    const bool canUpdate = newerAvailable_ && matchingAsset().has_value();
    updateButton_->setVisible(canUpdate && !busy);
    updateButton_->setEnabled(canUpdate && !busy);
}

void UpdateDialog::startDownload() {
    if (downloadReply_ || reply_)
        return;
    const auto asset = matchingAsset();
    if (!manifest_ || !asset)
        return;

    const QDir versionDir(QDir(downloadDirectory_).filePath("v" + manifest_->version));
    if (!QDir().mkpath(versionDir.absolutePath())) {
        failDownload(uiText("Cannot save update file."));
        return;
    }
    downloadFinalPath_ = versionDir.filePath(asset->filename);
    downloadPartPath_ = downloadFinalPath_ + ".part";
    QFile::remove(downloadPartPath_);

    auto file = std::make_unique<QFile>(downloadPartPath_);
    if (!file->open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        failDownload(uiText("Cannot save update file.") + " " + file->errorString());
        return;
    }

    activeDownload_ = *asset;
    downloadPartFile_ = std::move(file);
    downloadHash_ = std::make_unique<QCryptographicHash>(QCryptographicHash::Sha256);
    downloadError_.clear();
    downloadedBytes_ = 0;
    expectedBytes_ = asset->size;

    status_->setStyleSheet({});
    status_->setText(uiText("Downloading update..."));
    downloadFile_->setText(uiText("Downloading %1...").arg(asset->filename));
    downloadBar_->setRange(0, 100);
    downloadBar_->setValue(0);
    downloadStats_->setText(QString("0 B / %1").arg(formatByteSize(expectedBytes_)));
    downloadPanel_->show();
    updateButton_->hide();
    retry_->hide();
    cancelDownload_->show();
    openRelease_->setEnabled(false);

    QNetworkRequest request(asset->url);
    request.setRawHeader("User-Agent", "NativeDNS/" + currentVersion_.toUtf8());
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    request.setMaximumRedirectsAllowed(5);

    downloadTimer_.start();
    downloadReply_ = network_->get(request);
    connect(downloadReply_, &QNetworkReply::readyRead, this, [this] { readDownloadChunk(); });
    connect(downloadReply_, &QNetworkReply::finished, this, [this] { finishDownload(); });
    downloadStallTimer_->start();
}

void UpdateDialog::readDownloadChunk() {
    if (!downloadReply_ || !downloadPartFile_ || !downloadHash_ || !activeDownload_)
        return;
    const QByteArray chunk = downloadReply_->readAll();
    if (chunk.isEmpty())
        return;
    downloadStallTimer_->start();
    if (downloadedBytes_ + chunk.size() > maximumUpdateAssetBytes ||
        (activeDownload_->size > 0 && downloadedBytes_ + chunk.size() > activeDownload_->size)) {
        downloadError_ = uiText("The downloaded file size does not match the release manifest.");
        downloadReply_->abort();
        return;
    }
    if (downloadPartFile_->write(chunk) != chunk.size()) {
        downloadError_ = uiText("Cannot save update file.") + " " + downloadPartFile_->errorString();
        downloadReply_->abort();
        return;
    }
    downloadHash_->addData(chunk);
    downloadedBytes_ += chunk.size();
    updateDownloadProgress();
}

void UpdateDialog::updateDownloadProgress() {
    const qint64 total = expectedBytes_ > 0 ? expectedBytes_ : downloadedBytes_;
    const int percent =
        total > 0 ? static_cast<int>(std::clamp<qint64>((downloadedBytes_ * 100) / total, 0, 100))
                  : 0;
    downloadBar_->setValue(percent);

    const qint64 elapsedMs = std::max<qint64>(1, downloadTimer_.elapsed());
    const double bytesPerSec = (static_cast<double>(downloadedBytes_) * 1000.0) / elapsedMs;
    QString stats =
        QString("%1 / %2").arg(formatByteSize(downloadedBytes_), formatByteSize(total));
    if (downloadedBytes_ > 0) {
        stats += "  •  " + formatTransferSpeed(bytesPerSec);
        if (bytesPerSec > 1.0 && total > downloadedBytes_) {
            const auto etaSec = static_cast<qint64>((total - downloadedBytes_) / bytesPerSec);
            stats += "  •  " + formatEta(etaSec);
        }
    }
    downloadStats_->setText(stats);
}

void UpdateDialog::finishDownload() {
    if (!downloadReply_)
        return;
    downloadStallTimer_->stop();
    disconnect(downloadReply_, nullptr, this, nullptr);
    readDownloadChunk();
    auto* reply = downloadReply_.data();
    downloadReply_ = nullptr;
    reply->deleteLater();

    const auto asset = activeDownload_;
    const QString partPath = downloadPartPath_;
    const QString finalPath = downloadFinalPath_;
    const QString savedError = downloadError_;
    const qint64 bytesWritten = downloadedBytes_;
    QByteArray computedHash;
    if (downloadHash_)
        computedHash = downloadHash_->result().toHex().toLower();
    if (downloadPartFile_) {
        downloadPartFile_->flush();
        downloadPartFile_->close();
        downloadPartFile_.reset();
    }
    downloadHash_.reset();
    activeDownload_.reset();
    downloadPartPath_.clear();
    downloadError_.clear();
    cancelDownload_->hide();
    openRelease_->setEnabled(manifest_.has_value());

    if (!savedError.isEmpty()) {
        QFile::remove(partPath);
        failDownload(savedError);
        return;
    }
    const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (httpStatus != 200) {
        QFile::remove(partPath);
        failDownload(httpStatus
                         ? uiText("The update server returned HTTP %1.").arg(httpStatus)
                         : uiText("Could not connect to the update server. %1")
                               .arg(reply->errorString()));
        return;
    }
    if (reply->error() != QNetworkReply::NoError) {
        QFile::remove(partPath);
        failDownload(reply->errorString());
        return;
    }
    if (!asset || bytesWritten != asset->size) {
        QFile::remove(partPath);
        failDownload(uiText("The downloaded file size does not match the release manifest."));
        return;
    }

    downloadStats_->setText(uiText("Verifying integrity (SHA-256)..."));
    if (QString::fromLatin1(computedHash) != asset->sha256) {
        QFile::remove(partPath);
        failDownload(uiText("The downloaded file failed SHA-256 verification."));
        return;
    }

    QFile::remove(finalPath);
    if (!QFile::rename(partPath, finalPath)) {
        QFile::remove(partPath);
        failDownload(uiText("Cannot save update file."));
        return;
    }

    downloadBar_->setValue(100);
    if (installHandler_) {
        status_->setStyleSheet({});
        status_->setText(uiText("Starting updater..."));
        downloadStats_->setText(uiText("Starting updater..."));
        QString launchError;
        if (!installHandler_(*asset, finalPath, launchError)) {
            failDownload(launchError.isEmpty() ? uiText("Cannot launch the updater.")
                                               : launchError);
            return;
        }
        return;
    }
    status_->setStyleSheet({});
    status_->setText(uiText("Update downloaded and verified."));
    downloadStats_->setText(uiText("Update downloaded and verified."));
    refreshUpdateButton();
}

void UpdateDialog::failDownload(const QString& message) {
    status_->setStyleSheet("color: " + palette().color(QPalette::BrightText).name() + ";");
    status_->setText(uiText("Download failed.") + "\n" + message);
    downloadStats_->setText(message);
    refreshUpdateButton();
}
