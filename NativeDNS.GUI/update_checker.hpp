#pragma once

#include <nativedns/platform.hpp>
#include <QDialog>
#include <QElapsedTimer>
#include <QList>
#include <QMap>
#include <QPointer>
#include <QUrl>
#include <QVersionNumber>
#include <functional>
#include <memory>
#include <optional>

class QLabel;
class QPushButton;
class QProgressBar;
class QTextBrowser;
class QNetworkAccessManager;
class QNetworkReply;
class QTimer;
class QAction;
class QMenu;
class QFile;
class QCryptographicHash;

struct ReleaseChange {
    QString commit;
    QString english;
    QString russian;
    QString category;
};

struct ReleaseCategory {
    QString id;
    QString english;
    QString russian;
};

struct ReleaseAsset {
    QString key;
    QString filename;
    QUrl url;
    qint64 size = 0;
    QString sha256;
};

struct ReleaseManifest {
    QString version;
    QVersionNumber number;
    QUrl releaseUrl;
    QList<ReleaseChange> changes;
    QList<ReleaseCategory> categories;
    QMap<QString, ReleaseAsset> assets;
};

inline constexpr qsizetype maximumUpdateManifestBytes = 512 * 1024;
inline constexpr qint64 maximumUpdateAssetBytes = 512ll * 1024 * 1024;
QUrl updateManifestUrl();
QString currentPlatformAssetKey(nd::platform::DistributionKind kind);
bool startupUpdateCheckEnabled();
QAction* addStartupUpdateCheckAction(QMenu* menu);
std::optional<ReleaseManifest> parseReleaseManifest(const QByteArray& json, QString& error);

class UpdateDialog final : public QDialog {
public:
    using InstallHandler =
        std::function<bool(const ReleaseAsset&, const QString& downloadedPath, QString& error)>;

    explicit UpdateDialog(const QString& currentVersion,
                          QWidget* parent = nullptr,
                          QNetworkAccessManager* network = nullptr);
    ~UpdateDialog() override;
    void setDistributionKind(nd::platform::DistributionKind kind);
    void setDownloadDirectory(const QString& directory);
    void setInstallHandler(InstallHandler handler);
    std::optional<ReleaseAsset> matchingAsset() const;
    void check();
    void checkOnStart();
    void cancelStartupCheck();
    void showForManualCheck();

protected:
    void done(int result) override;

private:
    void cancelRequest();
    void cancelDownload(bool showCanceledStatus);
    void startRequest();
    void readResponse();
    void finishRequest();
    void showFailure(const QString& message);
    void displayManifest(bool cached);
    void refreshUpdateButton();
    void startDownload();
    void readDownloadChunk();
    void updateDownloadProgress();
    void finishDownload();
    void failDownload(const QString& message);

    QString currentVersion_;
    std::optional<ReleaseManifest> manifest_;
    nd::platform::DistributionKind distributionKind_;
    QString downloadDirectory_;
    InstallHandler installHandler_;
    QNetworkAccessManager* network_;
    QPointer<QNetworkReply> reply_;
    QTimer* deadline_;
    QByteArray response_;
    QString requestError_;

    QPointer<QNetworkReply> downloadReply_;
    QTimer* downloadStallTimer_;
    QElapsedTimer downloadTimer_;
    std::unique_ptr<QFile> downloadPartFile_;
    std::unique_ptr<QCryptographicHash> downloadHash_;
    std::optional<ReleaseAsset> activeDownload_;
    QString downloadPartPath_;
    QString downloadFinalPath_;
    QString downloadError_;
    qint64 downloadedBytes_ = 0;
    qint64 expectedBytes_ = 0;

    QLabel* status_;
    QLabel* versions_;
    QLabel* notesTitle_;
    QTextBrowser* notes_;
    QWidget* downloadPanel_;
    QLabel* downloadFile_;
    QProgressBar* downloadBar_;
    QLabel* downloadStats_;
    QPushButton* updateButton_;
    QPushButton* cancelDownload_;
    QPushButton* openRelease_;
    QPushButton* retry_;
    bool quiet_ = false;
    bool newerAvailable_ = false;
};
