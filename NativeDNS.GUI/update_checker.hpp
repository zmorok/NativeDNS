#pragma once

#include <QDialog>
#include <QList>
#include <QPointer>
#include <QUrl>
#include <QVersionNumber>
#include <optional>

class QLabel;
class QPushButton;
class QTextBrowser;
class QNetworkAccessManager;
class QNetworkReply;
class QTimer;
class QAction;
class QMenu;

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

struct ReleaseManifest {
    QString version;
    QVersionNumber number;
    QUrl releaseUrl;
    QList<ReleaseChange> changes;
    QList<ReleaseCategory> categories;
};

inline constexpr qsizetype maximumUpdateManifestBytes = 512 * 1024;
QUrl updateManifestUrl();
bool startupUpdateCheckEnabled();
QAction* addStartupUpdateCheckAction(QMenu* menu);
std::optional<ReleaseManifest> parseReleaseManifest(const QByteArray& json, QString& error);

// Checks and displays release metadata only; package installation is separate.
class UpdateDialog final : public QDialog {
public:
    explicit UpdateDialog(const QString& currentVersion,
                          QWidget* parent = nullptr,
                          QNetworkAccessManager* network = nullptr);
    ~UpdateDialog() override;
    void check();
    void checkOnStart();
    void cancelStartupCheck();
    void showForManualCheck();

protected:
    void done(int result) override;

private:
    void cancelRequest();
    void startRequest();
    void readResponse();
    void finishRequest();
    void showFailure(const QString& message);
    void displayManifest(bool cached);

    QString currentVersion_;
    std::optional<ReleaseManifest> manifest_;
    QNetworkAccessManager* network_;
    QPointer<QNetworkReply> reply_;
    QTimer* deadline_;
    QByteArray response_;
    QString requestError_;
    QLabel* status_;
    QLabel* versions_;
    QLabel* notesTitle_;
    QTextBrowser* notes_;
    QPushButton* openRelease_;
    QPushButton* retry_;
    bool quiet_ = false;
};
