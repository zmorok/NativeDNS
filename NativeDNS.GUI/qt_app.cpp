#include "qt_app.hpp"
#include "update_checker.hpp"
#include "toolbar_button.hpp"
#include "bounded_table_header.hpp"
#include "log_filter_ui.hpp"
#include "action_icons.hpp"
#include "platform_launcher.hpp"
#include "window_activation.hpp"
#include "ui_preferences.hpp"
#include <nativedns/autostart.hpp>
#include <nativedns/dns.hpp>
#include <nativedns/dnscrypt.hpp>
#include <nativedns/ipc.hpp>
#include <nativedns/platform.hpp>
#include <nativedns/network_preflight.hpp>
#include <nativedns/router.hpp>
#include <QApplication>
#include <QAbstractTableModel>
#include <QAbstractItemView>
#include <QAction>
#include <QActionGroup>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QCursor>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDesktopServices>
#include <QDateTime>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QEvent>
#include <QEventLoop>
#include <QFileDialog>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHelpEvent>
#include <QIcon>
#include <QInputDialog>
#include <QIntValidator>
#include <QMimeData>
#include <QProcess>
#include <QProgressDialog>
#include <QItemSelectionModel>
#include <QKeyEvent>
#include <QLineEdit>
#include <QMenuBar>
#include <QMenu>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QResizeEvent>
#include <QScreen>
#include <QScrollBar>
#include <QStandardPaths>
#include <QStatusBar>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QTableWidget>
#include <QToolBar>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPointer>
#include <QMetaObject>
#include <QNetworkInformation>
#include <QNetworkInterface>
#include <QStringList>
#include <QBrush>
#include <QColor>
#include <QFileInfo>
#include <QFrame>
#include <QSignalBlocker>
#include <QSettings>
#include <QStyle>
#include <QStyleOptionComboBox>
#include <QThread>
#include <QThreadPool>
#include <QTextDocument>
#include <QToolTip>
#include <QUrl>
#include <cmath>
#include <thread>
#include <algorithm>
#include <functional>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <numeric>

namespace {
constexpr auto repositoryUrl = "https://github.com/zmorok/NativeDNS";
constexpr int ruleIdRole = Qt::UserRole + 1;
// Local IPC still needs scheduler time during adapter changes or system load.
// Polls run off the UI thread and have at most one outstanding request each.
constexpr uint32_t corePollTimeoutMs = 1500;
nd::IpcResponse readCoreStatus(const std::string& endpoint = nd::core_pipe_name) {
    return nd::pipe_request(endpoint, nd::IpcOperation::status, {}, corePollTimeoutMs);
}

QString coreHostExecutable() {
    return QString::fromUtf8(nd::platform::path_to_utf8(nd::platform::core_host_executable()).c_str());
}

QMessageBox* coreControlFailureDialog(QWidget* parent, const QString& details) {
    auto* dialog = new QMessageBox(QMessageBox::Critical,
                                   "NativeDNS",
                                   uiText("Connection to CoreHost was lost."),
                                   QMessageBox::NoButton,
                                   parent);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setTextFormat(Qt::PlainText);
    dialog->setWindowFlag(Qt::WindowStaysOnTopHint, true);
    dialog->setInformativeText(
        uiText("Core control is unavailable. Terminate NativeDNS and CoreHost, or close this "
               "window to keep waiting for recovery.") +
        "\n\n" + details);
    auto* terminate =
        dialog->addButton(uiText("Terminate application"), QMessageBox::DestructiveRole);
    terminate->setObjectName("terminateApplication");
    auto* close = dialog->addButton(uiText("Close"), QMessageBox::RejectRole);
    close->setObjectName("closeControlError");
    dialog->setDefaultButton(close);
    dialog->setEscapeButton(close);
    dialog->setWindowModality(Qt::NonModal);
    return dialog;
}

void showCriticalAlert(QWidget* parent, const QString& title, const QString& text) {
    QMessageBox dialog(QMessageBox::Critical, title, text, QMessageBox::Ok, parent);
    dialog.setTextFormat(Qt::PlainText);
    dialog.setWindowFlag(Qt::WindowStaysOnTopHint, true);
    dialog.show();
    activateApplicationWindow(dialog);
    QApplication::alert(&dialog);
    dialog.exec();
}

struct NetworkProbeSnapshot {
    bool available = false;
    QString signature;
};

std::optional<QNetworkInformation::Reachability> currentReachability() {
    if (const auto* information = QNetworkInformation::instance())
        return information->reachability();
    return std::nullopt;
}

NetworkProbeSnapshot probeNetwork(std::optional<QNetworkInformation::Reachability> reachability) {
    NetworkProbeSnapshot result;
    bool hasReachabilityDecision = false;
    if (reachability.has_value()) {
        if (*reachability == QNetworkInformation::Reachability::Online) {
            result.available = true;
            hasReachabilityDecision = true;
        } else if (*reachability != QNetworkInformation::Reachability::Unknown) {
            result.available = false;
            hasReachabilityDecision = true;
        }
    }
    QStringList parts;
    if (reachability.has_value())
        parts << QString::number(static_cast<int>(*reachability));
    for (const auto& interface : QNetworkInterface::allInterfaces()) {
        const auto flags = interface.flags();
        const bool activeNonLoopback = (flags & QNetworkInterface::IsUp) &&
                                       (flags & QNetworkInterface::IsRunning) &&
                                       !(flags & QNetworkInterface::IsLoopBack);
        if (!activeNonLoopback)
            continue;
        QStringList addresses;
        for (const auto& entry : interface.addressEntries()) {
            const auto ip = entry.ip();
            addresses << ip.toString();
            if (!hasReachabilityDecision && !ip.isNull() && !ip.isLoopback())
                result.available = true;
        }
        addresses.sort();
        parts << QString::number(interface.index()) + ':' + QString::number(static_cast<int>(flags)) +
                     ':' + addresses.join(',');
    }
    parts.sort();
    result.signature = parts.join(';');
    return result;
}

QThreadPool* serverTestPool(uint32_t concurrency) {
    static QPointer<QThreadPool> pool;
    if (!pool) {
        pool = new QThreadPool(qApp);
    }
    pool->setMaxThreadCount(std::clamp<int>(static_cast<int>(concurrency), 1, 16));
    return pool;
}

QString q(const std::string& value) {
    return QString::fromUtf8(value.c_str(), static_cast<int>(value.size()));
}
std::string s(const QString& value) {
    const auto bytes = value.toUtf8();
    return std::string(bytes.constData(), static_cast<size_t>(bytes.size()));
}
struct ReloadOutcome {
    bool ok = false;
    bool connectFailed = false;
    QString error;
};
ReloadOutcome executeConfigReload(const std::string& expected,
                                  const std::string& request,
                                  uint32_t timeoutMs) {
    ReloadOutcome outcome;
    try {
        const auto response = nd::pipe_request(
            nd::core_pipe_name, nd::IpcOperation::reload_config, request, timeoutMs);
        if (response.status || response.payload != "RELOADED config_id=" + expected) {
            outcome.error = response.status
                                ? q(response.payload)
                                : uiText("CoreHost did not confirm the expected configuration");
        } else {
            outcome.ok = true;
        }
    } catch (const nd::Error& error) {
        if (error.code == "IPC_CONNECT")
            outcome.connectFailed = true;
        else
            outcome.error = q(error.what());
    } catch (const std::exception& error) {
        outcome.error = q(error.what());
    }
    return outcome;
}
std::filesystem::path fsPath(const QString& value) {
#ifdef _WIN32
    return std::filesystem::path(value.toStdWString());
#else
    return std::filesystem::path(s(value));
#endif
}
QString qPath(const std::filesystem::path& value) {
#ifdef _WIN32
    return QString::fromStdWString(value.wstring());
#else
    return q(value.string());
#endif
}
QString protocolText(nd::Protocol p) {
    switch (p) {
        case nd::Protocol::udp:
            return "UDP";
        case nd::Protocol::tcp:
            return "TCP";
        case nd::Protocol::doh:
            return "DoH";
        case nd::Protocol::dot:
            return "DoT";
        case nd::Protocol::doh3:
            return "DoH3";
        case nd::Protocol::doq:
            return "DoQ";
        case nd::Protocol::dnscrypt:
            return "DNSCrypt";
        case nd::Protocol::anonymized_dnscrypt:
            return uiText("Anonymized DNSCrypt");
    }
    return {};
}
nd::Protocol protocolFrom(int index) {
    static const nd::Protocol values[]{nd::Protocol::udp,
                                       nd::Protocol::tcp,
                                       nd::Protocol::doh,
                                       nd::Protocol::dot,
                                       nd::Protocol::doh3,
                                       nd::Protocol::doq,
                                       nd::Protocol::dnscrypt,
                                       nd::Protocol::anonymized_dnscrypt};
    return values[std::clamp(index, 0, 7)];
}
int protocolIndex(nd::Protocol p) {
    for (int i = 0; i < 8; ++i)
        if (protocolFrom(i) == p)
            return i;
    return 0;
}
QString joinPatterns(const std::vector<std::string>& patterns) {
    QStringList list;
    for (const auto& p : patterns)
        list << q(p);
    return list.join(";\n");
}
QString previewPatterns(const std::vector<std::string>& patterns) {
    QStringList list;
    for (const auto& p : patterns)
        list << q(p);
    return list.join("; ");
}
QString protocolFullText(nd::Protocol p) {
    switch (p) {
        case nd::Protocol::udp:
            return "Plain";
        case nd::Protocol::tcp:
            return "TCP";
        case nd::Protocol::doh:
            return "DNS over HTTPS";
        case nd::Protocol::dot:
            return "DNS over TLS";
        case nd::Protocol::doh3:
            return "DNS over HTTPS/3";
        case nd::Protocol::doq:
            return "DNS over QUIC";
        case nd::Protocol::dnscrypt:
            return "DNSCrypt";
        case nd::Protocol::anonymized_dnscrypt:
            return uiText("Anonymized DNSCrypt");
    }
    return {};
}
uint32_t nextServerId(const nd::Config& c) {
    uint32_t id = 0;
    for (const auto& v : c.servers)
        id = std::max(id, v.id);
    return id + 1;
}
uint32_t nextPoolId(const nd::Config& c) {
    uint32_t id = 0;
    for (const auto& v : c.pools)
        id = std::max(id, v.id);
    return id + 1;
}
uint32_t nextRuleId(const nd::Config& c) {
    uint32_t id = 0;
    for (const auto& v : c.rules)
        id = std::max(id, v.id);
    return id + 1;
}

constexpr qulonglong kPoolTargetFlag = 1ULL << 32;
qulonglong encodeRuleTarget(uint32_t serverId, uint32_t poolId) {
    if (poolId)
        return kPoolTargetFlag | static_cast<qulonglong>(poolId);
    return static_cast<qulonglong>(serverId);
}
bool isPoolTarget(qulonglong encoded) {
    return (encoded & kPoolTargetFlag) != 0;
}
uint32_t targetId(qulonglong encoded) {
    return static_cast<uint32_t>(encoded & 0xFFFFFFFFULL);
}

class AnchoredComboBox final : public QComboBox {
public:
    explicit AnchoredComboBox(QWidget* parent = nullptr) : QComboBox(parent) {
        setMaxVisibleItems(14);
        if (auto* v = view()) {
            v->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
            v->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            v->setTextElideMode(Qt::ElideRight);
        }
    }
    void openPopup() {
        showPopup();
    }

protected:
    void showPopup() override {
        const bool dark = palette().color(QPalette::Window).lightness() < 128;
        view()->setStyleSheet(
            dark ? "QAbstractItemView { background-color: #252526; color: #f0f0f0; "
                   "selection-background-color: #35495c; selection-color: #f0f0f0; outline: 0; }"
                   "QAbstractItemView::item:hover, QAbstractItemView::item:selected { "
                   "background-color: #35495c; color: #f0f0f0; }"
                 : "QAbstractItemView { background-color: #ffffff; color: #202020; "
                   "selection-background-color: #d7ebf9; selection-color: #202020; outline: 0; }"
                   "QAbstractItemView::item:hover, QAbstractItemView::item:selected { "
                   "background-color: #d7ebf9; color: #202020; }");
        view()->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        view()->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        view()->setTextElideMode(Qt::ElideRight);

        const auto computeGeometry = [this]() -> QRect {
            const QPoint topLeft = mapToGlobal(QPoint(0, 0));
            const QPoint bottomLeft = mapToGlobal(QPoint(0, height()));
            QScreen* scr = QGuiApplication::screenAt(mapToGlobal(rect().center()));
            if (!scr)
                scr = screen();
            if (!scr)
                scr = QGuiApplication::primaryScreen();
            const QRect avail = scr ? scr->availableGeometry() : QRect(0, 0, 1920, 1080);

            const QFontMetrics fm(view()->font());
            int totalRowsHeight = 0;
            int visibleCapHeight = 0;
            int textWidth = 0;
            const int rowCount = count();
            const int maxVis = std::max(1, maxVisibleItems());
            for (int r = 0; r < rowCount; ++r) {
                int rh = view()->sizeHintForRow(r);
                if (rh <= 0)
                    rh = fm.height() + 6;
                totalRowsHeight += rh;
                if (r < maxVis)
                    visibleCapHeight += rh;
                const QString text = itemText(r);
                if (!text.isEmpty())
                    textWidth = std::max(textWidth, fm.horizontalAdvance(text));
            }
            const int frame = view()->frameWidth() * 2 + 6;
            const int desiredHeight =
                std::max(40, std::min(totalRowsHeight, visibleCapHeight) + frame);

            const int spaceBelow = avail.bottom() - bottomLeft.y() - 4;
            const int spaceAbove = topLeft.y() - avail.top() - 4;
            int popupHeight = desiredHeight;
            int popupY = bottomLeft.y();
            if (spaceBelow >= desiredHeight || spaceBelow >= spaceAbove) {
                popupHeight = std::min(desiredHeight, std::max(40, spaceBelow));
                popupY = std::min(bottomLeft.y(), avail.bottom() - popupHeight + 1);
            } else {
                popupHeight = std::min(desiredHeight, std::max(40, spaceAbove));
                popupY = std::max(avail.top(), topLeft.y() - popupHeight);
            }

            const bool needsScroll = totalRowsHeight + frame > popupHeight;
            const int scrollWidth =
                needsScroll ? style()->pixelMetric(QStyle::PM_ScrollBarExtent) + 6 : 0;
            const int maxWidth = std::max(width(), avail.width() - 16);
            const int desiredWidth = textWidth + scrollWidth + view()->frameWidth() * 2 + 32;
            const int popupWidth = std::clamp(std::max(width(), desiredWidth), width(), maxWidth);

            int popupX = bottomLeft.x();
            if (popupWidth > width()) {
                const QWidget* topWin = window();
                const int rightLimit =
                    topWin ? std::min(avail.right(), topWin->frameGeometry().right() - 4)
                           : avail.right();
                if (popupX + popupWidth - 1 > rightLimit) {
                    const int rightAlignedX = bottomLeft.x() + width() - popupWidth;
                    if (rightAlignedX >= avail.left())
                        popupX = rightAlignedX;
                }
            }
            popupX = std::clamp(
                popupX, avail.left(), std::max(avail.left(), avail.right() - popupWidth + 1));

            return QRect(popupX, popupY, popupWidth, popupHeight);
        };

        const QRect initialRect = computeGeometry();
        view()->setMinimumWidth(std::max(0, initialRect.width() - 4));
        QComboBox::showPopup();
        QPointer<QWidget> popup = view()->window();
        const auto applyPopupGeometry = [this, popup, computeGeometry] {
            if (!popup || !popup->isVisible())
                return;
            const QRect target = computeGeometry();
            view()->setMinimumWidth(std::max(0, target.width() - 4));
            popup->setMinimumWidth(width());
            popup->setMaximumWidth(QWIDGETSIZE_MAX);
            popup->setGeometry(target);
        };
        applyPopupGeometry();
        QTimer::singleShot(0, this, applyPopupGeometry);
    }
};

struct ComboOption {
    QString text;
    qulonglong value = 0;
    bool separator = false;
};

std::vector<ComboOption> buildRuleTargetOptions(const nd::Config& config) {
    std::vector<ComboOption> options;
    options.reserve(config.pools.size() + config.servers.size() + 2);
    if (!config.pools.empty()) {
        for (const auto& pool : config.pools)
            options.push_back({QStringLiteral("P| ") + q(pool.name),
                               encodeRuleTarget(0, pool.id),
                               false});
        options.push_back({{}, 0, true});
    }
    options.push_back({uiText("Original/System"), 0, false});
    for (const auto& server : config.servers)
        options.push_back({QStringLiteral("S| ") + q(server.name),
                           encodeRuleTarget(server.id, 0),
                           false});
    return options;
}

void populateRuleTargetCombo(QComboBox& combo, const nd::Config& config) {
    combo.clear();
    for (const auto& option : buildRuleTargetOptions(config)) {
        if (option.separator)
            combo.insertSeparator(combo.count());
        else
            combo.addItem(option.text, QVariant::fromValue(option.value));
    }
}

class LazyComboDelegate final : public QStyledItemDelegate {
public:
    using Options = std::function<std::vector<ComboOption>()>;
    using Changed = std::function<void(const QModelIndex&, qulonglong)>;

    LazyComboDelegate(Options options, Changed changed, QObject* parent)
        : QStyledItemDelegate(parent), options_(std::move(options)), changed_(std::move(changed)) {
    }

    QWidget*
    createEditor(QWidget* parent, const QStyleOptionViewItem&, const QModelIndex&) const override {
        auto* editor = new AnchoredComboBox(parent);
        for (const auto& option : options_()) {
            if (option.separator)
                editor->insertSeparator(editor->count());
            else
                editor->addItem(option.text, QVariant::fromValue(option.value));
        }
        connect(editor, qOverload<int>(&QComboBox::activated), editor, [this, editor] {
            editor->setProperty("choiceActivated", true);
            auto* self = const_cast<LazyComboDelegate*>(this);
            emit self->commitData(editor);
            emit self->closeEditor(editor);
        });
        return editor;
    }

    void paint(QPainter* painter,
               const QStyleOptionViewItem& option,
               const QModelIndex& index) const override {
        QStyleOptionComboBox combo;
        combo.rect = option.rect;
        combo.state = option.state;
        combo.direction = option.direction;
        combo.fontMetrics = option.fontMetrics;
        combo.palette = option.palette;
        if (!(index.flags() & Qt::ItemIsEditable))
            combo.state &= ~QStyle::State_Enabled;
        combo.currentText = index.data(Qt::DisplayRole).toString();
        combo.frame = true;
        auto* style = option.widget ? option.widget->style() : QApplication::style();
        style->drawComplexControl(QStyle::CC_ComboBox, &combo, painter, option.widget);
        style->drawControl(QStyle::CE_ComboBoxLabel, &combo, painter, option.widget);
    }

    void setEditorData(QWidget* editor, const QModelIndex& index) const override {
        auto* combo = static_cast<AnchoredComboBox*>(editor);
        const int selected = combo->findData(index.data(Qt::UserRole));
        combo->setCurrentIndex(selected >= 0 ? selected : 0);
        QTimer::singleShot(0, combo, [combo] { combo->openPopup(); });
    }

    void setModelData(QWidget* editor,
                      QAbstractItemModel* model,
                      const QModelIndex& index) const override {
        (void)model;
        const auto* combo = static_cast<QComboBox*>(editor);
        // Focus loss or Escape must not apply the clicked row's value to other rows.
        if (!combo->property("choiceActivated").toBool())
            return;
        const auto value = combo->currentData().toULongLong();
        changed_(index, value);
    }

private:
    Options options_;
    Changed changed_;
};

void positionDialog(QDialog& dialog, QWidget* parent) {
    if (!parent)
        return;
    const auto center = parent->window()->frameGeometry().center();
    dialog.move(center - QPoint(dialog.width() / 2, dialog.height() / 2));
}

void translateDialogButtons(QDialogButtonBox* buttons) {
    if (auto* ok = buttons->button(QDialogButtonBox::Ok))
        ok->setText(uiText("OK"));
    if (auto* cancel = buttons->button(QDialogButtonBox::Cancel))
        cancel->setText(uiText("Cancel"));
}

void configureFixedTableRows(QTableView* table) {
    const int height = table->fontMetrics().height() + 8;
    table->setWordWrap(false);
    table->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table->verticalHeader()->setMinimumSectionSize(height);
    table->verticalHeader()->setDefaultSectionSize(height);
}

void setFormFieldEnabled(QFormLayout* form, QWidget* field, bool enabled) {
    field->setEnabled(enabled);
    if (auto* label = form->labelForField(field))
        label->setEnabled(enabled);
}

void showAboutDialog(QWidget* parent) {
    QDialog dialog(parent);
    dialog.setWindowTitle(uiText("About"));
    dialog.setWindowIcon(QApplication::windowIcon());
    dialog.setModal(true);

    auto* icon = new QLabel(&dialog);
    icon->setPixmap(QApplication::windowIcon().pixmap(64, 64));
    icon->setAlignment(Qt::AlignTop | Qt::AlignHCenter);

    const auto distColor = dialog.palette().color(QPalette::PlaceholderText).name();
    const auto distLabel =
        QString::fromLatin1(nd::platform::distribution_label(nd::platform::distribution_kind()))
            .toHtmlEscaped();
    auto* description = new QLabel(
        "<b>NativeDNS</b> <span style=\"color:" + distColor + ";\">" + distLabel + "</span><br>" +
            uiText("Cross-platform DNS client") + "<br>Qt 6 + native C++ Core",
        &dialog);
    description->setTextFormat(Qt::RichText);

    auto* summary = new QHBoxLayout;
    summary->addWidget(icon);
    summary->addSpacing(10);
    summary->addWidget(description, 1);

    auto* separator = new QFrame(&dialog);
    separator->setFrameShape(QFrame::HLine);
    separator->setFrameShadow(QFrame::Sunken);

    const auto version = QCoreApplication::applicationVersion().toHtmlEscaped();
    auto* details =
        new QLabel(uiText("Version") + " " + version + " &nbsp;&nbsp; <a href=\"" +
                       QString(repositoryUrl) + "\">" + uiText("GitHub repository") + "</a>",
                   &dialog);
    details->setTextFormat(Qt::RichText);
    details->setTextInteractionFlags(Qt::TextBrowserInteraction);
    details->setOpenExternalLinks(true);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok, &dialog);
    translateDialogButtons(buttons);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);

    auto* root = new QVBoxLayout(&dialog);
    root->addLayout(summary);
    root->addWidget(separator);
    root->addWidget(details);
    root->addWidget(buttons);
    dialog.setFixedSize(dialog.sizeHint());
    positionDialog(dialog, parent);
    dialog.exec();
}

QString friendlyCoreStatus(const QString& raw) {
    const auto parts = raw.split(' ', Qt::SkipEmptyParts);
    if (parts.isEmpty())
        return uiText("Core: Unknown");
    auto value = [&](const QString& key) {
        for (const auto& part : parts)
            if (part.startsWith(key + '='))
                return part.mid(key.size() + 1);
        return QString{};
    };
    const auto state = parts.front();
    if (state == "ERROR") {
        const auto marker = raw.indexOf(" error=");
        return marker >= 0 ? uiText("Core: Error") + " | " + raw.mid(marker + 7)
                           : uiText("Core: Error");
    }
    QString stateText = state.toLower();
    if (!stateText.isEmpty())
        stateText[0] = stateText[0].toUpper();
    if (state != "RUNNING")
        return uiText(("Core: " + stateText).toUtf8().constData());
    const QString mode =
        value("transparent") == "1" ? uiText("Transparent") : uiText("Local proxy");
    const QString udp = value("udp") == "1" ? uiText("Active") : uiText("Inactive");
    const QString tcp = value("tcp") == "1" ? uiText("Active") : uiText("Inactive");
    return uiText("Core: Running") + " | " + uiText("Mode") + ": " + mode + " | " +
           uiText("DNS port") + ": " + value("port") + " | UDP: " + udp + " | TCP: " + tcp;
}

void setInputValidationError(QWidget* field, bool invalid) {
    if (!field)
        return;
    field->setProperty("validationError", invalid);
    if (invalid) {
        const auto* ref = field->window() ? field->window() : field;
        const bool dark = ref->palette().color(QPalette::Window).lightness() < 128;
        const QString color = dark ? QStringLiteral("#ff5555") : QStringLiteral("#d32f2f");
        if (qobject_cast<QPlainTextEdit*>(field))
            field->setStyleSheet(
                QStringLiteral("QPlainTextEdit { border: 2px solid %1; }").arg(color));
        else
            field->setStyleSheet(QStringLiteral("QLineEdit { border: 2px solid %1; }").arg(color));
    } else {
        field->setStyleSheet(QString{});
    }
}

bool editServer(QWidget* parent,
                nd::Server& server,
                const std::function<void(const nd::Server&)>& validateCandidate = {}) {
    QDialog dialog(parent);
    dialog.setObjectName("serverEditorDialog");
    dialog.setWindowTitle(server.id ? uiText("DNS Server") : uiText("Add DNS Server"));
    dialog.resize(520, 460);
    auto* form = new QFormLayout;
    QLineEdit name(q(server.name)), ip(q(server.ip)), host(q(server.hostname)), url(q(server.url)),
        port(server.port ? QString::number(server.port) : QString()), bootstrap,
        publicKey(q(server.public_key)), provider(q(server.provider_name)), relay(q(server.relay));
    name.setObjectName("serverNameEdit");
    ip.setObjectName("serverIpEdit");
    port.setObjectName("serverPortEdit");
    host.setObjectName("serverHostnameEdit");
    url.setObjectName("serverUrlEdit");
    bootstrap.setObjectName("serverBootstrapEdit");
    publicKey.setObjectName("serverPublicKeyEdit");
    provider.setObjectName("serverProviderEdit");
    relay.setObjectName("serverRelayEdit");
    AnchoredComboBox protocol;
    protocol.setObjectName("serverProtocolCombo");
    for (int i = 0; i < 8; ++i)
        protocol.addItem(protocolText(protocolFrom(i)));
    protocol.setCurrentIndex(protocolIndex(server.protocol));
    QCheckBox enabled(uiText("Enabled")), dnssec(uiText("DNSSEC supported")),
        directCertificateFallback(uiText("Allow direct certificate fallback"));
    enabled.setChecked(server.enabled);
    dnssec.setChecked(server.dnssec_supported);
    directCertificateFallback.setChecked(server.allow_direct_certificate_fallback);
    bootstrap.setText([&] {
        QStringList x;
        for (const auto& v : server.bootstrap)
            x << q(v);
        return x.join(';');
    }());
    form->addRow(uiText("Name:"), &name);
    form->addRow(uiText("Protocol:"), &protocol);
    form->addRow(uiText("IP:"), &ip);
    form->addRow(uiText("Port:"), &port);
    form->addRow(uiText("Hostname:"), &host);
    form->addRow(uiText("URL:"), &url);
    form->addRow(uiText("Bootstrap:"), &bootstrap);
    form->addRow(uiText("Public key:"), &publicKey);
    form->addRow(uiText("Provider:"), &provider);
    form->addRow(uiText("Relay:"), &relay);
    form->addRow(&directCertificateFallback);
    form->addRow(&enabled);
    form->addRow(&dnssec);

    const std::array<QLineEdit*, 9> allInputs{
        &name, &ip, &port, &host, &url, &bootstrap, &publicKey, &provider, &relay};
    const auto clearAllErrors = [&] {
        for (auto* field : allInputs)
            setInputValidationError(field, false);
    };
    for (auto* field : allInputs) {
        QObject::connect(field, &QLineEdit::textChanged, &dialog, [field] {
            if (field->property("validationError").toBool())
                setInputValidationError(field, false);
        });
    }

    auto update = [&] {
        clearAllErrors();
        const auto p = protocolFrom(protocol.currentIndex());
        const bool plain = p == nd::Protocol::udp || p == nd::Protocol::tcp;
        const bool doh = p == nd::Protocol::doh || p == nd::Protocol::doh3;
        const bool dot = p == nd::Protocol::dot || p == nd::Protocol::doq;
        const bool crypt = p == nd::Protocol::dnscrypt || p == nd::Protocol::anonymized_dnscrypt;
        setFormFieldEnabled(form, &ip, plain || crypt || dot || doh);
        setFormFieldEnabled(form, &url, doh);
        setFormFieldEnabled(form, &host, dot || doh);
        setFormFieldEnabled(form, &publicKey, crypt);
        setFormFieldEnabled(form, &provider, crypt);
        setFormFieldEnabled(form, &relay, p == nd::Protocol::anonymized_dnscrypt);
        directCertificateFallback.setEnabled(p == nd::Protocol::anonymized_dnscrypt);
    };
    QObject::connect(&protocol, &QComboBox::currentIndexChanged, &dialog, [&] { update(); });
    update();

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    translateDialogButtons(buttons);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, [&] {
        clearAllErrors();
        QLineEdit* firstInvalid = nullptr;
        QStringList errors;
        const auto flagInvalid = [&](QLineEdit* field, const QString& msg) {
            if (!field->property("validationError").toBool())
                setInputValidationError(field, true);
            if (!firstInvalid)
                firstInvalid = field;
            if (!msg.isEmpty() && !errors.contains(msg))
                errors << msg;
        };

        nd::Server candidate = server;
        candidate.name = s(name.text().trimmed());
        if (candidate.name.empty())
            flagInvalid(&name, uiText("Server name must not be empty."));

        candidate.protocol = protocolFrom(protocol.currentIndex());
        const bool plain =
            candidate.protocol == nd::Protocol::udp || candidate.protocol == nd::Protocol::tcp;
        const bool doh =
            candidate.protocol == nd::Protocol::doh || candidate.protocol == nd::Protocol::doh3;
        const bool dot =
            candidate.protocol == nd::Protocol::dot || candidate.protocol == nd::Protocol::doq;
        const bool crypt = candidate.protocol == nd::Protocol::dnscrypt ||
                           candidate.protocol == nd::Protocol::anonymized_dnscrypt;

        const QString portText = port.text().trimmed();
        if (portText.isEmpty()) {
            candidate.port = 0;
        } else {
            bool okPort = false;
            const uint portValue = portText.toUInt(&okPort);
            if (!okPort || portValue == 0 || portValue > 65535)
                flagInvalid(&port, uiText("Port must be between 1 and 65535."));
            else
                candidate.port = static_cast<uint16_t>(portValue);
        }

        candidate.ip = s(ip.text().trimmed());
        if (!candidate.ip.empty()) {
            try {
                (void)nd::parse_numeric_endpoint(candidate.ip);
            } catch (const std::exception& e) {
                flagInvalid(&ip, q(e.what()));
            }
        } else if (plain) {
            flagInvalid(&ip, QStringLiteral("Plain server requires IP"));
        } else if (crypt) {
            flagInvalid(&ip, QStringLiteral("DNSCrypt server requires a numeric IP"));
        }

        candidate.hostname = s(host.text().trimmed());
        if (dot || (doh && !candidate.hostname.empty())) {
            try {
                (void)nd::normalize_host(candidate.hostname);
            } catch (const std::exception& e) {
                flagInvalid(&host, q(e.what()));
            }
        }

        candidate.url = s(url.text().trimmed());
        if (doh) {
            if (!candidate.url.starts_with("https://") ||
                candidate.url.find_first_of("\r\n\t ") != std::string::npos ||
                candidate.url.find('@') != std::string::npos) {
                flagInvalid(
                    &url,
                    QStringLiteral("DoH requires HTTPS URL without credentials or whitespace"));
            } else {
                const auto slash = candidate.url.find('/', 8);
                const auto authority = candidate.url.substr(
                    8, slash == std::string::npos ? std::string::npos : slash - 8);
                if (authority.empty())
                    flagInvalid(&url, QStringLiteral("Empty DoH host"));
            }
        }

        candidate.bootstrap.clear();
        for (const auto& part : bootstrap.text().split(';', Qt::SkipEmptyParts)) {
            const QString trimmed = part.trimmed();
            if (trimmed.isEmpty())
                continue;
            const std::string entry = s(trimmed);
            candidate.bootstrap.push_back(entry);
            bool validBootstrap = false;
            try {
                (void)nd::parse_numeric_endpoint(entry);
                validBootstrap = true;
            } catch (...) {
                // Also accept numeric ip:port / [ipv6]:port syntax.
                std::string hostPart = entry;
                std::string portPart;
                if (!entry.empty() && entry.front() == '[') {
                    const auto close = entry.find(']');
                    if (close != std::string::npos && close + 2 < entry.size() &&
                        entry[close + 1] == ':') {
                        hostPart = entry.substr(1, close - 1);
                        portPart = entry.substr(close + 2);
                    }
                } else {
                    const auto colon = entry.rfind(':');
                    if (colon != std::string::npos && entry.find(':') == colon) {
                        hostPart = entry.substr(0, colon);
                        portPart = entry.substr(colon + 1);
                    }
                }
                if (!portPart.empty()) {
                    bool okBp = false;
                    const uint bp = q(portPart).toUInt(&okBp);
                    if (okBp && bp >= 1 && bp <= 65535) {
                        try {
                            (void)nd::parse_numeric_endpoint(hostPart);
                            validBootstrap = true;
                        } catch (...) {
                        }
                    }
                }
            }
            if (!validBootstrap)
                flagInvalid(&bootstrap, uiText("Bootstrap entries must be numeric IP addresses."));
        }

        candidate.public_key = s(publicKey.text().trimmed());
        candidate.provider_name = s(provider.text().trimmed());
        candidate.relay = s(relay.text().trimmed());
        if (crypt) {
            try {
                (void)nd::normalize_host(candidate.provider_name);
            } catch (const std::exception& e) {
                flagInvalid(&provider, q(e.what()));
            }
            try {
                (void)nd::parse_dnscrypt_provider_key(candidate.public_key);
            } catch (const std::exception& e) {
                flagInvalid(&publicKey, q(e.what()));
            }
            if (candidate.protocol == nd::Protocol::anonymized_dnscrypt) {
                nd::Server relayCheck = candidate;
                relayCheck.ip = "1.1.1.1";
                relayCheck.provider_name = "2.dnscrypt-cert.example";
                relayCheck.public_key = std::string(64, '0');
                try {
                    nd::validate_dnscrypt_server(relayCheck);
                } catch (const std::exception& e) {
                    flagInvalid(&relay, q(e.what()));
                }
            }
        }

        candidate.enabled = enabled.isChecked();
        candidate.dnssec_supported = dnssec.isChecked();
        candidate.allow_direct_certificate_fallback =
            candidate.protocol == nd::Protocol::anonymized_dnscrypt &&
            directCertificateFallback.isChecked();

        if (errors.isEmpty() && validateCandidate) {
            try {
                validateCandidate(candidate);
            } catch (const std::exception& e) {
                errors << q(e.what());
            }
        }

        if (!errors.isEmpty()) {
            if (firstInvalid) {
                firstInvalid->setFocus();
                firstInvalid->selectAll();
            }
            QMessageBox box(
                QMessageBox::Critical, "NativeDNS", errors.join('\n'), QMessageBox::Ok, &dialog);
            box.setObjectName("serverValidationErrorBox");
            box.exec();
            return;
        }

        server = std::move(candidate);
        dialog.accept();
    });

    auto* root = new QVBoxLayout(&dialog);
    root->addLayout(form);
    root->addWidget(buttons);
    positionDialog(dialog, parent);
    return dialog.exec() == QDialog::Accepted;
}

class ServerDialog final : public QDialog {
public:
    ~ServerDialog() override {
        *cancelled_ = true;
        if (auto* pool = serverTestPool(working_.test_concurrency))
            pool->clear();
    }
    ServerDialog(QWidget* parent, nd::Config& config, std::function<bool()> changed)
        : QDialog(parent), target_(config), original_(config), working_(config),
          changed_(std::move(changed)) {
        setWindowTitle(uiText("DNS Servers"));
        resize(860, 460);
        table_ = new QTableWidget(this);
        table_->setColumnCount(5);
        table_->setHorizontalHeaderLabels(
            {uiText("Name"), uiText("Protocol"), uiText("Address"), uiText("Status"), "RTT"});
        new BoundedTableHeader(table_, {120, 85, 160, 95, 70}, 0, 2, 5);
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        configureFixedTableRows(table_);

        auto* add = new QPushButton(uiText("Add"));
        auto* edit = new QPushButton(uiText("Edit"));
        auto* clone = new QPushButton(uiText("Clone"));
        auto* remove = new QPushButton(uiText("Remove"));
        check_ = new QPushButton(uiText("Check"));
        checkAll_ = new QPushButton(uiText("Check All"));
        auto* ok = new QPushButton(uiText("OK"));
        auto* close = new QPushButton(uiText("Close"));
        auto* side = new QVBoxLayout;
        side->addWidget(add);
        side->addWidget(edit);
        side->addWidget(clone);
        side->addWidget(remove);
        side->addSpacing(add->sizeHint().height());
        side->addWidget(check_);
        side->addWidget(checkAll_);
        side->addStretch();
        auto* content = new QHBoxLayout;
        content->addWidget(table_, 1);
        content->addLayout(side);
        auto* bottom = new QHBoxLayout;
        bottom->addWidget(ok);
        bottom->addStretch();
        bottom->addWidget(close);
        auto* root = new QVBoxLayout(this);
        root->addLayout(content, 1);
        root->addLayout(bottom);

        connect(add, &QPushButton::clicked, this, [this] {
            nd::Server server;
            server.id = nextServerId(working_);
            server.name = s(uiText("New DNS Server"));
            const auto validateAdd = [this](const nd::Server& candidate) {
                nd::ConfigEditor editor(working_);
                editor.add_server(candidate);
            };
            if (!editServer(this, server, validateAdd))
                return;
            try {
                nd::ConfigEditor editor(working_);
                editor.add_server(server);
                working_ = editor.get();
                reload(server.id);
            } catch (const std::exception& e) {
                QMessageBox::critical(this, "NativeDNS", e.what());
            }
        });
        connect(edit, &QPushButton::clicked, this, [this] {
            const auto rows = table_->selectionModel()->selectedRows();
            if (rows.size() != 1)
                return;
            const int row = rows.front().row();
            auto server = working_.servers[static_cast<size_t>(row)];
            const auto validateEdit = [this](const nd::Server& candidate) {
                nd::ConfigEditor editor(working_);
                editor.update_server(candidate);
            };
            if (!editServer(this, server, validateEdit))
                return;
            try {
                nd::ConfigEditor editor(working_);
                editor.update_server(server);
                working_ = editor.get();
                reload(server.id);
            } catch (const std::exception& e) {
                QMessageBox::critical(this, "NativeDNS", e.what());
            }
        });
        const auto updateSelectionControls = [this, edit, clone, remove] {
            const auto selected = table_->selectionModel()->selectedRows();
            const bool single = selected.size() == 1;
            edit->setEnabled(single);
            clone->setEnabled(single);
            remove->setEnabled(single);
            check_->setEnabled(!working_.servers.empty() &&
                               (!selected.isEmpty() || table_->currentRow() >= 0));
        };
        updateSelectionControls_ = updateSelectionControls;
        connect(table_->selectionModel(),
                &QItemSelectionModel::selectionChanged,
                this,
                updateSelectionControls);
        connect(table_->selectionModel(),
                &QItemSelectionModel::currentRowChanged,
                this,
                updateSelectionControls);
        connect(clone, &QPushButton::clicked, this, [this] {
            const auto rows = table_->selectionModel()->selectedRows();
            if (rows.size() != 1)
                return;
            auto server = working_.servers[static_cast<size_t>(rows.front().row())];
            server.id = nextServerId(working_);
            server.name += " (copy)";
            try {
                nd::ConfigEditor editor(working_);
                editor.add_server(server);
                working_ = editor.get();
                reload(server.id);
            } catch (const std::exception& e) {
                QMessageBox::critical(this, "NativeDNS", e.what());
            }
        });
        connect(remove, &QPushButton::clicked, this, [this] {
            const auto rows = table_->selectionModel()->selectedRows();
            if (rows.size() != 1)
                return;
            const int row = rows.front().row();
            if (QMessageBox::question(this, "NativeDNS", uiText("Remove selected DNS server?")) !=
                QMessageBox::Yes)
                return;
            try {
                nd::ConfigEditor editor(working_);
                editor.remove_server(working_.servers[static_cast<size_t>(row)].id);
                working_ = editor.get();
                reload();
            } catch (const std::exception& e) {
                QMessageBox::critical(this, "NativeDNS", e.what());
            }
        });
        connect(check_, &QPushButton::clicked, this, [this] { checkSelected(); });
        connect(checkAll_, &QPushButton::clicked, this, [this] { checkAll(); });
        connect(ok, &QPushButton::clicked, this, [this] { commit(); });
        connect(close, &QPushButton::clicked, this, &QDialog::reject);
        connect(
            table_, &QTableWidget::cellDoubleClicked, this, [edit](int, int) { edit->click(); });
        reload();
    }

private:
    static std::string address(const nd::Server& server) {
        return !server.url.empty()
                   ? server.url
                   : (!server.hostname.empty()
                          ? server.hostname
                          : server.ip + (server.port ? ":" + std::to_string(server.port) : ""));
    }
    static void bold(QTableWidgetItem* item, bool enabled) {
        auto font = item->font();
        font.setBold(enabled);
        item->setFont(font);
    }
    const nd::Server* original(uint32_t id) const {
        const auto found = std::find_if(original_.servers.begin(),
                                        original_.servers.end(),
                                        [id](const nd::Server& server) { return server.id == id; });
        return found == original_.servers.end() ? nullptr : &*found;
    }
    void commit() {
        if (working_ == original_) {
            accept();
            return;
        }
        const auto previous = target_;
        target_ = working_;
        if (changed_()) {
            original_ = working_;
            accept();
        } else
            target_ = previous;
    }
    void reload(uint32_t selectedId = 0) {
        table_->setUpdatesEnabled(false);
        table_->clearContents();
        table_->setRowCount(static_cast<int>(working_.servers.size()));
        int selectedRow = -1;
        for (int row = 0; row < table_->rowCount(); ++row) {
            const auto& server = working_.servers[static_cast<size_t>(row)];
            if (server.id == selectedId)
                selectedRow = row;
            auto* name = new QTableWidgetItem(q(server.name));
            auto* protocol = new QTableWidgetItem(protocolText(server.protocol));
            auto* serverAddress = new QTableWidgetItem(q(address(server)));
            auto* status = new QTableWidgetItem(uiText("Not tested"));
            auto* rtt = new QTableWidgetItem("—");
            const auto* before = original(server.id);
            const bool added = !before;
            bold(name,
                 added || before->name != server.name || before->enabled != server.enabled ||
                     before->dnssec_supported != server.dnssec_supported);
            bold(protocol, added || before->protocol != server.protocol);
            bold(serverAddress,
                 added || address(*before) != address(server) ||
                     before->bootstrap != server.bootstrap ||
                     before->public_key != server.public_key ||
                     before->provider_name != server.provider_name ||
                     before->relay != server.relay);
            table_->setItem(row, 0, name);
            table_->setItem(row, 1, protocol);
            table_->setItem(row, 2, serverAddress);
            table_->setItem(row, 3, status);
            table_->setItem(row, 4, rtt);
        }
        if (selectedRow >= 0)
            table_->selectRow(selectedRow);
        const bool hasServers = !working_.servers.empty();
        checkAll_->setEnabled(hasServers);
        if (updateSelectionControls_)
            updateSelectionControls_();
        table_->setUpdatesEnabled(true);
        table_->viewport()->update();
    }
    void colorRow(int row, const QColor& background, const QColor& foreground) {
        for (int column = 0; column < table_->columnCount(); ++column)
            if (auto* item = table_->item(row, column)) {
                item->setBackground(QBrush(background));
                item->setForeground(QBrush(foreground));
            }
    }
    static nd::TestResult testServer(nd::Server server) {
        if ((server.protocol == nd::Protocol::doh || server.protocol == nd::Protocol::dot) &&
            server.ip.empty() && server.bootstrap.empty()) {
            if (!nd::platform::system_dns_servers().empty()) {
                server.use_system_bootstrap = true;
            } else {
                try {
                    auto config = nd::default_config();
                    config.servers.push_back(server);
                    nd::prepare_secure_endpoints(config);
                    server = std::move(config.servers.back());
                } catch (const nd::Error& error) {
                    nd::TestResult result;
                    result.protocol = server.protocol;
                    result.server_id = server.id;
                    result.error_code = error.code;
                    result.message = error.what();
                    return result;
                } catch (const std::exception& error) {
                    nd::TestResult result;
                    result.protocol = server.protocol;
                    result.server_id = server.id;
                    result.error_code = "INTERNAL";
                    result.message = error.what();
                    return result;
                }
            }
        }
        return nd::test_server(server);
    }
    void checkSelected() {
        auto rows = table_->selectionModel()->selectedRows();
        if (rows.isEmpty() && table_->currentRow() >= 0)
            rows << table_->model()->index(table_->currentRow(), 0);
        checkRows(rows);
    }
    void checkAll() {
        QModelIndexList rows;
        for (int row = 0; row < table_->rowCount(); ++row)
            rows << table_->model()->index(row, 0);
        checkRows(rows);
    }
    void checkRows(const QModelIndexList& rows) {
        auto* pool = serverTestPool(working_.test_concurrency);
        for (const auto& index : rows) {
            const int row = index.row();
            if (row < 0 || row >= static_cast<int>(working_.servers.size()))
                continue;
            auto server = working_.servers[static_cast<size_t>(row)];
            table_->item(row, 3)->setText(uiText("Testing..."));
            table_->item(row, 4)->setText("—");
            colorRow(row, palette().color(QPalette::Base), palette().color(QPalette::Text));
            QPointer<ServerDialog> self(this);
            auto cancelled = cancelled_;
            pool->start([self, server, cancelled] {
                if (cancelled->load())
                    return;
                auto result = testServer(server);
                if (cancelled->load())
                    return;
                QMetaObject::invokeMethod(
                    qApp,
                    [self, serverId = server.id, result, cancelled] {
                        if (!self || cancelled->load())
                            return;
                        const auto found = std::find_if(
                            self->working_.servers.begin(),
                            self->working_.servers.end(),
                            [&](const nd::Server& value) { return value.id == serverId; });
                        if (found == self->working_.servers.end())
                            return;
                        const int row =
                            static_cast<int>(std::distance(self->working_.servers.begin(), found));
                        auto* status = self->table_->item(row, 3);
                        auto* rtt = self->table_->item(row, 4);
                        if (!status || !rtt)
                            return;
                        status->setText(
                            result.success ? "OK" : q(result.error_code + ": " + result.message));
                        rtt->setText(result.success ? QString::number(result.rtt_ms, 'f', 1) + " ms"
                                                    : "—");
                        const bool dark = self->palette().color(QPalette::Base).lightness() < 128;
                        self->colorRow(row,
                                       result.success
                                           ? (dark ? QColor(28, 68, 38) : QColor(220, 245, 224))
                                           : (dark ? QColor(78, 30, 34) : QColor(255, 224, 224)),
                                       result.success
                                           ? (dark ? QColor(130, 230, 150) : QColor(20, 105, 35))
                                           : (dark ? QColor(255, 130, 130) : QColor(150, 0, 0)));
                    },
                    Qt::QueuedConnection);
            });
        }
    }
    nd::Config& target_;
    nd::Config original_;
    nd::Config working_;
    std::function<bool()> changed_;
    QTableWidget* table_ = nullptr;
    QPushButton* check_ = nullptr;
    QPushButton* checkAll_ = nullptr;
    std::function<void()> updateSelectionControls_;
    std::shared_ptr<std::atomic_bool> cancelled_ = std::make_shared<std::atomic_bool>(false);
};

constexpr auto kServerIdsMimeType = "application/x-nativedns-server-ids";
constexpr int kPoolTreeKindRole = Qt::UserRole + 10;
constexpr int kPoolTreePoolIdRole = Qt::UserRole + 11;
constexpr int kPoolTreeServerIdRole = Qt::UserRole + 12;

bool editRedundancyOptions(QWidget* parent, std::string& testHostname, uint32_t& recheckSeconds) {
    QDialog dialog(parent);
    dialog.setObjectName("redundancyOptionsDialog");
    dialog.setWindowTitle(uiText("Redundancy Pool Options"));
    dialog.setModal(true);
    dialog.resize(360, 145);

    auto* hostEdit = new QLineEdit(q(testHostname), &dialog);
    hostEdit->setObjectName("redundancyTestHostname");
    hostEdit->selectAll();
    auto* recheckEdit = new QLineEdit(QString::number(recheckSeconds), &dialog);
    recheckEdit->setObjectName("redundancyRecheckSeconds");
    recheckEdit->setValidator(new QIntValidator(5, 86400, recheckEdit));
    recheckEdit->setMaximumWidth(90);

    for (auto* field : {hostEdit, recheckEdit}) {
        QObject::connect(field, &QLineEdit::textChanged, &dialog, [field] {
            if (field->property("validationError").toBool())
                setInputValidationError(field, false);
        });
    }

    auto* recheckRow = new QHBoxLayout;
    recheckRow->setContentsMargins(0, 0, 0, 0);
    recheckRow->addWidget(recheckEdit);
    recheckRow->addWidget(new QLabel(uiText("(seconds)"), &dialog));
    recheckRow->addStretch();

    auto* form = new QFormLayout;
    form->addRow(uiText("Test hostname:"), hostEdit);
    form->addRow(uiText("Recheck in:"), recheckRow);

    auto* ok = new QPushButton(uiText("OK"), &dialog);
    ok->setDefault(true);
    auto* cancel = new QPushButton(uiText("Cancel"), &dialog);
    auto* buttons = new QHBoxLayout;
    buttons->addWidget(ok);
    buttons->addStretch();
    buttons->addWidget(cancel);

    auto* root = new QVBoxLayout(&dialog);
    root->addLayout(form);
    root->addStretch();
    root->addLayout(buttons);

    QObject::connect(cancel, &QPushButton::clicked, &dialog, &QDialog::reject);
    QObject::connect(ok, &QPushButton::clicked, &dialog, [&] {
        setInputValidationError(hostEdit, false);
        setInputValidationError(recheckEdit, false);
        QLineEdit* firstInvalid = nullptr;
        QStringList errors;

        const QString hostText = hostEdit->text().trimmed();
        try {
            (void)nd::normalize_host(s(hostText));
        } catch (const std::exception& error) {
            setInputValidationError(hostEdit, true);
            firstInvalid = hostEdit;
            errors << q(error.what());
        }
        bool okInt = false;
        const int seconds = recheckEdit->text().trimmed().toInt(&okInt);
        if (!okInt || seconds < 5 || seconds > 86400) {
            setInputValidationError(recheckEdit, true);
            if (!firstInvalid)
                firstInvalid = recheckEdit;
            errors << uiText("Recheck interval must be between 5 and 86400 seconds.");
        }
        if (!errors.isEmpty()) {
            if (firstInvalid) {
                firstInvalid->setFocus();
                firstInvalid->selectAll();
            }
            QMessageBox::warning(&dialog, uiText("Redundancy Pool Options"), errors.join('\n'));
            return;
        }
        testHostname = s(hostText);
        recheckSeconds = static_cast<uint32_t>(seconds);
        dialog.accept();
    });

    positionDialog(dialog, parent);
    return dialog.exec() == QDialog::Accepted;
}

bool editPoolType(QWidget* parent, nd::ServerPool& pool) {
    QDialog dialog(parent);
    dialog.setObjectName("poolTypeDialog");
    dialog.setWindowTitle(uiText("Pool Type"));
    dialog.setModal(true);
    dialog.resize(450, 290);

    std::string testHostname = pool.test_hostname;
    uint32_t recheckSeconds = pool.recheck_seconds;

    auto* nameEdit = new QLineEdit(q(pool.name), &dialog);
    nameEdit->setObjectName("poolNameEdit");
    nameEdit->selectAll();
    QObject::connect(nameEdit, &QLineEdit::textChanged, &dialog, [nameEdit] {
        if (nameEdit->property("validationError").toBool())
            setInputValidationError(nameEdit, false);
    });
    auto* nameRow = new QHBoxLayout;
    nameRow->addStretch();
    nameRow->addWidget(new QLabel(uiText("Pool Name:"), &dialog));
    nameRow->addWidget(nameEdit, 1);
    nameRow->addStretch();

    auto* redundancyBox = new QGroupBox(uiText("Redundancy"), &dialog);
    auto* redundancyRadio =
        new QRadioButton(uiText("Automatically monitor DNS servers and use the best one."),
                         redundancyBox);
    redundancyRadio->setObjectName("poolRedundancyRadio");
    auto* optionsButton = new QPushButton(uiText("Options..."), redundancyBox);
    optionsButton->setObjectName("poolRedundancyOptions");
    auto* optionsRow = new QHBoxLayout;
    optionsRow->addSpacing(22);
    optionsRow->addWidget(optionsButton);
    optionsRow->addStretch();
    auto* redundancyLayout = new QVBoxLayout(redundancyBox);
    redundancyLayout->addWidget(redundancyRadio);
    redundancyLayout->addLayout(optionsRow);

    auto* lbBox = new QGroupBox(uiText("Load Balancing"), &dialog);
    auto* lbRadio =
        new QRadioButton(uiText("On each request use a random DNS server from the pool."), lbBox);
    lbRadio->setObjectName("poolLoadBalancingRadio");
    auto* lbLayout = new QVBoxLayout(lbBox);
    lbLayout->addWidget(lbRadio);

    auto* modeGroup = new QButtonGroup(&dialog);
    modeGroup->setExclusive(true);
    modeGroup->addButton(redundancyRadio, 0);
    modeGroup->addButton(lbRadio, 1);
    if (pool.type == nd::PoolType::load_balancing)
        lbRadio->setChecked(true);
    else
        redundancyRadio->setChecked(true);

    const auto syncOptionsEnabled = [redundancyRadio, optionsButton] {
        optionsButton->setEnabled(redundancyRadio->isChecked());
    };
    syncOptionsEnabled();
    QObject::connect(redundancyRadio, &QRadioButton::toggled, &dialog, syncOptionsEnabled);
    QObject::connect(optionsButton, &QPushButton::clicked, &dialog, [&] {
        (void)editRedundancyOptions(&dialog, testHostname, recheckSeconds);
    });

    auto* ok = new QPushButton(uiText("OK"), &dialog);
    ok->setDefault(true);
    auto* cancel = new QPushButton(uiText("Cancel"), &dialog);
    auto* buttons = new QHBoxLayout;
    buttons->addWidget(ok);
    buttons->addStretch();
    buttons->addWidget(cancel);

    auto* root = new QVBoxLayout(&dialog);
    root->addLayout(nameRow);
    root->addSpacing(6);
    root->addWidget(redundancyBox);
    root->addWidget(lbBox);
    root->addStretch();
    root->addLayout(buttons);

    QObject::connect(cancel, &QPushButton::clicked, &dialog, &QDialog::reject);
    QObject::connect(ok, &QPushButton::clicked, &dialog, [&] {
        setInputValidationError(nameEdit, false);
        const QString trimmed = nameEdit->text().trimmed();
        if (trimmed.isEmpty()) {
            setInputValidationError(nameEdit, true);
            nameEdit->setFocus();
            QMessageBox::warning(&dialog, uiText("Pool Type"), uiText("Pool name must not be empty."));
            return;
        }
        pool.name = s(trimmed);
        pool.type = lbRadio->isChecked() ? nd::PoolType::load_balancing : nd::PoolType::redundancy;
        pool.test_hostname = testHostname;
        pool.recheck_seconds = recheckSeconds;
        dialog.accept();
    });

    positionDialog(dialog, parent);
    return dialog.exec() == QDialog::Accepted;
}

class DraggableServerTable final : public QTableWidget {
public:
    explicit DraggableServerTable(QWidget* parent = nullptr) : QTableWidget(parent) {
        setDragEnabled(true);
        setDragDropMode(QAbstractItemView::DragOnly);
        setDefaultDropAction(Qt::CopyAction);
    }

protected:
    QStringList mimeTypes() const override {
        return {QString::fromLatin1(kServerIdsMimeType)};
    }
    QMimeData* mimeData(const QList<QTableWidgetItem*>& items) const override {
        std::vector<uint32_t> ids;
        std::unordered_set<uint32_t> seen;
        for (const auto* item : items) {
            if (!item)
                continue;
            const auto* first = this->item(item->row(), 0);
            if (!first)
                continue;
            const uint32_t id = first->data(Qt::UserRole).toUInt();
            if (id && seen.insert(id).second)
                ids.push_back(id);
        }
        auto* mime = new QMimeData;
        QStringList encoded;
        for (const auto id : ids)
            encoded << QString::number(id);
        mime->setData(QString::fromLatin1(kServerIdsMimeType), encoded.join(';').toUtf8());
        return mime;
    }
};

class PoolTreeWidget final : public QTreeWidget {
public:
    using DropHandler = std::function<void(uint32_t poolId, const std::vector<uint32_t>& serverIds)>;
    explicit PoolTreeWidget(QWidget* parent = nullptr) : QTreeWidget(parent) {
        setHeaderHidden(true);
        setRootIsDecorated(true);
        setAcceptDrops(true);
        setDropIndicatorShown(true);
        setDragDropMode(QAbstractItemView::DropOnly);
        setSelectionMode(QAbstractItemView::SingleSelection);
    }
    void setDropHandler(DropHandler handler) {
        onDrop_ = std::move(handler);
    }

protected:
    void dragEnterEvent(QDragEnterEvent* event) override {
        if (event->mimeData() &&
            event->mimeData()->hasFormat(QString::fromLatin1(kServerIdsMimeType)))
            event->acceptProposedAction();
        else
            event->ignore();
    }
    void dragMoveEvent(QDragMoveEvent* event) override {
        if (event->mimeData() &&
            event->mimeData()->hasFormat(QString::fromLatin1(kServerIdsMimeType)) &&
            targetPoolIdAt(event->position().toPoint()) != 0)
            event->acceptProposedAction();
        else
            event->ignore();
    }
    void dropEvent(QDropEvent* event) override {
        if (!event->mimeData() ||
            !event->mimeData()->hasFormat(QString::fromLatin1(kServerIdsMimeType))) {
            event->ignore();
            return;
        }
        const uint32_t poolId = targetPoolIdAt(event->position().toPoint());
        if (!poolId || !onDrop_) {
            event->ignore();
            return;
        }
        const QString raw =
            QString::fromUtf8(event->mimeData()->data(QString::fromLatin1(kServerIdsMimeType)));
        std::vector<uint32_t> serverIds;
        for (const auto& part : raw.split(';', Qt::SkipEmptyParts)) {
            bool ok = false;
            const uint32_t id = part.toUInt(&ok);
            if (ok && id)
                serverIds.push_back(id);
        }
        if (serverIds.empty()) {
            event->ignore();
            return;
        }
        onDrop_(poolId, serverIds);
        event->acceptProposedAction();
    }

private:
    uint32_t targetPoolIdAt(const QPoint& pos) const {
        if (const auto* item = itemAt(pos))
            return item->data(0, kPoolTreePoolIdRole).toUInt();
        if (const auto* current = currentItem())
            return current->data(0, kPoolTreePoolIdRole).toUInt();
        if (topLevelItemCount() == 1)
            return topLevelItem(0)->data(0, kPoolTreePoolIdRole).toUInt();
        return 0;
    }
    DropHandler onDrop_;
};

class ServerPoolsDialog final : public QDialog {
public:
    using StatusFetcher = std::function<std::vector<nd::PoolStatusSnapshot>()>;

    ServerPoolsDialog(QWidget* parent,
                      nd::Config& config,
                      std::function<bool()> changed,
                      StatusFetcher statusFetcher = {})
        : QDialog(parent), target_(config), original_(config), working_(config),
          changed_(std::move(changed)), statusFetcher_(std::move(statusFetcher)) {
        setWindowTitle(uiText("Server Pools"));
        resize(760, 560);

        serverTable_ = new DraggableServerTable(this);
        serverTable_->setObjectName("poolSourceServersTable");
        serverTable_->setColumnCount(3);
        serverTable_->setHorizontalHeaderLabels(
            {uiText("Name"), uiText("Protocol"), uiText("Address")});
        new BoundedTableHeader(serverTable_, {160, 120, 220}, 0, 2, 3);
        serverTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        serverTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        serverTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        configureFixedTableRows(serverTable_);

        auto* hint = new QLabel(
            uiText("Drag and drop DNS servers from the list above into a pool.\nRedundancy pools "
                   "monitor servers and use the best one; Load Balancing pools use a random server "
                   "for each request."),
            this);
        hint->setWordWrap(true);

        poolTree_ = new PoolTreeWidget(this);
        poolTree_->setObjectName("serverPoolsTree");
        poolTree_->setDropHandler(
            [this](uint32_t poolId, const std::vector<uint32_t>& serverIds) {
                addServersToPool(poolId, serverIds);
            });
        poolTree_->installEventFilter(this);

        createButton_ = new QPushButton(uiText("Create"), this);
        createButton_->setObjectName("createPoolButton");
        typeButton_ = new QPushButton(uiText("Type..."), this);
        typeButton_->setObjectName("poolTypeButton");
        removeButton_ = new QPushButton(uiText("Remove"), this);
        removeButton_->setObjectName("removePoolButton");

        auto* poolSide = new QVBoxLayout;
        poolSide->addWidget(createButton_);
        poolSide->addWidget(typeButton_);
        poolSide->addWidget(removeButton_);
        poolSide->addStretch();

        auto* poolArea = new QHBoxLayout;
        poolArea->addWidget(poolTree_, 1);
        poolArea->addLayout(poolSide);

        auto* ok = new QPushButton(uiText("OK"), this);
        auto* cancel = new QPushButton(uiText("Cancel"), this);
        auto* bottom = new QHBoxLayout;
        bottom->addWidget(ok);
        bottom->addStretch();
        bottom->addWidget(cancel);

        auto* root = new QVBoxLayout(this);
        root->addWidget(serverTable_, 5);
        root->addSpacing(4);
        root->addWidget(hint);
        root->addSpacing(4);
        root->addLayout(poolArea, 5);
        root->addLayout(bottom);

        connect(createButton_, &QPushButton::clicked, this, [this] { createPool(); });
        connect(typeButton_, &QPushButton::clicked, this, [this] { editSelectedPoolType(); });
        connect(removeButton_, &QPushButton::clicked, this, [this] { removeSelected(); });
        connect(ok, &QPushButton::clicked, this, [this] { commit(); });
        connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
        connect(poolTree_,
                &QTreeWidget::currentItemChanged,
                this,
                [this](QTreeWidgetItem*, QTreeWidgetItem*) { updateButtons(); });
        connect(poolTree_,
                &QTreeWidget::itemDoubleClicked,
                this,
                [this](QTreeWidgetItem* item, int) {
                    if (item && item->data(0, kPoolTreeKindRole).toInt() == 1)
                        editSelectedPoolType();
                });
        connect(serverTable_,
                &QTableWidget::cellDoubleClicked,
                this,
                [this](int row, int) {
                    const uint32_t poolId = selectedPoolId();
                    if (!poolId || row < 0 || row >= serverTable_->rowCount())
                        return;
                    if (const auto* item = serverTable_->item(row, 0)) {
                        const uint32_t sid = item->data(Qt::UserRole).toUInt();
                        if (sid)
                            addServersToPool(poolId, {sid});
                    }
                });

        populateServers();
        rebuildPoolTree();
        updateButtons();

        if (!statusFetcher_) {
            statusFetcher_ = []() -> std::vector<nd::PoolStatusSnapshot> {
                try {
                    const auto response = nd::pipe_request(
                        nd::core_pipe_name, nd::IpcOperation::pool_status, {}, 1000);
                    if (!response.status)
                        return nd::parse_pool_statuses(response.payload);
                } catch (...) {
                }
                return {};
            };
        }
        connect(&pollTimer_, &QTimer::timeout, this, [this] { refreshLiveStatus(); });
        pollTimer_.start(2000);
        QTimer::singleShot(0, this, [this] { refreshLiveStatus(); });
    }

    ~ServerPoolsDialog() override {
        *cancelled_ = true;
        pollTimer_.stop();
    }

    bool addServersToPool(uint32_t poolId, const std::vector<uint32_t>& serverIds) {
        auto it = std::find_if(working_.pools.begin(),
                               working_.pools.end(),
                               [poolId](const nd::ServerPool& p) { return p.id == poolId; });
        if (it == working_.pools.end())
            return false;
        bool addedAny = false;
        for (const auto sid : serverIds) {
            if (std::find(it->server_ids.begin(), it->server_ids.end(), sid) ==
                it->server_ids.end()) {
                it->server_ids.push_back(sid);
                addedAny = true;
            }
        }
        if (addedAny)
            rebuildPoolTree(poolId, serverIds.empty() ? 0u : serverIds.back());
        return addedAny;
    }

protected:
    bool eventFilter(QObject* watched, QEvent* event) override {
        if (watched == poolTree_ && event->type() == QEvent::KeyPress) {
            const auto* key = static_cast<QKeyEvent*>(event);
            if (key->key() == Qt::Key_Delete && removeButton_->isEnabled()) {
                removeSelected();
                return true;
            }
        }
        return QDialog::eventFilter(watched, event);
    }

private:
    static std::string serverAddress(const nd::Server& server) {
        return !server.url.empty()
                   ? server.url
                   : (!server.hostname.empty()
                          ? server.hostname
                          : server.ip + (server.port ? ":" + std::to_string(server.port) : ""));
    }
    const nd::Server* findServer(uint32_t id) const {
        const auto it = std::find_if(working_.servers.begin(),
                                     working_.servers.end(),
                                     [id](const nd::Server& s) { return s.id == id; });
        return it == working_.servers.end() ? nullptr : &*it;
    }
    uint32_t selectedPoolId() const {
        if (const auto* item = poolTree_->currentItem())
            return item->data(0, kPoolTreePoolIdRole).toUInt();
        return 0;
    }
    uint32_t selectedMemberServerId() const {
        if (const auto* item = poolTree_->currentItem();
            item && item->data(0, kPoolTreeKindRole).toInt() == 2)
            return item->data(0, kPoolTreeServerIdRole).toUInt();
        return 0;
    }
    void populateServers() {
        serverTable_->setRowCount(static_cast<int>(working_.servers.size()));
        for (int row = 0; row < serverTable_->rowCount(); ++row) {
            const auto& srv = working_.servers[static_cast<size_t>(row)];
            auto* nameItem = new QTableWidgetItem(q(srv.name));
            nameItem->setData(Qt::UserRole, srv.id);
            auto* protoItem = new QTableWidgetItem(protocolFullText(srv.protocol));
            auto* addrItem = new QTableWidgetItem(q(serverAddress(srv)));
            serverTable_->setItem(row, 0, nameItem);
            serverTable_->setItem(row, 1, protoItem);
            serverTable_->setItem(row, 2, addrItem);
        }
    }
    void rebuildPoolTree(uint32_t selectPoolId = 0, uint32_t selectServerId = 0) {
        if (!selectPoolId) {
            selectPoolId = selectedPoolId();
            selectServerId = selectedMemberServerId();
        }
        std::unordered_map<uint32_t, bool> collapsed;
        for (int i = 0; i < poolTree_->topLevelItemCount(); ++i) {
            const auto* item = poolTree_->topLevelItem(i);
            collapsed[item->data(0, kPoolTreePoolIdRole).toUInt()] = !item->isExpanded();
        }

        const bool dark = palette().color(QPalette::Base).lightness() < 128;
        const QColor okColor = dark ? QColor(105, 220, 145) : QColor(20, 140, 46);
        const QColor failColor = dark ? QColor(255, 110, 110) : QColor(185, 20, 20);
        const QColor normalColor = palette().color(QPalette::Text);

        poolTree_->setUpdatesEnabled(false);
        poolTree_->clear();
        QTreeWidgetItem* toSelect = nullptr;
        for (const auto& pool : working_.pools) {
            const QString typeTag = pool.type == nd::PoolType::load_balancing
                                        ? QStringLiteral("[Load Balancing]")
                                        : QStringLiteral("[Redundancy]");
            auto* poolItem = new QTreeWidgetItem(poolTree_, {q(pool.name) + " " + typeTag});
            poolItem->setData(0, kPoolTreeKindRole, 1);
            poolItem->setData(0, kPoolTreePoolIdRole, pool.id);
            poolItem->setData(0, kPoolTreeServerIdRole, 0u);
            if (pool.type == nd::PoolType::redundancy) {
                poolItem->setToolTip(
                    0,
                    uiText("Test hostname:") + " " + q(pool.test_hostname) + "\n" +
                        uiText("Recheck in:") + " " + QString::number(pool.recheck_seconds) + " " +
                        uiText("(seconds)"));
            }

            const auto liveIt = liveStatus_.find(pool.id);
            bool sawChecked = false;
            bool anyHealthy = false;
            for (const auto sid : pool.server_ids) {
                const auto* srv = findServer(sid);
                if (!srv)
                    continue;
                QString label = q(srv->name) + " [" + protocolFullText(srv->protocol) + "]";
                QColor color = normalColor;
                QString tip = q(serverAddress(*srv));
                if (liveIt != liveStatus_.end()) {
                    const auto mIt = liveIt->second.find(sid);
                    if (mIt != liveIt->second.end()) {
                        const auto& st = mIt->second;
                        if (st.health == nd::PoolMemberHealth::healthy) {
                            sawChecked = true;
                            anyHealthy = true;
                            const auto rttInt =
                                static_cast<long long>(std::llround(std::max(0.0, st.rtt_ms)));
                            label = QString::number(rttInt) + " " + label;
                            color = okColor;
                            tip = QString("OK (%1 ms)\n%2")
                                      .arg(QString::number(st.rtt_ms, 'f', 0), tip);
                        } else if (st.health == nd::PoolMemberHealth::failed) {
                            sawChecked = true;
                            color = failColor;
                            tip = (st.last_error.empty() ? uiText("Error") : q(st.last_error)) +
                                  "\n" + tip;
                        }
                    }
                }
                auto* memberItem = new QTreeWidgetItem(poolItem, {label});
                memberItem->setData(0, kPoolTreeKindRole, 2);
                memberItem->setData(0, kPoolTreePoolIdRole, pool.id);
                memberItem->setData(0, kPoolTreeServerIdRole, sid);
                memberItem->setForeground(0, QBrush(color));
                memberItem->setToolTip(0, tip);
                if (pool.id == selectPoolId && sid == selectServerId)
                    toSelect = memberItem;
            }
            if (pool.type == nd::PoolType::redundancy && sawChecked && !anyHealthy)
                poolItem->setForeground(0, QBrush(failColor));
            else
                poolItem->setForeground(0, QBrush(normalColor));

            const auto colIt = collapsed.find(pool.id);
            poolItem->setExpanded(colIt == collapsed.end() ? true : !colIt->second);
            if (!toSelect && pool.id == selectPoolId)
                toSelect = poolItem;
        }
        if (toSelect)
            poolTree_->setCurrentItem(toSelect);
        poolTree_->setUpdatesEnabled(true);
        updateButtons();
    }
    void updateButtons() {
        const auto* item = poolTree_->currentItem();
        const bool hasPool = item && item->data(0, kPoolTreePoolIdRole).toUInt() != 0;
        typeButton_->setEnabled(hasPool);
        removeButton_->setEnabled(hasPool);
    }
    void createPool() {
        nd::ServerPool pool;
        pool.id = nextPoolId(working_);
        const QString baseName = uiText("New Pool");
        QString candidate = baseName;
        int suffix = 2;
        while (std::any_of(working_.pools.begin(),
                           working_.pools.end(),
                           [&](const nd::ServerPool& p) { return q(p.name) == candidate; })) {
            candidate = baseName + " " + QString::number(suffix++);
        }
        pool.name = s(candidate);
        pool.type = nd::PoolType::redundancy;
        pool.test_hostname = working_.test_target.empty() ? "iana.org" : working_.test_target;
        pool.recheck_seconds = 60;
        try {
            nd::ConfigEditor editor(working_);
            editor.add_pool(pool);
            working_ = editor.get();
            rebuildPoolTree(pool.id, 0);
        } catch (const std::exception& e) {
            QMessageBox::critical(this, "NativeDNS", e.what());
        }
    }
    void editSelectedPoolType() {
        const uint32_t poolId = selectedPoolId();
        if (!poolId)
            return;
        auto it = std::find_if(working_.pools.begin(),
                               working_.pools.end(),
                               [poolId](const nd::ServerPool& p) { return p.id == poolId; });
        if (it == working_.pools.end())
            return;
        auto edited = *it;
        if (!editPoolType(this, edited))
            return;
        try {
            nd::ConfigEditor editor(working_);
            editor.update_pool(edited);
            working_ = editor.get();
            rebuildPoolTree(edited.id, 0);
        } catch (const std::exception& e) {
            QMessageBox::critical(this, "NativeDNS", e.what());
        }
    }
    void removeSelected() {
        const auto* item = poolTree_->currentItem();
        if (!item)
            return;
        const int kind = item->data(0, kPoolTreeKindRole).toInt();
        const uint32_t poolId = item->data(0, kPoolTreePoolIdRole).toUInt();
        if (kind == 2) {
            const uint32_t sid = item->data(0, kPoolTreeServerIdRole).toUInt();
            auto it = std::find_if(working_.pools.begin(),
                                   working_.pools.end(),
                                   [poolId](const nd::ServerPool& p) { return p.id == poolId; });
            if (it == working_.pools.end())
                return;
            std::erase(it->server_ids, sid);
            rebuildPoolTree(poolId, 0);
            return;
        }
        if (kind == 1 && poolId) {
            const bool referenced = std::any_of(
                working_.rules.begin(), working_.rules.end(), [poolId](const nd::Rule& r) {
                    return r.pool_id == poolId;
                });
            if (referenced) {
                QMessageBox::warning(
                    this,
                    uiText("Server Pools"),
                    uiText("Cannot remove a pool referenced by one or more rules."));
                return;
            }
            if (QMessageBox::question(
                    this, "NativeDNS", uiText("Remove selected server pool?")) != QMessageBox::Yes)
                return;
            try {
                nd::ConfigEditor editor(working_);
                editor.remove_pool(poolId);
                working_ = editor.get();
                rebuildPoolTree();
            } catch (const std::exception& e) {
                QMessageBox::critical(this, "NativeDNS", e.what());
            }
        }
    }
    void refreshLiveStatus() {
        if (!statusFetcher_ || pollPending_.exchange(true))
            return;
        QPointer<ServerPoolsDialog> self(this);
        auto cancelled = cancelled_;
        auto fetcher = statusFetcher_;
        QThreadPool::globalInstance()->start([self, cancelled, fetcher] {
            std::vector<nd::PoolStatusSnapshot> snapshots;
            if (!cancelled->load())
                snapshots = fetcher();
            QMetaObject::invokeMethod(
                qApp,
                [self, cancelled, snapshots = std::move(snapshots)] {
                    if (!self || cancelled->load())
                        return;
                    self->pollPending_ = false;
                    self->liveStatus_.clear();
                    for (const auto& ps : snapshots) {
                        auto& map = self->liveStatus_[ps.pool_id];
                        for (const auto& m : ps.members)
                            map[m.server_id] = m;
                    }
                    self->rebuildPoolTree();
                },
                Qt::QueuedConnection);
        });
    }
    void commit() {
        if (working_ == original_) {
            accept();
            return;
        }
        const auto previous = target_;
        target_ = working_;
        if (changed_()) {
            original_ = working_;
            accept();
        } else {
            target_ = previous;
        }
    }

    nd::Config& target_;
    nd::Config original_;
    nd::Config working_;
    std::function<bool()> changed_;
    StatusFetcher statusFetcher_;
    DraggableServerTable* serverTable_ = nullptr;
    PoolTreeWidget* poolTree_ = nullptr;
    QPushButton* createButton_ = nullptr;
    QPushButton* typeButton_ = nullptr;
    QPushButton* removeButton_ = nullptr;
    QTimer pollTimer_;
    std::atomic_bool pollPending_{false};
    std::shared_ptr<std::atomic_bool> cancelled_ = std::make_shared<std::atomic_bool>(false);
    std::unordered_map<uint32_t, std::unordered_map<uint32_t, nd::PoolMemberStatus>> liveStatus_;
};

bool editRule(QWidget* parent,
              const nd::Config& config,
              nd::Rule& rule,
              const std::function<void(const nd::Rule&)>& validateCandidate = {}) {
    QDialog dialog(parent);
    dialog.setObjectName("ruleEditorDialog");
    dialog.setWindowTitle(rule.is_default ? uiText("Default Rule") : uiText("DNS Rule"));
    dialog.resize(560, 420);
    auto* form = new QFormLayout;
    QLineEdit name(q(rule.name));
    name.setObjectName("ruleNameEdit");
    QPlainTextEdit hosts;
    hosts.setObjectName("ruleHostnamesEdit");
    hosts.setPlainText(joinPatterns(rule.patterns));
    hosts.setMinimumHeight(150);
    QObject::connect(&name, &QLineEdit::textChanged, &dialog, [&name] {
        if (name.property("validationError").toBool())
            setInputValidationError(&name, false);
    });
    QObject::connect(&hosts, &QPlainTextEdit::textChanged, &dialog, [&hosts] {
        if (hosts.property("validationError").toBool())
            setInputValidationError(&hosts, false);
    });
    AnchoredComboBox action;
    action.addItems({uiText("process"), uiText("bypass"), uiText("block")});
    action.setCurrentIndex(rule.action == nd::Action::process  ? 0
                           : rule.action == nd::Action::bypass ? 1
                                                               : 2);
    AnchoredComboBox server;
    populateRuleTargetCombo(server, config);
    const int found =
        server.findData(QVariant::fromValue(encodeRuleTarget(rule.server_id, rule.pool_id)));
    if (found >= 0)
        server.setCurrentIndex(found);
    QCheckBox enabled(uiText("Enabled"));
    enabled.setChecked(rule.enabled);
    AnchoredComboBox block;
    block.addItems({"0.0.0.0 / ::", "NXDOMAIN", "REFUSED", uiText("Silent drop")});
    block.setCurrentIndex(static_cast<int>(rule.block_mode));
    form->addRow(uiText("Name:"), &name);
    form->addRow(uiText("Hostnames:"), &hosts);
    form->addRow(uiText("Action:"), &action);
    form->addRow(uiText("DNS Server:"), &server);
    form->addRow(uiText("Block mode:"), &block);
    form->addRow(&enabled);
    auto update = [&] {
        setFormFieldEnabled(form, &server, action.currentIndex() == 0);
        setFormFieldEnabled(form, &block, action.currentIndex() == 2);
        setFormFieldEnabled(form, &name, !rule.is_default);
        setFormFieldEnabled(form, &hosts, !rule.is_default);
        enabled.setEnabled(!rule.is_default);
    };
    QObject::connect(&action, &QComboBox::currentIndexChanged, &dialog, [&] { update(); });
    update();
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    translateDialogButtons(buttons);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, [&] {
        setInputValidationError(&name, false);
        setInputValidationError(&hosts, false);
        QWidget* firstInvalid = nullptr;
        QStringList errors;
        const auto flagInvalid = [&](QWidget* field, const QString& msg) {
            if (!field->property("validationError").toBool())
                setInputValidationError(field, true);
            if (!firstInvalid)
                firstInvalid = field;
            if (!msg.isEmpty() && !errors.contains(msg))
                errors << msg;
        };

        nd::Rule candidate = rule;
        if (!candidate.is_default) {
            candidate.name = s(name.text().trimmed());
            if (candidate.name.empty())
                flagInvalid(&name, uiText("Rule name must not be empty."));
            bool patternsParsed = false;
            try {
                candidate.patterns = nd::split_patterns(s(hosts.toPlainText()));
                patternsParsed = true;
            } catch (const std::exception& e) {
                flagInvalid(&hosts, q(e.what()));
            }
            if (patternsParsed) {
                if (candidate.patterns.empty())
                    flagInvalid(&hosts, uiText("At least one hostname pattern is required."));
                else if (candidate.patterns.size() > 4096)
                    flagInvalid(&hosts, QStringLiteral("Missing or excessive patterns"));
            }
            candidate.enabled = enabled.isChecked();
        }
        candidate.action = action.currentIndex() == 0   ? nd::Action::process
                           : action.currentIndex() == 1 ? nd::Action::bypass
                                                        : nd::Action::block;
        if (candidate.action == nd::Action::process) {
            const auto encoded = server.currentData().toULongLong();
            if (isPoolTarget(encoded)) {
                candidate.pool_id = targetId(encoded);
                candidate.server_id = 0;
            } else {
                candidate.server_id = targetId(encoded);
                candidate.pool_id = 0;
            }
        } else {
            candidate.server_id = 0;
            candidate.pool_id = 0;
        }
        candidate.block_mode = static_cast<nd::BlockMode>(block.currentIndex());

        if (errors.isEmpty() && validateCandidate) {
            try {
                validateCandidate(candidate);
            } catch (const std::exception& e) {
                errors << q(e.what());
            }
        }

        if (!errors.isEmpty()) {
            if (firstInvalid)
                firstInvalid->setFocus();
            QMessageBox::critical(&dialog, "NativeDNS", errors.join('\n'));
            return;
        }
        rule = std::move(candidate);
        dialog.accept();
    });
    auto* root = new QVBoxLayout(&dialog);
    root->addLayout(form);
    root->addWidget(buttons);
    positionDialog(dialog, parent);
    return dialog.exec() == QDialog::Accepted;
}

class CenteredCheckDelegate final : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter* painter,
               const QStyleOptionViewItem& option,
               const QModelIndex& index) const override {
        QStyleOptionViewItem item(option);
        initStyleOption(&item, index);
        auto* style = item.widget ? item.widget->style() : QApplication::style();
        const auto indicatorRect = checkRect(item);
        item.features &= ~QStyleOptionViewItem::HasCheckIndicator;
        style->drawControl(QStyle::CE_ItemViewItem, &item, painter, item.widget);

        if (indicatorRect.isValid()) {
            item.rect = indicatorRect;
            if (!(index.flags() & Qt::ItemIsUserCheckable))
                item.state &= ~QStyle::State_Enabled;
            item.state &= ~(QStyle::State_HasFocus | QStyle::State_On | QStyle::State_Off |
                            QStyle::State_NoChange);
            item.state |= item.checkState == Qt::Checked ? QStyle::State_On : QStyle::State_Off;
            style->drawPrimitive(QStyle::PE_IndicatorItemViewItemCheck, &item, painter, item.widget);
        }
    }

    bool editorEvent(QEvent* event,
                     QAbstractItemModel* model,
                     const QStyleOptionViewItem& option,
                     const QModelIndex& index) override {
        if (!(index.flags() & Qt::ItemIsUserCheckable) ||
            !(index.flags() & Qt::ItemIsEnabled) || !(option.state & QStyle::State_Enabled))
            return false;
        if (event->type() == QEvent::MouseButtonPress ||
            event->type() == QEvent::MouseButtonRelease ||
            event->type() == QEvent::MouseButtonDblClick) {
            const auto* mouse = static_cast<QMouseEvent*>(event);
            if (mouse->button() != Qt::LeftButton ||
                !option.rect.contains(mouse->position().toPoint()))
                return false;
            if (event->type() != QEvent::MouseButtonRelease)
                return true;
        } else if (event->type() == QEvent::KeyPress) {
            const auto* key = static_cast<QKeyEvent*>(event);
            if (key->key() != Qt::Key_Space && key->key() != Qt::Key_Select)
                return false;
            if (key->isAutoRepeat())
                return true;
        } else
            return false;
        const auto state = index.data(Qt::CheckStateRole).toInt() == Qt::Checked
                               ? Qt::Unchecked
                               : Qt::Checked;
        return model->setData(index, state, Qt::CheckStateRole);
    }

private:
    static QRect checkRect(const QStyleOptionViewItem& item) {
        auto* style = item.widget ? item.widget->style() : QApplication::style();
        auto rect = style->subElementRect(QStyle::SE_ItemViewItemCheckIndicator, &item, item.widget);
        rect.moveCenter(item.rect.center());
        return rect;
    }
};

class RulesTableModel final : public QAbstractTableModel {
public:
    RulesTableModel(const nd::Config& current,
                    const nd::Config& original,
                    std::function<bool(uint32_t, bool)> enabledChanged,
                    QObject* parent)
        : QAbstractTableModel(parent), current_(current), original_(original),
          enabledChanged_(std::move(enabledChanged)) {
        rebuildIndexes();
    }

    int rowCount(const QModelIndex& parent = {}) const override {
        return parent.isValid() ? 0 : static_cast<int>(current_.rules.size());
    }
    int columnCount(const QModelIndex& parent = {}) const override {
        return parent.isValid() ? 0 : 5;
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
            return {};
        static const char* keys[]{"Enabled", "Name", "Hostnames", "Action", "DNS Server"};
        return section >= 0 && section < 5 ? uiText(keys[section]) : QVariant{};
    }
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override {
        if (!index.isValid() || index.row() < 0 ||
            static_cast<size_t>(index.row()) >= current_.rules.size())
            return {};
        const auto& rule = current_.rules[static_cast<size_t>(index.row())];
        if (role == ruleIdRole)
            return rule.id;
        if (role == Qt::UserRole) {
            if (index.column() == 3)
                return QVariant::fromValue<qulonglong>(rule.action == nd::Action::process  ? 0
                                                       : rule.action == nd::Action::bypass ? 1
                                                                                           : 2);
            if (index.column() == 4)
                return QVariant::fromValue(encodeRuleTarget(rule.server_id, rule.pool_id));
            return {};
        }
        if (role == Qt::ToolTipRole && index.column() == 2)
            return joinPatterns(rule.patterns);
        if (role == Qt::ToolTipRole && index.column() == 0 && rule.is_default)
            return uiText("Default rule must remain enabled.");
        if (role == Qt::CheckStateRole && index.column() == 0)
            return rule.enabled ? Qt::Checked : Qt::Unchecked;
        if (role == Qt::DisplayRole) {
            if (index.column() == 0)
                return {};
            if (index.column() == 1)
                return q(rule.name);
            if (index.column() == 2)
                return previewPatterns(rule.patterns);
            if (index.column() == 3)
                return uiText(rule.action == nd::Action::process  ? "process"
                              : rule.action == nd::Action::bypass ? "bypass"
                                                                  : "block");
            if (index.column() == 4) {
                if (rule.action != nd::Action::process)
                    return uiText("Original/System");
                if (rule.pool_id) {
                    const auto pool = pool_names_.find(rule.pool_id);
                    return pool == pool_names_.end() ? uiText("Original/System")
                                                     : QStringLiteral("P| ") + pool->second;
                }
                if (rule.server_id) {
                    const auto server = server_names_.find(rule.server_id);
                    return server == server_names_.end() ? uiText("Original/System")
                                                         : QStringLiteral("S| ") + server->second;
                }
                return uiText("Original/System");
            }
        }
        if (role == Qt::ForegroundRole && !rule.enabled)
            return QBrush(Qt::gray);
        if (role == Qt::FontRole && changed(rule, index.column())) {
            auto font = QApplication::font();
            font.setBold(true);
            return font;
        }
        return {};
    }
    Qt::ItemFlags flags(const QModelIndex& index) const override {
        if (!index.isValid())
            return Qt::NoItemFlags;
        auto result = Qt::ItemIsEnabled | Qt::ItemIsSelectable;
        if (index.column() == 0 && !current_.rules[static_cast<size_t>(index.row())].is_default)
            result |= Qt::ItemIsUserCheckable;
        if (index.column() == 3)
            result |= Qt::ItemIsEditable;
        if (index.column() == 4) {
            const auto& rule = current_.rules[static_cast<size_t>(index.row())];
            if (rule.action == nd::Action::process)
                result |= Qt::ItemIsEditable;
        }
        return result;
    }
    bool setData(const QModelIndex& index, const QVariant& value, int role) override {
        if (role != Qt::CheckStateRole || !index.isValid() || index.column() != 0 ||
            index.row() < 0 || static_cast<size_t>(index.row()) >= current_.rules.size() ||
            !(flags(index) & Qt::ItemIsUserCheckable))
            return false;
        const int state = value.toInt();
        if (state != Qt::Checked && state != Qt::Unchecked)
            return false;
        return enabledChanged_(current_.rules[static_cast<size_t>(index.row())].id,
                               state == Qt::Checked);
    }
    void refresh() {
        beginResetModel();
        rebuildIndexes();
        endResetModel();
    }
    void refreshRuleData() {
        // Inline edits do not change row identities; retain selection and the Shift anchor.
        if (rowCount())
            emit dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
    }

private:
    bool changed(const nd::Rule& rule, int column) const {
        const auto found = original_rules_.find(rule.id);
        if (found == original_rules_.end())
            return true;
        const auto& before = *found->second;
        if (column == 0)
            return before.enabled != rule.enabled;
        if (column == 1) {
            const auto row = original_rows_.find(rule.id);
            return before.name != rule.name || before.interface_id != rule.interface_id ||
                   before.metadata != rule.metadata || row == original_rows_.end() ||
                   row->second != static_cast<size_t>(&rule - current_.rules.data());
        }
        if (column == 2)
            return before.patterns != rule.patterns;
        if (column == 3)
            return before.action != rule.action || before.block_mode != rule.block_mode ||
                   before.dnssec_validate != rule.dnssec_validate ||
                   before.dnssec_reject_unsigned != rule.dnssec_reject_unsigned;
        return column == 4 &&
               (before.server_id != rule.server_id || before.pool_id != rule.pool_id);
    }
    void rebuildIndexes() {
        original_rules_.clear();
        original_rows_.clear();
        server_names_.clear();
        pool_names_.clear();
        original_rules_.reserve(original_.rules.size());
        original_rows_.reserve(original_.rules.size());
        server_names_.reserve(current_.servers.size());
        pool_names_.reserve(current_.pools.size());
        for (size_t row = 0; row < original_.rules.size(); ++row) {
            original_rules_.emplace(original_.rules[row].id, &original_.rules[row]);
            original_rows_.emplace(original_.rules[row].id, row);
        }
        for (const auto& server : current_.servers)
            server_names_.emplace(server.id, q(server.name));
        for (const auto& pool : current_.pools)
            pool_names_.emplace(pool.id, q(pool.name));
    }
    const nd::Config& current_;
    const nd::Config& original_;
    std::function<bool(uint32_t, bool)> enabledChanged_;
    std::unordered_map<uint32_t, const nd::Rule*> original_rules_;
    std::unordered_map<uint32_t, size_t> original_rows_;
    std::unordered_map<uint32_t, QString> server_names_;
    std::unordered_map<uint32_t, QString> pool_names_;
};

class RulesTableView final : public QTableView {
public:
    using QTableView::QTableView;

protected:
    QItemSelectionModel::SelectionFlags
    selectionCommand(const QModelIndex& index, const QEvent* event = nullptr) const override {
        if (event && (event->type() == QEvent::MouseButtonPress ||
                      event->type() == QEvent::MouseButtonRelease)) {
            const auto* mouse = static_cast<const QMouseEvent*>(event);
            if (mouse->button() == Qt::LeftButton &&
                !(mouse->modifiers() & (Qt::ControlModifier | Qt::ShiftModifier)) &&
                index.column() >= 3 && selectionModel()->isSelected(index))
                return QItemSelectionModel::NoUpdate;
        }
        return QTableView::selectionCommand(index, event);
    }
};

class RulesDialog final : public QDialog {
public:
    RulesDialog(QWidget* parent, nd::Config& config, std::function<bool()> changed)
        : QDialog(parent), target_(config), changed_(std::move(changed)) {
        setWindowTitle(uiText("Rules"));
        resize(880, 480);
        model_ = new RulesTableModel(
            working_, original_,
            [this](uint32_t id, bool enabled) {
                return updateRules({id}, [enabled](nd::Rule& rule) { rule.enabled = enabled; });
            },
            this);
        table_ = new RulesTableView(this);
        table_->setModel(model_);
        new BoundedTableHeader(table_, {75, 140, 180, 100, 100}, 1, 2, 3);
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        configureFixedTableRows(table_);

        table_->setItemDelegateForColumn(0, new CenteredCheckDelegate(table_));

        auto* up = new QPushButton(uiText("Up"));
        auto* down = new QPushButton(uiText("Down"));
        auto* add = new QPushButton(uiText("Add"));
        auto* edit = new QPushButton(uiText("Edit"));
        auto* clone = new QPushButton(uiText("Clone"));
        auto* remove = new QPushButton(uiText("Remove"));
        auto* ok = new QPushButton(uiText("OK"));
        auto* close = new QPushButton(uiText("Close"));
        auto* side = new QVBoxLayout;
        side->addWidget(up);
        side->addWidget(down);
        side->addSpacing(up->sizeHint().height());
        side->addWidget(add);
        side->addWidget(edit);
        side->addWidget(clone);
        side->addWidget(remove);
        side->addStretch();
        auto* content = new QHBoxLayout;
        content->addWidget(table_, 1);
        content->addLayout(side);
        auto* bottom = new QHBoxLayout;
        bottom->addWidget(ok);
        bottom->addStretch();
        bottom->addWidget(close);
        auto* root = new QVBoxLayout(this);
        root->addLayout(content, 1);
        root->addLayout(bottom);
        initializationControls_ = {table_, up, down, add, edit, clone, remove, ok};
        for (auto* control : initializationControls_)
            control->setEnabled(false);

        table_->setItemDelegateForColumn(
            3,
            new LazyComboDelegate(
                [] {
                    return std::vector<ComboOption>{
                        {uiText("process"), 0}, {uiText("bypass"), 1}, {uiText("block"), 2}};
                },
                [this](const QModelIndex& index, qulonglong value) {
                    const auto ids = selectedRuleIds(index);
                    QTimer::singleShot(0, this, [this, ids, value] {
                        updateRules(ids, [value](nd::Rule& rule) {
                            rule.action = value == 0   ? nd::Action::process
                                          : value == 1 ? nd::Action::bypass
                                                       : nd::Action::block;
                            if (rule.action != nd::Action::process) {
                                rule.server_id = 0;
                                rule.pool_id = 0;
                            }
                        });
                    });
                },
                table_));
        table_->setItemDelegateForColumn(
            4,
            new LazyComboDelegate(
                [this] { return buildRuleTargetOptions(working_); },
                [this](const QModelIndex& index, qulonglong value) {
                    const auto ids = selectedRuleIds(index);
                    QTimer::singleShot(0, this, [this, ids, value] {
                        updateRules(ids, [value](nd::Rule& rule) {
                            if (rule.action == nd::Action::process) {
                                if (isPoolTarget(value)) {
                                    rule.pool_id = targetId(value);
                                    rule.server_id = 0;
                                } else {
                                    rule.server_id = targetId(value);
                                    rule.pool_id = 0;
                                }
                            }
                        });
                    });
                },
                table_));

        const auto updateSingleRuleControls = [this, up, down, edit, clone, remove] {
            const bool single =
                table_->isEnabled() && table_->selectionModel()->selectedRows().size() == 1;
            for (auto* button : {up, down, edit, clone, remove})
                button->setEnabled(single);
        };
        connect(table_->selectionModel(),
                &QItemSelectionModel::selectionChanged,
                this,
                updateSingleRuleControls);
        updateSingleRuleControls_ = updateSingleRuleControls;

        connect(up, &QPushButton::clicked, this, [this] { move(-1); });
        connect(down, &QPushButton::clicked, this, [this] { move(1); });
        connect(add, &QPushButton::clicked, this, [this] {
            nd::Rule rule;
            rule.id = nextRuleId(working_);
            rule.name = s(uiText("New Rule"));
            rule.patterns = {"example.com"};
            const auto validateAdd = [this](const nd::Rule& candidate) {
                nd::ConfigEditor editor(working_);
                editor.add_rule(candidate);
            };
            if (editRule(this, working_, rule, validateAdd))
                apply([&](nd::ConfigEditor& editor) { editor.add_rule(rule); }, rule.id);
        });
        connect(clone, &QPushButton::clicked, this, [this] {
            const int row = table_->currentIndex().row();
            if (row < 0)
                return;
            const auto id = nextRuleId(working_);
            apply(
                [&](nd::ConfigEditor& editor) {
                    editor.clone_rule(working_.rules[static_cast<size_t>(row)].id, id);
                },
                id);
        });
        connect(edit, &QPushButton::clicked, this, [this] {
            const int row = table_->currentIndex().row();
            if (row < 0)
                return;
            auto rule = working_.rules[static_cast<size_t>(row)];
            const auto validateEdit = [this](const nd::Rule& candidate) {
                nd::ConfigEditor editor(working_);
                editor.update_rule(candidate);
            };
            if (editRule(this, working_, rule, validateEdit))
                apply([&](nd::ConfigEditor& editor) { editor.update_rule(rule); }, rule.id);
        });
        connect(remove, &QPushButton::clicked, this, [this] {
            const int row = table_->currentIndex().row();
            if (row < 0)
                return;
            if (working_.rules[static_cast<size_t>(row)].is_default) {
                QMessageBox::information(
                    this, "NativeDNS", uiText("Default rule cannot be removed."));
                return;
            }
            apply([&](nd::ConfigEditor& editor) {
                editor.remove_rule(working_.rules[static_cast<size_t>(row)].id);
            });
        });
        connect(ok, &QPushButton::clicked, this, [this] { commit(); });
        connect(close, &QPushButton::clicked, this, &QDialog::reject);
        connect(table_, &QTableView::clicked, this, [this](const QModelIndex& index) {
            if (index.column() >= 3 && index.column() <= 4 &&
                (index.flags() & Qt::ItemIsEditable) &&
                !(QApplication::keyboardModifiers() & (Qt::ControlModifier | Qt::ShiftModifier)))
                table_->edit(index);
        });
        connect(table_, &QTableView::doubleClicked, this, [edit](const QModelIndex& index) {
            if (index.column() > 0 && index.column() < 3)
                edit->click();
        });
    }

protected:
    void paintEvent(QPaintEvent* event) override {
        QDialog::paintEvent(event);
        if (initializationScheduled_)
            return;
        initializationScheduled_ = true;
        QTimer::singleShot(0, this, [this] {
            original_ = target_;
            working_ = target_;
            model_->refresh();
            table_->doItemsLayout();
            for (auto* control : initializationControls_)
                control->setEnabled(true);
            updateSingleRuleControls_();
        });
    }

private:
    void commit() {
        if (working_ == original_) {
            accept();
            return;
        }
        const auto previous = target_;
        target_ = working_;
        if (changed_()) {
            original_ = working_;
            accept();
        } else
            target_ = previous;
    }
    template <class F> void apply(F fn, uint32_t selectedId = 0) {
        try {
            nd::ConfigEditor editor(working_);
            fn(editor);
            working_ = editor.get();
            reload(selectedId);
        } catch (const std::exception& e) {
            QMessageBox::critical(this, "NativeDNS", e.what());
        }
    }
    std::unordered_set<uint32_t> selectedRuleIds(const QModelIndex& clicked) const {
        std::unordered_set<uint32_t> ids;
        if (table_->selectionModel()->isSelected(clicked))
            for (const auto& index : table_->selectionModel()->selectedRows())
                ids.insert(index.data(ruleIdRole).toUInt());
        else
            ids.insert(clicked.data(ruleIdRole).toUInt());
        return ids;
    }
    bool updateRules(const std::unordered_set<uint32_t>& ids,
                     const std::function<void(nd::Rule&)>& update) {
        try {
            auto next = working_;
            for (auto& rule : next.rules)
                if (ids.contains(rule.id))
                    update(rule);
            if (next == working_)
                return true;
            // Validate and publish the whole batch once, including for large rule lists.
            nd::validate(next);
            working_ = std::move(next);
            model_->refreshRuleData();
            return true;
        } catch (const std::exception& e) {
            QMessageBox::critical(this, "NativeDNS", e.what());
            model_->refreshRuleData();
            return false;
        }
    }
    void move(int direction) {
        const int row = table_->currentIndex().row();
        if (row < 0)
            return;
        const auto id = working_.rules[static_cast<size_t>(row)].id;
        apply([&](nd::ConfigEditor& editor) { editor.move_rule(id, direction); }, id);
    }
    void reload(uint32_t selectedId = 0) {
        model_->refresh();
        int selectedRow = -1;
        if (selectedId)
            for (size_t row = 0; row < working_.rules.size(); ++row)
                if (working_.rules[row].id == selectedId) {
                    selectedRow = static_cast<int>(row);
                    break;
                }
        if (selectedRow >= 0)
            table_->selectRow(selectedRow);
    }
    nd::Config& target_;
    nd::Config original_;
    nd::Config working_;
    std::function<bool()> changed_;
    RulesTableModel* model_ = nullptr;
    QTableView* table_ = nullptr;
    std::vector<QWidget*> initializationControls_;
    std::function<void()> updateSingleRuleControls_;
    bool initializationScheduled_ = false;
};
} // namespace

NativeDnsWindow::NativeDnsWindow(bool background, bool diagnostic_logging)
    : diagnosticLogging_(diagnostic_logging) {
    (void)background;
    loadConfiguration();
    buildUi();
    if (diagnosticLogging_) {
        log_->applyDiagnosticPreset();
        setWindowTitle(windowTitle() + " (" + uiText("Diagnostic capture") + ")");
    }
    appendLocalLog(uiText("Configuration file: ") + qPath(configPath()));
    QNetworkInformation::loadDefaultBackend();
    const auto initialNetwork = probeNetwork(currentReachability());
    networkAvailable_ = initialNetwork.available;
    networkSignature_ = initialNetwork.signature;
    connect(&statusTimer_, &QTimer::timeout, this, [this] { refreshStatus(); });
    connect(&logTimer_, &QTimer::timeout, this, [this] { refreshLogs(); });
    connect(qApp, &QCoreApplication::aboutToQuit, this, [this] {
        if (updateDialog_)
            updateDialog_->reject();
        shutdownCoreForExit();
    });
    statusTimer_.start(1000);
    logTimer_.start(500);
    statusTimer_.setTimerType(Qt::CoarseTimer);
    logTimer_.setTimerType(Qt::CoarseTimer);
    QTimer::singleShot(100, this, [this] {
        ensureCoreStarted();
    });
    QTimer::singleShot(1000, this, [this] {
        if (exiting_ || !startupUpdateCheckEnabled() || updateDialog_)
            return;
        auto* dialog = new UpdateDialog(QCoreApplication::applicationVersion(), this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        attachUpdateInstaller(dialog);
        updateDialog_ = dialog;
        dialog->checkOnStart();
    });
}

NativeDnsWindow::~NativeDnsWindow() {
    shutdownCoreForExit();
    if (tray_)
        tray_->hide();
}

void NativeDnsWindow::ensureCoreStarted() {
    startCore(true);
}
std::filesystem::path NativeDnsWindow::configPath() const {
    return nd::platform::user_config_directory() / "NativeDNS.xml";
}

void NativeDnsWindow::showAndActivate() {
    activateApplicationWindow(*this);
}

bool NativeDnsWindow::hasSystemTray() const {
    return trayAvailable_ && tray_ && QSystemTrayIcon::isSystemTrayAvailable();
}

void NativeDnsWindow::buildUi() {
    setWindowTitle("NativeDNS " + QCoreApplication::applicationVersion());
    setWindowIcon(QApplication::windowIcon());
    resize(900, 560);
    setMinimumSize(680, 420);
    auto mark = [](QAction* action, const char* key) {
        action->setProperty("uiTextKey", QString::fromUtf8(key));
        action->setText(uiText(key));
        return action;
    };
    auto addMenu = [this, &mark](const char* key) {
        auto* menu = menuBar()->addMenu(QString{});
        mark(menu->menuAction(), key);
        return menu;
    };
    auto addAction = [&mark](QMenu* menu, const char* key) {
        return mark(menu->addAction(QString{}), key);
    };
    auto addSubMenu = [&mark](QMenu* parent, const char* key) {
        auto* menu = parent->addMenu(QString{});
        mark(menu->menuAction(), key);
        return menu;
    };

    log_ = new LogPanel(this, nullptr, diagnosticLogging_);
    setCentralWidget(log_);
    coreStatus_ = new QLabel(uiText("Core: starting..."), this);
    coreStatus_->installEventFilter(this);
    statusBar()->addPermanentWidget(log_->countLabel(), 1);
    statusBar()->addPermanentWidget(coreStatus_);

    auto* file = addMenu("&File");
    auto* newCfg = addAction(file, "New Configuration");
    auto* import = addAction(file, "Import Configuration");
    auto* exportCfg = addAction(file, "Export Configuration");
    file->addSeparator();
    auto* autostart = addAction(file, "Autostart");
    autostart->setCheckable(true);
    autostartAction_ = autostart;
    connect(file, &QMenu::aboutToShow, this, [this] { refreshAutostartAction(); });
    file->addSeparator();
    auto* exit = addAction(file, "Exit");

    auto* viewMenu = addMenu("&View");
    viewMenu->setObjectName("viewMenu");
    auto* show = addSubMenu(viewMenu, "Show...");
    show->setObjectName("logVisibilityMenu");
    addLogVisibilityActions(show, *log_);
    viewMenu->addSeparator();

    auto* config = addMenu("&Configuration");
    auto* servers = addAction(config, "DNS Servers");
    auto* rules = addAction(config, "Rules");
    auto* serverPools = addAction(config, "Server Pools");
#ifdef _WIN32
    config->addSeparator();
    prepareSystemDnsAction_ = addAction(config, "Temporarily disable Windows encrypted DNS");
    prepareSystemDnsAction_->setObjectName("prepareSystemDnsAction");
    prepareSystemDnsAction_->setCheckable(true);
    syncConfigurationActions();
    connect(prepareSystemDnsAction_, &QAction::toggled, this, [this](bool enabled) {
        const auto previous = config_;
        config_.settings["windowsPrepareSystemDns"] = enabled ? "1" : "0";
        if (!applyConfiguration()) config_ = previous;
        syncConfigurationActions();
    });
#endif

    // Too early to expose Advanced features; keep the menu hidden for now.
    auto* advanced = addMenu("&Advanced");
    advanced->menuAction()->setVisible(false);
    // Too early to enable additional modules; preserve this placeholder for future work.
    auto* note = addAction(advanced, "Additional modules will appear here");
    note->setEnabled(false);

    auto* logMenu = addMenu("&Log");
    auto* clear = addAction(logMenu, "Clear Display");
    auto* restart = mark(new QAction(this), "Restart");
    auto* screen = addSubMenu(logMenu, "Details");
    screen->setObjectName("logDetailsMenu");
    auto* group = new QActionGroup(this);
    group->setExclusive(true);
    const int configuredLevel = diagnosticLogging_ ? 3 : std::clamp(static_cast<int>(config_.logging.screen), 0, 3);
    for (int i = 0; i < 4; ++i) {
        static constexpr const char* levelKeys[]{"Errors Only", "Normal", "Verbose", "Debug"};
        auto* action = addAction(screen, levelKeys[i]);
        action->setEnabled(!diagnosticLogging_);
        action->setCheckable(true);
        action->setData(i);
        group->addAction(action);
        if (i == configuredLevel)
            action->setChecked(true);
        connect(action, &QAction::triggered, this, [this, i] {
            config_.logging.screen = static_cast<nd::Level>(i);
            saveConfiguration();
            refreshLogs();
        });
    }
    auto* views = addSubMenu(logMenu, "View");
    views->setObjectName("logViewMenu");
    addLogViewActions(views, *log_);
    auto* actions = addSubMenu(logMenu, "Show only action...");
    actions->setObjectName("logActionFilterMenu");
    addLogActionFilterActions(actions, *log_);
    auto* commands = addSubMenu(logMenu, "Show only commands...");
    commands->setObjectName("logCommandsFilterMenu");
    addLogCommandFilterActions(commands, *log_, actions);
    auto* errors = addSubMenu(logMenu, "Show only errors...");
    errors->setObjectName("logErrorsFilterMenu");
    addLogErrorFilterActions(errors, *log_);

    auto* diagnosticsMenu = addMenu("&Diagnostics");
    diagnosticsMenu->setObjectName("diagnosticsMenu");
    auto* interceptionDiagnostics = addAction(diagnosticsMenu, "Interception Diagnostics");
    connect(interceptionDiagnostics,
            &QAction::triggered,
            this,
            &NativeDnsWindow::openInterceptionDiagnostics);
#ifdef _WIN32
    auto* collectDiagnostics = addAction(diagnosticsMenu, "Collect diagnostic report...");
    collectDiagnostics->setObjectName("collectDiagnosticsAction");
    connect(collectDiagnostics, &QAction::triggered, this, [this, collectDiagnostics] {
        bool accepted = false;
        const auto host = QInputDialog::getText(this, uiText("Collect diagnostic report..."),
            uiText("Domain to test:"), QLineEdit::Normal, q(config_.test_target), &accepted).trimmed();
        if (!accepted || host.isEmpty()) return;
        try { (void)nd::normalize_host(s(host)); }
        catch (const std::exception& error) { QMessageBox::warning(this, "NativeDNS", q(error.what())); return; }
        auto* process = new QProcess(this);
        auto* progress = new QProgressDialog(uiText("Collecting diagnostic report..."), QString{}, 0, 0, this);
        progress->setCancelButton(nullptr); progress->setWindowModality(Qt::WindowModal);
        progress->setMinimumDuration(0); collectDiagnostics->setEnabled(false);
        auto finish = [this, process, progress, collectDiagnostics](bool success) {
            progress->close(); progress->deleteLater(); collectDiagnostics->setEnabled(true);
            process->deleteLater();
            if (success) {
                QString directory = qPath(nd::platform::application_root_directory() / "logs");
                for (const auto& row :
                     QString::fromUtf8(process->readAllStandardOutput()).split('\n'))
                    if (row.startsWith("Archive="))
                        directory = QFileInfo(row.mid(8).trimmed()).absolutePath();
                QDesktopServices::openUrl(QUrl::fromLocalFile(directory));
            } else
                QMessageBox::warning(
                    this,
                    "NativeDNS",
                    uiText("Diagnostic collection failed. Check the logs folder."));
        };
        connect(process, &QProcess::finished, this, [finish](int code, QProcess::ExitStatus status) { finish(code == 0 && status == QProcess::NormalExit); });
        connect(process, &QProcess::errorOccurred, this, [finish](QProcess::ProcessError error) { if (error == QProcess::FailedToStart) finish(false); });
        process->start(qPath(nd::platform::gui_entrypoint()), {"--collect", "--quiet", "--host", host, "--config", qPath(configPath())});
    });
#endif
    diagnosticsMenu->addSeparator();
    auto* fileEnabled = addAction(diagnosticsMenu, "Write diagnostic file");
    fileEnabled->setCheckable(true);
    fileEnabled->setChecked(diagnosticLogging_ || config_.logging.file_enabled);
    fileEnabled->setEnabled(!diagnosticLogging_);
    connect(fileEnabled, &QAction::toggled, this, [this](bool enabled) {
        config_.logging.file_enabled = enabled;
        applyFileLogging();
    });
    auto* fileLevel = addSubMenu(diagnosticsMenu, "File level");
    auto* fileGroup = new QActionGroup(this);
    fileGroup->setExclusive(true);
    const int configuredFileLevel = diagnosticLogging_ ? 3 : std::clamp(static_cast<int>(config_.logging.file), 0, 3);
    for (int i = 0; i < 4; ++i) {
        static constexpr const char* levelKeys[]{"Errors Only", "Normal", "Verbose", "Debug"};
        auto* action = addAction(fileLevel, levelKeys[i]);
        action->setEnabled(!diagnosticLogging_);
        action->setCheckable(true);
        fileGroup->addAction(action);
        if (i == configuredFileLevel)
            action->setChecked(true);
        connect(action, &QAction::triggered, this, [this, i] {
            config_.logging.file = static_cast<nd::Level>(i);
            applyFileLogging();
        });
    }
    auto* clearFile = addAction(diagnosticsMenu, "Clear Diagnostic File");
    auto* openLogFolder = addAction(diagnosticsMenu, "Open Log Folder");
    connect(clearFile, &QAction::triggered, this, [this] {
        try {
            const auto response =
                nd::pipe_request(nd::core_pipe_name, nd::IpcOperation::clear_file_log, {}, 500);
            if (response.status)
                throw std::runtime_error(response.payload);
        } catch (const std::exception& error) {
            QMessageBox::warning(this, "NativeDNS Log", error.what());
        }
    });
    connect(openLogFolder, &QAction::triggered, this, [this] {
        try {
            const auto directory = nd::platform::application_root_directory() / "logs";
            std::filesystem::create_directories(directory);
            QDesktopServices::openUrl(QUrl::fromLocalFile(qPath(directory)));
        } catch (...) {
        }
    });

    QSettings uiSettings;
    hideToTray_ = uiSettings.value("ui/hideToTray", true).toBool();
    darkTheme_ = uiSettings.value("ui/darkTheme", false).toBool();

    auto* language = addSubMenu(viewMenu, "Language");
    auto* english = addAction(language, "English");
    english->setCheckable(true);
    auto* russian = addAction(language, "Русский");
    russian->setCheckable(true);
    auto* languageGroup = new QActionGroup(this);
    languageGroup->setExclusive(true);
    languageGroup->addAction(english);
    languageGroup->addAction(russian);
    english->setChecked(uiLanguage() == UiLanguage::english);
    russian->setChecked(uiLanguage() == UiLanguage::russian);
    auto* theme = addSubMenu(viewMenu, "Theme");
    auto* light = addAction(theme, "Light");
    light->setCheckable(true);
    light->setChecked(!darkTheme_);
    auto* dark = addAction(theme, "Dark");
    dark->setCheckable(true);
    dark->setChecked(darkTheme_);
    auto* themeGroup = new QActionGroup(this);
    themeGroup->setExclusive(true);
    themeGroup->addAction(light);
    themeGroup->addAction(dark);
    viewMenu->addSeparator();
    hideToTrayAction_ = addAction(viewMenu, "Hide to tray");
    hideToTrayAction_->setCheckable(true);
    hideToTrayAction_->setChecked(hideToTray_);

    auto* help = addMenu("&Help");
    auto* checkUpdates = addAction(help, "Check for updates");
    auto* startupUpdates = addStartupUpdateCheckAction(help);
    connect(startupUpdates, &QAction::triggered, this, [this] {
        if (!startupUpdateCheckEnabled() && updateDialog_)
            updateDialog_->cancelStartupCheck();
    });
    help->addSeparator();
    auto* about = addAction(help, "About NativeDNS");

    auto* bar = addToolBar("Main");
    bar->setObjectName("mainToolBar");
    bar->setMovable(false);
    bar->setIconSize(QSize(32, 32));
    bar->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    auto* toolbarServers = mark(new QAction(this), "DNS Servers");
    auto* toolbarRules = mark(new QAction(this), "Rules");
    auto* toolbarPools = mark(new QAction(this), "Server Pools");
    const auto setActionIcons = [servers,
                                 rules,
                                 serverPools,
                                 clear,
                                 restart,
                                 toolbarServers,
                                 toolbarRules,
                                 toolbarPools](bool dark) {
        const auto serverIcon = makeActionIcon(ActionIcon::dns_servers, dark);
        const auto rulesIcon = makeActionIcon(ActionIcon::rules, dark);
        const auto poolsIcon = makeActionIcon(ActionIcon::server_pools, dark);
        servers->setIcon(serverIcon);
        toolbarServers->setIcon(serverIcon);
        rules->setIcon(rulesIcon);
        toolbarRules->setIcon(rulesIcon);
        serverPools->setIcon(poolsIcon);
        toolbarPools->setIcon(poolsIcon);
        clear->setIcon(makeActionIcon(ActionIcon::clear_display, dark));
        restart->setIcon(makeActionIcon(ActionIcon::restart, dark));
    };
    setActionIcons(darkTheme_);
    const auto addToolbarButton = [bar](QAction* action) {
        auto* button = new ToolbarButton(bar);
        button->setDefaultAction(action);
        button->setIconSize(bar->iconSize());
        button->setToolButtonStyle(bar->toolButtonStyle());
        bar->addWidget(button);
    };
    addToolbarButton(toolbarServers);
    addToolbarButton(toolbarRules);
    addToolbarButton(toolbarPools);
    bar->addSeparator();
    addToolbarButton(clear);
    addToolbarButton(restart);

    trayAvailable_ = QSystemTrayIcon::isSystemTrayAvailable();
    QIcon trayIcon = QApplication::windowIcon();
    if (trayIcon.isNull())
        trayIcon = style()->standardIcon(QStyle::SP_ComputerIcon);
    tray_ = new QSystemTrayIcon(trayIcon, this);
    tray_->setToolTip("NativeDNS");
    auto* trayMenu = new QMenu(this);
    auto* open = addAction(trayMenu, "Open NativeDNS");
    QFont openFont = open->font();
    openFont.setBold(true);
    open->setFont(openFont);
    trayMenu->setDefaultAction(open);
    trayMenu->addAction(servers);
    trayMenu->addAction(rules);
    trayMenu->addAction(serverPools);
    trayMenu->addAction(restart);
    trayMenu->addSeparator();
    trayMenu->addAction(exit);
    tray_->setContextMenu(trayMenu);
    if (trayAvailable_)
        tray_->show();
    else {
        hideToTray_ = false;
        hideToTrayAction_->setChecked(false);
        hideToTrayAction_->setEnabled(false);
        hideToTrayAction_->setToolTip("The desktop system tray is not available.");
    }

    connect(
        tray_, &QSystemTrayIcon::activated, this, [this](QSystemTrayIcon::ActivationReason reason) {
            if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick)
                showAndActivate();
        });
    connect(open, &QAction::triggered, this, [this] { showAndActivate(); });
    connect(english, &QAction::triggered, this, [this] {
        setUiLanguage(UiLanguage::english);
        QSettings().setValue("ui/language", "en");
        retranslateUi();
    });
    connect(russian, &QAction::triggered, this, [this] {
        setUiLanguage(UiLanguage::russian);
        QSettings().setValue("ui/language", "ru");
        retranslateUi();
    });
    connect(light, &QAction::triggered, this, [this, setActionIcons] {
        darkTheme_ = false;
        QSettings().setValue("ui/darkTheme", false);
        applyUiTheme(*qApp, false);
        setActionIcons(false);
        if (!coreStatus_->styleSheet().isEmpty())
            coreStatus_->setStyleSheet("color: #be0000;");
        refreshStatus();
    });
    connect(dark, &QAction::triggered, this, [this, setActionIcons] {
        darkTheme_ = true;
        QSettings().setValue("ui/darkTheme", true);
        applyUiTheme(*qApp, true);
        setActionIcons(true);
        if (!coreStatus_->styleSheet().isEmpty())
            coreStatus_->setStyleSheet("color: #ff6969;");
        refreshStatus();
    });

    connect(newCfg, &QAction::triggered, this, [this] {
        if (QMessageBox::question(this, "NativeDNS", uiText("Create a new configuration?")) ==
            QMessageBox::Yes) {
            config_ = nd::default_config();
            if (applyConfiguration())
                log_->clear();
        }
    });
    connect(import, &QAction::triggered, this, [this] { importConfiguration(); });
    connect(exportCfg, &QAction::triggered, this, [this] { exportConfiguration(); });
    connect(servers, &QAction::triggered, this, [this] { openServers(); });
    connect(rules, &QAction::triggered, this, [this] { openRules(); });
    connect(serverPools, &QAction::triggered, this, [this] { openServerPools(); });
    connect(toolbarServers, &QAction::triggered, this, [this] { openServers(); });
    connect(toolbarRules, &QAction::triggered, this, [this] { openRules(); });
    connect(toolbarPools, &QAction::triggered, this, [this] { openServerPools(); });
    connect(restart, &QAction::triggered, this, [this] { requestCoreRestart(); });
    connect(clear, &QAction::triggered, this, [this] {
        log_->clear();
        logSequence_ = 0;
        try {
            (void)nd::pipe_request(nd::core_pipe_name, nd::IpcOperation::clear_display, {}, 100);
        } catch (...) {
        }
    });
    connect(hideToTrayAction_, &QAction::toggled, this, [this](bool enabled) {
        if (enabled && !trayAvailable_) {
            QSignalBlocker blocker(hideToTrayAction_);
            hideToTrayAction_->setChecked(false);
            return;
        }
        hideToTray_ = enabled;
        QSettings settings;
        settings.setValue("ui/hideToTray", enabled);
    });
    connect(exit, &QAction::triggered, this, [this] { exitApplication(); });
    connect(about, &QAction::triggered, this, [this] { showAboutDialog(this); });
    connect(checkUpdates, &QAction::triggered, this, [this] {
        if (!updateDialog_) {
            auto* dialog = new UpdateDialog(QCoreApplication::applicationVersion(), this);
            dialog->setAttribute(Qt::WA_DeleteOnClose);
            attachUpdateInstaller(dialog);
            updateDialog_ = dialog;
            dialog->show();
            dialog->check();
        } else {
            updateDialog_->showForManualCheck();
        }
    });

    connect(autostart, &QAction::toggled, this, [this, autostart](bool enabled) {
        const bool applyEnabled = autostartNeedsRepair_ ? true : enabled;
        try {
#ifdef _WIN32
            // Registering a highest-privilege Scheduled Task requires elevation.
            // Keep the Qt GUI unprivileged and elevate only the CoreHost bootstrap,
            // which also acts as a tiny one-shot privileged helper.
            const QString coreHost =
                coreHostExecutable();
            if (!QFileInfo(coreHost).isFile())
                throw std::runtime_error("NativeDNS.CoreHost.exe is missing");

            QStringList args;
            if (applyEnabled)
                args << "--register-autostart" << qPath(configPath()) << "--gui-executable"
                     << qPath(nd::platform::gui_entrypoint());
            else
                args << "--unregister-autostart";

            int exitCode = -1;
            QString launchError;
            if (!runNativeDnsHelper(coreHost, args, true, &exitCode, &launchError))
                throw std::runtime_error(s(launchError));
            if (exitCode != 0)
                throw std::runtime_error("Elevated autostart helper failed with exit code " +
                                         std::to_string(exitCode));
#else
        // Linux autostart is a user-level desktop entry. Transparent CoreHost
        // elevation still happens separately through pkexec when Core starts.
        const auto executable=fsPath(QCoreApplication::applicationFilePath());
        if(applyEnabled)nd::enable_autostart(executable,configPath());else nd::disable_autostart();
#endif
            refreshAutostartAction();
        } catch (const std::exception& e) {
            showCriticalAlert(this, "Autostart", e.what());
            refreshAutostartAction();
        }
    });
    refreshAutostartAction();
}

void NativeDnsWindow::attachUpdateInstaller(UpdateDialog* dialog) {
    if (!dialog)
        return;
    dialog->setDistributionKind(nd::platform::distribution_kind());
    dialog->setInstallHandler(
        [this](const ReleaseAsset&, const QString& downloadedPath, QString& error) -> bool {
#ifdef _WIN32
            const auto root = nd::platform::application_root_directory();
            const auto updaterSource = root / L"Updater.exe";
            std::error_code ec;
            if (!std::filesystem::is_regular_file(updaterSource, ec)) {
                error = uiText("Updater.exe was not found next to NativeDNS.exe.");
                return false;
            }

            const QString tempRoot = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
            if (tempRoot.isEmpty()) {
                error = uiText("Cannot access the system temporary directory.");
                return false;
            }

            const auto stagingDir = fsPath(tempRoot) /
                                    (L"NativeDNS-Updater-" +
                                     std::to_wstring(QCoreApplication::applicationPid()) + L"-" +
                                     std::to_wstring(QDateTime::currentMSecsSinceEpoch()));
            std::filesystem::create_directories(stagingDir, ec);
            if (ec) {
                error = uiText("Cannot prepare temporary updater directory.");
                return false;
            }

            const auto updaterCopy = stagingDir / L"Updater.exe";
            std::filesystem::copy_file(updaterSource,
                                       updaterCopy,
                                       std::filesystem::copy_options::overwrite_existing,
                                       ec);
            if (ec) {
                std::filesystem::remove_all(stagingDir, ec);
                error = uiText("Cannot copy Updater.exe to temporary directory.");
                return false;
            }

            const auto distKind = nd::platform::distribution_kind();
            const QString mode = distKind == nd::platform::DistributionKind::executable
                                     ? "executable"
                                     : "portable";
            QStringList args;
            args << "--mode" << mode << "--install-dir" << qPath(root) << "--package"
                 << downloadedPath << "--wait-pid"
                 << QString::number(QCoreApplication::applicationPid()) << "--lang"
                 << (uiLanguage() == UiLanguage::russian ? "ru" : "en") << "--cleanup-package";
            if (diagnosticLogging_)
                args << "--relaunch-args" << "--diagnostics";

            if (!QProcess::startDetached(qPath(updaterCopy), args, qPath(stagingDir))) {
                std::filesystem::remove_all(stagingDir, ec);
                error = uiText("Cannot launch the updater.");
                return false;
            }

            appendLocalLog(uiText("Launching updater and closing NativeDNS..."));
            QTimer::singleShot(0, this, [this] { exitApplication(); });
            return true;
#else
            (void)downloadedPath;
            error = uiText("Automatic installation is currently supported on Windows only. Use "
                           "Open release to download manually.");
            return false;
#endif
        });
}

void NativeDnsWindow::refreshAutostartAction() {
    if (!autostartAction_)
        return;
    try {
        QSignalBlocker blocker(autostartAction_);
        const auto status = nd::autostart_status();
        autostartNeedsRepair_ = status.enabled && status.needs_repair;
        autostartAction_->setChecked(status.enabled);
        const char* key =
            autostartNeedsRepair_ ? "Autostart (reselect to apply)" : "Autostart";
        autostartAction_->setText(uiText(key));
        autostartAction_->setProperty("uiTextKey", key);
        autostartAction_->setProperty("warningIcon", autostartNeedsRepair_);
        autostartAction_->setToolTip(
            autostartNeedsRepair_
                ? uiText("Autostart registration is outdated. Click Autostart to apply the "
                         "current application path.")
                : QString{});
    } catch (...) {
    }
}

void NativeDnsWindow::retranslateUi() {
    syncConfigurationActions();
    refreshAutostartAction();
    log_->retranslateUi();
    const auto actions = findChildren<QAction*>();
    for (auto* action : actions) {
        const auto key = action->property("uiTextKey").toString();
        if (!key.isEmpty())
            action->setText(uiText(key.toUtf8().constData()));
    }
    refreshStatus();
}

void NativeDnsWindow::loadConfiguration() {
    const auto path = configPath();
    try {
        if (std::filesystem::exists(path))
            config_ = nd::load_config(path);
        else {
            std::filesystem::create_directories(path.parent_path());
            config_ = nd::default_config();
            nd::save_config(config_, path);
        }
    } catch (const std::exception& e) {
        auto backup = path;
        backup += ".bak";
        std::optional<nd::Config> backupConfig;
        if (std::filesystem::exists(backup)) {
            try {
                backupConfig = nd::load_config(backup);
            } catch (...) {
            }
        }
        if (backupConfig) {
            const auto answer = QMessageBox::question(
                this,
                uiText("Configuration"),
                q(e.what()) + "\n\n" +
                    uiText("Restore the last valid backup? Choose No to reset to defaults. The "
                           "unreadable file will be archived without overwriting the backup."));
            config_ = answer == QMessageBox::Yes ? *backupConfig : nd::default_config();
        } else {
            showCriticalAlert(
                this,
                uiText("Configuration"),
                q(e.what()) + "\n\n" +
                    uiText("The unreadable configuration will be archived and reset to defaults."));
            config_ = nd::default_config();
        }
        try {
            (void)nd::save_config_replacing_corrupt(config_, path);
        } catch (const std::exception& recoverError) {
            showCriticalAlert(this, uiText("Configuration"), recoverError.what());
        }
    }
}

bool NativeDnsWindow::saveConfiguration() {
    try {
        nd::save_config(config_, configPath());
        return true;
    } catch (const std::exception& e) {
        showCriticalAlert(this, uiText("Configuration"), e.what());
        return false;
    }
}
bool NativeDnsWindow::applyConfiguration() {
    const auto path = configPath();
    std::optional<nd::Config> previous;
    bool corruptOnDisk = false;
    try {
        if (std::filesystem::exists(path))
            previous = nd::load_config(path);
    } catch (...) {
        corruptOnDisk = true;
    }
    if (corruptOnDisk) {
        try {
            const auto archived = nd::save_config_replacing_corrupt(config_, path);
            if (!archived.empty())
                appendLocalLog(uiText("Archived unreadable configuration to: ") + qPath(archived),
                               true);
        } catch (const std::exception& error) {
            showCriticalAlert(this, uiText("Configuration"), error.what());
            return false;
        }
    } else if (!saveConfiguration()) {
        return false;
    }
    if (restartCore()) {
        syncConfigurationActions();
        return true;
    }
    if (!reloadRejected_) {
        syncConfigurationActions();
        return true;
    }
    if (previous) {
        try {
            nd::save_config(*previous, configPath());
            config_ = *previous;
        } catch (const std::exception& error) {
            showCriticalAlert(this, uiText("Configuration"), error.what());
        }
    }
    syncConfigurationActions();
    return false;
}
void NativeDnsWindow::syncConfigurationActions() {
    if (!prepareSystemDnsAction_) return;
    QSignalBlocker blocker(prepareSystemDnsAction_);
    prepareSystemDnsAction_->setChecked(nd::runtime_options(config_).prepare_system_dns);
    prepareSystemDnsAction_->setToolTip(uiText(
        "Original Windows DNS encryption is restored on Stop or Exit, or on the next start after a crash. DNS addresses and hosts are preserved."));
}
std::string NativeDnsWindow::effectiveFingerprint() const {
    return nd::routing_fingerprint(config_);
}
std::string NativeDnsWindow::reloadRequest(const std::string& id) const {
    return "routing=" + id + (diagnosticLogging_ ? "\tdiagnostics=1" : "\tdiagnostics=0");
}
bool NativeDnsWindow::restartCore() {
    reloadRejected_ = false;
    configurationConfirmed_ = false;
    const auto expected = effectiveFingerprint();
    const auto request = reloadRequest(expected);
    auto outcome = std::make_shared<ReloadOutcome>();
    QEventLoop loop;
    QProgressDialog progress(uiText("Applying DNS configuration..."), QString{}, 0, 0, this);
    progress.setCancelButton(nullptr);
    progress.setWindowModality(Qt::WindowModal);
    progress.setMinimumDuration(250);
    QThreadPool::globalInstance()->start([outcome, expected, request, &loop] {
        *outcome = executeConfigReload(expected, request, 5000);
        QMetaObject::invokeMethod(&loop, &QEventLoop::quit, Qt::QueuedConnection);
    });
    loop.exec(QEventLoop::ExcludeUserInputEvents);
    progress.close();
    if (outcome->ok) {
        configurationConfirmed_ = true;
        restartWhenNetworkReturns_ = false;
        appendLocalLog(uiText("DNS configuration reloaded without stopping the core."));
        refreshStatus();
        return true;
    }
    if (outcome->connectFailed) {
        coreLaunchPending_ = false;
        startCore(true);
        return true;
    }
    reloadRejected_ = true;
    appendLocalLog(uiText("DNS configuration reload failed: ") + outcome->error, true);
    showCriticalAlert(this, "NativeDNS", outcome->error);
    return false;
}
void NativeDnsWindow::requestCoreRestart() {
    if (exiting_ || restartOperationPending_.exchange(true))
        return;
    appendLocalLog(uiText("Reloading DNS configuration..."));
    const auto expected = effectiveFingerprint();
    QPointer<NativeDnsWindow> self(this);
    const auto captureRequest = reloadRequest(expected);
    QThreadPool::globalInstance()->start([self, expected, captureRequest] {
        const auto outcome = executeConfigReload(expected, captureRequest, 10000);
        QMetaObject::invokeMethod(
            qApp,
            [self, outcome] {
                if (!self)
                    return;
                self->restartOperationPending_ = false;
                if (self->exiting_)
                    return;
                if (outcome.connectFailed) {
                    self->startCore(true);
                } else if (!outcome.ok) {
                    self->appendLocalLog(uiText("DNS configuration reload failed: ") + outcome.error,
                                         true);
                } else {
                    self->restartWhenNetworkReturns_ = false;
                    self->appendLocalLog(
                        uiText("DNS configuration reloaded without stopping the core."));
                    self->refreshStatus();
                }
            },
            Qt::QueuedConnection);
    });
}
void NativeDnsWindow::applyFileLogging() {
    if (!saveConfiguration())
        return;
    try {
        const auto payload = std::string(diagnosticLogging_ || config_.logging.file_enabled ? "1" : "0") + '\t' +
                             std::to_string(diagnosticLogging_ ? 3u : static_cast<unsigned>(config_.logging.file));
        const auto response = nd::pipe_request(
            nd::core_pipe_name, nd::IpcOperation::configure_file_log, payload, 500);
        if (response.status)
            throw std::runtime_error(response.payload);
    } catch (...) {
        // The setting is persisted and will be applied when CoreHost starts.
    }
}
void NativeDnsWindow::openInterceptionDiagnostics() {
    QDialog dialog(this);
    dialog.setWindowTitle(uiText("Interception Diagnostics"));
    dialog.resize(820, 620);
    auto* layout = new QVBoxLayout(&dialog);
    auto* explanation = new QLabel(uiText("Running means the mechanism is started. Verified "
                                          "requires a successful active UDP/IPv4 test."),
                                   &dialog);
    explanation->setWordWrap(true);
    layout->addWidget(explanation);
    auto* text = new QPlainTextEdit(&dialog);
    text->setReadOnly(true);
    layout->addWidget(text);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    auto* refresh = buttons->addButton(uiText("Refresh"), QDialogButtonBox::ActionRole);
    auto* test =
        buttons->addButton(uiText("Run safe interception test"), QDialogButtonBox::ActionRole);
    test->setToolTip(uiText("Sends one UDP/53 query to a reserved TEST-NET address with TTL 1. It "
                            "may leave the computer if interception fails."));
#ifdef _WIN32
    auto* collect =
        buttons->addButton(uiText("Collect diagnostic report..."), QDialogButtonBox::ActionRole);
    connect(collect, &QPushButton::clicked, this, [this] {
        if (auto* action = findChild<QAction*>("collectDiagnosticsAction"))
            action->trigger();
    });
#endif
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    const auto load = [text, refresh, test](bool active) {
        refresh->setEnabled(false);
        test->setEnabled(false);
        QPointer<QPlainTextEdit> output(text);
        QPointer<QPushButton> refreshButton(refresh), testButton(test);
        QThreadPool::globalInstance()->start([output, refreshButton, testButton, active] {
            QString result;
            try {
                if (active) {
                    const auto probe = nd::pipe_request(
                        nd::core_pipe_name, nd::IpcOperation::interception_test, {}, 5000);
                    result += q(probe.payload) + "\n";
                }
                result += q(readCoreStatus().payload) + "\n";
                const auto status = nd::pipe_request(
                    nd::core_pipe_name, nd::IpcOperation::interception_status, {}, 5000);
                if (status.status)
                    throw std::runtime_error(status.payload);
                result += q(status.payload);
            } catch (const std::exception& error) {
                result += q(error.what());
            }
            QMetaObject::invokeMethod(
                qApp,
                [output, refreshButton, testButton, result] {
                    if (output)
                        output->setPlainText(result);
                    if (refreshButton)
                        refreshButton->setEnabled(true);
                    if (testButton)
                        testButton->setEnabled(true);
                },
                Qt::QueuedConnection);
        });
    };
    connect(refresh, &QPushButton::clicked, &dialog, [load] { load(false); });
    connect(test, &QPushButton::clicked, &dialog, [load] { load(true); });
    load(false);
    positionDialog(dialog, this);
    dialog.exec();
}
void NativeDnsWindow::openServers() {
    ServerDialog dialog(this, config_, [this] { return applyConfiguration(); });
    positionDialog(dialog, this);
    dialog.exec();
}
void NativeDnsWindow::openRules() {
    RulesDialog dialog(this, config_, [this] { return applyConfiguration(); });
    positionDialog(dialog, this);
    dialog.exec();
}
void NativeDnsWindow::openServerPools() {
    ServerPoolsDialog dialog(this, config_, [this] { return applyConfiguration(); });
    positionDialog(dialog, this);
    dialog.exec();
}
void NativeDnsWindow::importConfiguration() {
    const auto file = QFileDialog::getOpenFileName(
        this, uiText("Import Configuration"), {}, "DNS configuration (*.xml);;All files (*)");
    if (file.isEmpty())
        return;
    try {
        const auto path = fsPath(file);
        try {
            config_ = nd::load_config(path);
        } catch (const nd::Error&) {
            config_ = nd::import_yoga(path).config;
        }
        if (applyConfiguration())
            QMessageBox::information(this, "NativeDNS", uiText(configurationConfirmed_
                ? "Configuration imported." : "Configuration saved; CoreHost confirmation is pending."));
    } catch (const std::exception& e) {
        showCriticalAlert(this, uiText("Import"), e.what());
    }
}
void NativeDnsWindow::exportConfiguration() {
    const auto file = QFileDialog::getSaveFileName(
        this, uiText("Export Configuration"), "NativeDNS.xml", "XML (*.xml)");
    if (file.isEmpty())
        return;
    try {
        nd::save_config(config_, fsPath(file));
    } catch (const std::exception& e) {
        showCriticalAlert(this, uiText("Export"), e.what());
    }
}

void NativeDnsWindow::startCore(bool transparent, bool reportFailure) {
    if (exiting_)
        return;
    if (reportFailure)
        automaticRestarts_ = 0;
    if (coreLaunchPending_ && coreLaunchTimer_.isValid() && coreLaunchTimer_.elapsed() < 15000)
        return;
    if (restartWhenNetworkReturns_ && !reportFailure && networkProbeTimer_.isValid() &&
        networkProbeTimer_.elapsed() < 5000)
        return;
    if (coreStartOperationPending_.exchange(true))
        return;
    ++statusPollGeneration_;
    networkProbeTimer_.restart();
    const QString helper = coreHostExecutable();
    QStringList args{"--config", qPath(configPath())};
    if (diagnosticLogging_) args << "--diagnostics";
    if (transparent)
        args << "--transparent";
    const auto configuration = configPath();
    const auto captureRequest = reloadRequest(effectiveFingerprint());
    const auto launchState = coreLaunchState_;
    launchState->pending = true;
    launchState->cancelled = false;
    if (!restartWhenNetworkReturns_)
        setStatusText(uiText("Core: starting..."));
    QPointer<NativeDnsWindow> self(this);
    QThreadPool::globalInstance()->start(
        [self,
         helper,
         args,
         configuration,
         transparent,
         reportFailure,
         launchState,
         captureRequest,
         diagnostic = diagnosticLogging_] {
            bool success = false, running = false, scheduledDebug = false;
            QString failure, readyStatus;
            try {
                const auto response = readCoreStatus();
                if (response.status)
                    throw std::runtime_error(response.payload);
                if (response.payload.rfind("RUNNING", 0) == 0 ||
                    response.payload.rfind("STARTING", 0) == 0) {
                    success = true;
                    running = true;
                    if (response.payload.rfind("RUNNING", 0) == 0)
                        readyStatus = q(response.payload);
                } else {
                    const auto started =
                        nd::pipe_request(nd::core_pipe_name, nd::IpcOperation::start, {}, 500);
                    if (started.status)
                        throw std::runtime_error(started.payload);
                    success = true;
                    running = true;
                }
            } catch (const nd::Error& error) {
                if (error.code != "IPC_CONNECT" && error.code != "IPC_TIMEOUT")
                    failure = q(error.what());
            } catch (const std::exception& error) {
                failure = q(error.what());
            }
            if (success && running) {
                try {
                    const auto applied = nd::pipe_request(nd::core_pipe_name, nd::IpcOperation::reload_config, captureRequest, 10000);
                    if (applied.status)
                        throw std::runtime_error(applied.payload);
                } catch (const std::exception& error) {
                    success = false;
                    failure = q(error.what());
                }
            }
            if (!success && failure.isEmpty() && !launchState->cancelled) {
                // A missing/timed-out IPC endpoint does not mean its process
                // has exited. Never repeatedly launch into a held singleton.
                try {
                    nd::platform::ProcessInstanceLock probe(nd::core_instance_name,
                                                            nd::platform::InstanceScope::machine);
                    if (!probe.acquired())
                        failure =
                            uiText("CoreHost is running but its control channel is unavailable.");
                } catch (const std::exception& error) {
                    failure = q(error.what());
                }
            }
            if (!success && failure.isEmpty() && !launchState->cancelled) {
                bool launched = false;
#ifdef _WIN32
                if (transparent) {
                    try {
                        launched = nd::start_autostart_core(fsPath(helper), configuration);
                        scheduledDebug = launched && diagnostic;
                    } catch (const std::exception& error) {
                        QMetaObject::invokeMethod(
                            qApp,
                            [self, detail = q(error.what())] {
                                if (self)
                                    self->appendLocalLog(
                                        uiText("Scheduled CoreHost launch failed: ") + detail,
                                        true);
                            },
                            Qt::QueuedConnection);
                    }
                }
#endif
                QString launch_error;
                if (!launched && !launchState->cancelled)
                    launched = launchNativeDnsCore(helper, args, transparent, &launch_error);
                success = launched;
                launchState->issued = launched;
                if (!success && !launchState->cancelled)
                    failure = launch_error;
                if (launched) {
                    const auto deadline =
                        std::chrono::steady_clock::now() + std::chrono::seconds(10);
                    success = false;
                    while (!launchState->cancelled && std::chrono::steady_clock::now() < deadline) {
                        try {
                            const auto ready = readCoreStatus();
                            if (ready.status) {
                                failure = q(ready.payload);
                                break;
                            }
                            if (ready.payload.starts_with("STARTING")) {
                                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                                continue;
                            }
                            if (!ready.payload.starts_with("RUNNING")) {
                                failure = q(ready.payload);
                                break;
                            }
                            const auto applied = nd::pipe_request(nd::core_pipe_name,
                                                                  nd::IpcOperation::reload_config,
                                                                  captureRequest,
                                                                  10000);
                            if (applied.status) {
                                failure = q(applied.payload);
                                break;
                            }
                            readyStatus = q(ready.payload);
                            success = running = true;
                            break;
                        } catch (const nd::Error& error) {
                            if (error.code != "IPC_CONNECT" && error.code != "IPC_TIMEOUT") {
                                failure = q(error.what());
                                break;
                            }
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    if (!success && failure.isEmpty())
                        failure = uiText("CoreHost startup or IPC connection timed out.");
                }
            }
            launchState->pending = false;
            QMetaObject::invokeMethod(
                qApp,
                [self,
                 success,
                 running,
                 failure,
                 readyStatus,
                 reportFailure,
                 launchState,
                 scheduledDebug] {
                    if (!self)
                        return;
                    self->coreStartOperationPending_ = false;
                    ++self->statusPollGeneration_;
                    if (launchState->cancelled)
                        return;
                    self->restartWhenNetworkReturns_ = false;
                    if (!success) {
                        self->coreLaunchPending_ = false;
                        self->setStatusText(uiText("Core: stopped"), true);
                        self->appendLocalLog(uiText("Core startup failed: ") + failure, true);
                        if (reportFailure)
                            showCriticalAlert(self, "NativeDNS", failure);
                        return;
                    }
                    if (scheduledDebug)
                        self->appendLocalLog(
                            uiText("Debug logging enabled after scheduled startup; early "
                                   "initialization used the task's logging profile."));
                    self->coreLaunchPending_ = !running;
                    self->refreshAutostartAction();
                    if (running) {
                        self->coreLaunchState_->issued = false;
                        self->failedCorePolls_ = 0;
                        self->coreFailureTimer_.invalidate();
                        if (!readyStatus.isEmpty()) {
                            self->lastCoreStatus_ = readyStatus;
                            self->lastCoreContact_ =
                                QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
                            const bool degraded = readyStatus.contains("verification=DEGRADED");
                            self->setStatusText(
                                friendlyCoreStatus(readyStatus) +
                                    (degraded ? " | " + uiText("Interception degraded")
                                              : QString{}) +
                                    (self->networkAvailable_ ? QString{}
                                                             : " | " + uiText("Offline")),
                                degraded || !self->networkAvailable_);
                        }
                        self->refreshStatus();
                    } else {
                        self->coreLaunchTimer_.restart();
                        self->setStatusText(uiText("Core: starting..."));
                    }
                },
                Qt::QueuedConnection);
        });
}

namespace {
bool waitForCoreShutdown(int timeoutMs) {
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeoutMs) {
        try {
            nd::platform::ProcessInstanceLock probe(nd::core_instance_name,
                                                    nd::platform::InstanceScope::machine);
            if (probe.acquired())
                return true;
        } catch (...) {
            return false;
        }
        QThread::msleep(50);
    }
    return false;
}

template <typename LaunchState>
bool requestCoreShutdown(const std::shared_ptr<LaunchState>& launchState) {
    // Wait for the actual launch worker, not its queued GUI completion callback.
    QElapsedTimer startupWait;
    startupWait.start();
    while (launchState->pending && startupWait.elapsed() < 5000)
        QThread::msleep(50);
    if (launchState->pending)
        return false;
    if (launchState->issued) {
        // Shell/task launch success can precede the process acquiring its lock.
        // Do not mistake that interval for an already completed shutdown.
        startupWait.restart();
        bool appeared = false;
        while (startupWait.elapsed() < 5000) {
            try {
                nd::platform::ProcessInstanceLock probe(nd::core_instance_name,
                                                        nd::platform::InstanceScope::machine);
                appeared = !probe.acquired();
            } catch (...) {
                return false;
            }
            if (appeared)
                break;
            QThread::msleep(50);
        }
        if (!appeared)
            return false;
        launchState->issued = false;
    }
    QElapsedTimer shutdownWait;
    shutdownWait.start();
    while (shutdownWait.elapsed() < 12000) {
        if (waitForCoreShutdown(100)) {
            return true;
        }
        // The shutdown endpoint stays responsive independently of commands/logs.
        // The command fallback supports older CoreHost versions.
        for (const auto* endpoint : {nd::core_shutdown_pipe_name, nd::core_pipe_name}) {
            try {
                if (!nd::pipe_request(endpoint, nd::IpcOperation::shutdown, {}, 300).status) {
                    if (waitForCoreShutdown(11000)) {
                        return true;
                    }
                    return false;
                }
            } catch (...) {
                // A listener can be starting/recovering; keep probing the process.
            }
        }
    }
    return false;
}
} // namespace

bool NativeDnsWindow::shutdownCoreForExit() {
    if (coreShutdownAttempted_)
        return true;
    coreLaunchState_->cancelled = true;
    statusTimer_.stop();
    logTimer_.stop();
    coreLaunchPending_ = false;
    coreShutdownAttempted_ = requestCoreShutdown(coreLaunchState_);
    return coreShutdownAttempted_;
}

void NativeDnsWindow::showCoreControlFailure(const QString& details) {
    if (exiting_ || coreControlErrorLogged_ || coreControlDialog_)
        return;
    coreControlErrorLogged_ = true;
    appendLocalLog(uiText("Connection to CoreHost was lost.") + " " + details, true);
    auto* dialog = coreControlFailureDialog(
        this,
        details + "\n" + uiText("Last CoreHost response:") + " " +
            (lastCoreContact_.isEmpty() ? uiText("None")
                                        : lastCoreContact_ + " " + lastCoreStatus_) +
            "\n" + q(nd::platform::system_summary()));
    coreControlDialog_ = dialog;
    connect(dialog, &QMessageBox::buttonClicked, this, [this](QAbstractButton* button) {
        if (button->objectName() == "terminateApplication")
            exitApplication(true);
    });
    connect(dialog, &QObject::destroyed, this, [this] {
        if (coreHealthyTimer_.isValid() && coreHealthyTimer_.elapsed() >= 30000)
            coreControlErrorLogged_ = false;
    });
    dialog->show();
    activateApplicationWindow(*dialog);
    QApplication::alert(dialog);
}

void NativeDnsWindow::exitApplication(bool force) {
    if (exiting_)
        return;
    exiting_ = true;
    if (coreControlDialog_)
        coreControlDialog_->close();
    coreLaunchState_->cancelled = true;
    statusTimer_.stop();
    logTimer_.stop();
    setStatusText(force ? uiText("Core: terminating...") : uiText("Core: shutting down..."));
    const auto executable = coreHostExecutable();
    const auto launchState = coreLaunchState_;
    QPointer<NativeDnsWindow> self(this);
    // Emergency control must not queue behind blocked DNS tests/launch jobs.
    const auto exitConfirmed = exitConfirmed_;
    shutdownWorker_ = std::jthread([self, executable, launchState, force, exitConfirmed] {
        QString failure;
        try {
            if (force || !requestCoreShutdown(launchState)) {
                QElapsedTimer wait;
                wait.start();
                while (launchState->pending && wait.elapsed() < 5000)
                    QThread::msleep(50);
                if (launchState->pending)
                    throw std::runtime_error(
                        "CoreHost launch is still pending; shutdown cannot yet be confirmed.");
                const std::string roleArg =
                    QFileInfo(executable).fileName().compare("NativeDNS.exe", Qt::CaseInsensitive) == 0
                        ? "--core-host"
                        : "";
                auto targets = nd::platform::matching_processes(fsPath(executable), roleArg);
                if (launchState->issued && targets.empty()) {
                    wait.restart();
                    while (targets.empty() && wait.elapsed() < 5000) {
                        QThread::msleep(50);
                        targets = nd::platform::matching_processes(fsPath(executable), roleArg);
                    }
                    if (targets.empty())
                        throw std::runtime_error("Launched CoreHost has not appeared; shutdown "
                                                 "cannot yet be confirmed.");
                }
                for (const auto target : targets) {
                    try {
                        nd::platform::force_stop_process(fsPath(executable), target, roleArg);
                    } catch (const nd::Error& stopError) {
                        if (stopError.code != "PROCESS_PERMISSION")
                            throw;
                        // The helper verifies its own executable and the process birth
                        // token again after elevation. No name-based taskkill is used.
                        int code = 1;
                        QString error;
                        if (!runNativeDnsHelper(executable,
                                                {"--force-shutdown",
                                                 QString::number(target.pid),
                                                 QString::number(target.started)},
                                                true,
                                                &code,
                                                &error,
                                                30000))
                            throw std::runtime_error(std::string(stopError.what()) + "\n" +
                                                     error.toStdString());
                        if (code)
                            throw std::runtime_error(
                                "CoreHost force-shutdown helper failed: exit=" +
                                std::to_string(code));
                    }
                }
                nd::platform::ProcessInstanceLock probe(nd::core_instance_name,
                                                        nd::platform::InstanceScope::machine);
                if (!probe.acquired() ||
                    !nd::platform::matching_processes(fsPath(executable), roleArg).empty())
                    throw std::runtime_error(
                        "CoreHost is still running; process-instance lock is held.");
            }
        } catch (const nd::Error& error) {
            failure = q(error.code + ": " + error.what());
        } catch (const std::exception& error) {
            failure = q(error.what());
        }
        // Arm the GUI deadline from this independent worker even if the GUI
        // event thread cannot consume the completion callback or finish Qt cleanup.
        if (failure.isEmpty())
            *exitConfirmed = true;
        QMetaObject::invokeMethod(
            qApp,
            [self, failure] {
                if (!self)
                    return;
                if (!failure.isEmpty()) {
                    self->exiting_ = false;
                    self->statusTimer_.start();
                    self->logTimer_.start();
                    self->showAndActivate();
                    self->appendLocalLog(failure, true);
                    showCriticalAlert(self,
                                      "NativeDNS",
                                      uiText("CoreHost could not be terminated.") + "\n\n" +
                                          failure);
                    return;
                }
                self->coreShutdownAttempted_ = true;
                self->hide();
                if (self->tray_)
                    self->tray_->hide();
                QCoreApplication::quit();
            },
            Qt::QueuedConnection);
    });
}

void NativeDnsWindow::refreshStatus() {
    if (statusRefreshPending_.exchange(true)) {
        statusRefreshQueued_ = true;
        return;
    }
    const uint64_t pollGeneration = statusPollGeneration_;
    const auto reachability = currentReachability();
    QPointer<NativeDnsWindow> self(this);
    QThreadPool::globalInstance()->start([self, reachability, pollGeneration] {
        const auto network = probeNetwork(reachability);
        QString status, diagnostics;
        bool failed = false, processAlive = false;
        try {
            const auto response = readCoreStatus();
            if (response.status)
                throw std::runtime_error(response.payload);
            status = q(response.payload);
        } catch (const std::exception& error) {
            failed = true;
            const auto* coreError = dynamic_cast<const nd::Error*>(&error);
            diagnostics = QDateTime::currentDateTime().toString(Qt::ISODateWithMs) + "\n" +
                          q(nd::core_pipe_name) + "\n" +
                          (coreError ? q(coreError->code) + ": " : QString{}) + q(error.what());
            try {
                nd::platform::ProcessInstanceLock probe(nd::core_instance_name,
                                                        nd::platform::InstanceScope::machine);
                processAlive = !probe.acquired();
            } catch (...) {
                processAlive = true; // Do not launch if process absence cannot be established.
            }
            diagnostics += "\n" + uiText("CoreHost process lock:") + " " +
                           (processAlive ? uiText("Held") : uiText("Released"));
            try {
                const auto response =
                    nd::pipe_request(nd::core_shutdown_pipe_name, nd::IpcOperation::ping, {}, 1000);
                diagnostics += "\n" + q(nd::core_shutdown_pipe_name) + ": " +
                               (response.status ? q(response.payload) : "OK");
            } catch (const std::exception& shutdownError) {
                diagnostics +=
                    "\n" + q(nd::core_shutdown_pipe_name) + ": " + q(shutdownError.what());
            }
            try {
                const auto corePath = coreHostExecutable();
                const std::string roleArg =
                    QFileInfo(corePath).fileName().compare("NativeDNS.exe", Qt::CaseInsensitive) == 0
                        ? "--core-host"
                        : "";
                diagnostics += "\n" + corePath;
                for (const auto process :
                     nd::platform::matching_processes(fsPath(corePath), roleArg))
                    diagnostics +=
                        QString("\nPID=%1; birth=%2").arg(process.pid).arg(process.started);
            } catch (const std::exception& processError) {
                diagnostics += "\n" + q(processError.what());
            }
        }
        QMetaObject::invokeMethod(
            qApp,
            [self,
             network = std::move(network),
             status = std::move(status),
             diagnostics = std::move(diagnostics),
             failed,
             processAlive,
             pollGeneration] {
                if (!self)
                    return;
                self->statusRefreshPending_ = false;
                const bool queued = self->statusRefreshQueued_;
                self->statusRefreshQueued_ = false;
                if (self->exiting_)
                    return;
                if (pollGeneration != self->statusPollGeneration_) {
                    if (queued)
                        self->refreshStatus();
                    return;
                }
                if (queued)
                    QTimer::singleShot(0, self, [self] {
                        if (self && !self->exiting_)
                            self->refreshStatus();
                    });
                if (failed) {
                    self->coreHealthyTimer_.invalidate();
                    if (!self->coreFailureTimer_.isValid())
                        self->coreFailureTimer_.start();
                }
                const bool available = network.available;
                const bool networkReturned = available && !self->networkAvailable_;
                const auto& signature = network.signature;
                const bool networkChanged = signature != self->networkSignature_;
                self->networkAvailable_ = available;
                self->networkSignature_ = signature;
                if (!available && !self->networkErrorLogged_) {
                    self->appendLocalLog(
                        uiText("Internet connection lost. DNS resolution may fail; core "
                               "continues running offline."),
                        true);
                    self->networkErrorLogged_ = true;
                } else if (networkReturned) {
                    self->networkErrorLogged_ = false;
                    self->appendLocalLog(uiText("Internet connection restored."));
                }
                if (!failed) {
                    self->coreLaunchState_->issued = false;
                    self->failedCorePolls_ = 0;
                    self->coreFailureTimer_.invalidate();
                    self->lastCoreStatus_ = status;
                    self->lastCoreContact_ =
                        QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
                    if (status.startsWith("ERROR")) {
                        self->showCoreControlFailure(status);
                    }
                    if (status.startsWith("RUNNING")) {
                        if (!self->coreHealthyTimer_.isValid())
                            self->coreHealthyTimer_.start();
                        if (self->coreHealthyTimer_.elapsed() >= 30000) {
                            self->automaticRestarts_ = 0;
                            if (!self->coreControlDialog_)
                                self->coreControlErrorLogged_ = false;
                        }
                    } else {
                        self->coreHealthyTimer_.invalidate();
                    }
                    self->coreLaunchPending_ = false;
                    self->restartWhenNetworkReturns_ = false;
                    const bool degraded = status.contains("verification=DEGRADED");
                    const bool isError = status.startsWith("ERROR");
                    QStringList tips;
                    if (degraded) {
                        tips << uiText("Interception degraded: transparent DNS capture or packet delivery reported errors.\nWhat to do: open Diagnostics -> Interception Diagnostics and click \"Run safe interception test\", check for conflicting VPN/firewall software, or click Restart.");
                    }
                    if (!available) {
                        tips << uiText("Offline: no active external network connection was detected.\nWhat to do: check your network adapter, Wi-Fi/Ethernet, or VPN connection. CoreHost remains running and will resume DNS resolution automatically when connectivity returns.");
                    }
                    if (isError) {
                        tips << uiText("Core error: DNS interception backend reported an error.\nWhat to do: open Diagnostics -> Interception Diagnostics for details or click Restart.");
                    }
                    self->setStatusText(friendlyCoreStatus(status) +
                                            (degraded ? " | " + uiText("Interception degraded")
                                                      : QString{}) +
                                            (available ? QString{} : " | " + uiText("Offline")),
                                        isError || degraded || !available,
                                        tips.join("\n\n"));
                } else if (self->coreStartOperationPending_) {
                    if (!self->restartWhenNetworkReturns_)
                        self->setStatusText(uiText("Core: starting..."));
                } else if (processAlive && !self->coreLaunchPending_) {
                    self->coreHealthyTimer_.invalidate();
                    self->setStatusText(uiText("Core: control unavailable"), true);
                    if (++self->failedCorePolls_ >= 3 &&
                        self->coreFailureTimer_.elapsed() >= 10000)
                        self->showCoreControlFailure(diagnostics);
                } else if (self->coreLaunchPending_ && self->coreLaunchTimer_.isValid() &&
                           self->coreLaunchTimer_.elapsed() < 15000) {
                    self->setStatusText(uiText("Core: starting..."));
                } else {
                    self->coreHealthyTimer_.invalidate();
                    if (!processAlive)
                        self->coreLaunchState_->issued = false;
                    if (self->coreLaunchPending_)
                        self->appendLocalLog(
                            uiText("Core startup timed out. Check network and DNS configuration."),
                            true);
                    self->coreLaunchPending_ = false;
                    self->setStatusText(self->restartWhenNetworkReturns_
                                            ? uiText("Core: waiting for network")
                                            : uiText("Core: stopped"),
                                        true);
                    ++self->failedCorePolls_;
                    if (self->failedCorePolls_ >= 3)
                        self->showCoreControlFailure(diagnostics);
                    const bool retryDue =
                        self->failedCorePolls_ >= 3 && (!self->networkProbeTimer_.isValid() ||
                                                        self->networkProbeTimer_.elapsed() >= 5000);
                    if (!self->exiting_ && self->automaticRestarts_ < 3 &&
                        (retryDue || networkChanged)) {
                        ++self->automaticRestarts_;
                        self->startCore(true, false);
                    }
                }
            },
            Qt::QueuedConnection);
    });
}

void NativeDnsWindow::refreshLogs() {
    if (logRefreshPending_.exchange(true))
        return;
    const auto request = std::to_string(logSequence_) + "\t0\t" +
                         std::to_string(diagnosticLogging_ ? 3u : static_cast<unsigned>(config_.logging.screen));
    QPointer<NativeDnsWindow> self(this);
    QThreadPool::globalInstance()->start([self, request] {
        QString payload;
        try {
            auto response = nd::pipe_request(
                nd::core_log_pipe_name, nd::IpcOperation::logs, request + "\tstructured",
                corePollTimeoutMs);
            if (response.status)
                response =
                    nd::pipe_request(nd::core_log_pipe_name, nd::IpcOperation::logs, request,
                                     corePollTimeoutMs);
            if (!response.status)
                payload = q(response.payload);
        } catch (...) {
        }
        QMetaObject::invokeMethod(
            qApp,
            [self, payload = std::move(payload)] {
                if (!self)
                    return;
                self->logRefreshPending_ = false;
                self->appendLogLines(payload);
            },
            Qt::QueuedConnection);
    });
}
void NativeDnsWindow::appendLogLines(const QString& payload) {
    const auto records = decodeLogRecords(payload);
    for (const auto& record : records)
        logSequence_ = std::max(logSequence_, static_cast<uint64_t>(record.sequence));
    log_->appendRecords(records);
}
bool NativeDnsWindow::eventFilter(QObject* watched, QEvent* event) {
    if (watched == coreStatus_ && !coreStatus_->toolTip().isEmpty()) {
        if (event->type() == QEvent::Enter) {
            QToolTip::showText(QCursor::pos(), coreStatus_->toolTip(), coreStatus_);
        } else if (event->type() == QEvent::Leave) {
            QToolTip::hideText();
        } else if (event->type() == QEvent::ToolTip) {
            auto* help = static_cast<QHelpEvent*>(event);
            QToolTip::showText(help->globalPos(), coreStatus_->toolTip(), coreStatus_);
            return true;
        }
    }
    return QMainWindow::eventFilter(watched, event);
}
void NativeDnsWindow::setStatusText(const QString& text, bool error, const QString& tooltip) {
    coreStatus_->setText(text);
    coreStatus_->setToolTip(tooltip);
    const QColor errorColor = darkTheme_ ? QColor(255, 105, 105) : QColor(190, 0, 0);
    auto colors = coreStatus_->palette();
    colors.setColor(QPalette::WindowText,
                    error ? errorColor : palette().color(QPalette::Text));
    coreStatus_->setPalette(colors);
    coreStatus_->setStyleSheet(error ? QString("color: %1;").arg(errorColor.name())
                                     : QString{});
}
void NativeDnsWindow::appendLocalLog(const QString& message, bool error) {
    LogRecord record;
    record.timestamp = QDateTime::currentDateTime();
    record.message = message;
    record.error = error;
    log_->appendRecords({record});
}

void NativeDnsWindow::closeEvent(QCloseEvent* event) {
    if (exiting_) {
        // Exit can still be waiting for elevated OS termination in a worker.
        // Keep the GUI alive until CoreHost termination has been confirmed.
        event->ignore();
        return;
    }

    const bool trayNow = tray_ && QSystemTrayIcon::isSystemTrayAvailable();
    if (trayNow != trayAvailable_) {
        trayAvailable_ = trayNow;
        if (trayAvailable_) {
            tray_->show();
            hideToTrayAction_->setEnabled(true);
            hideToTrayAction_->setToolTip(QString());
        } else {
            tray_->hide();
            hideToTray_ = false;
            QSignalBlocker blocker(hideToTrayAction_);
            hideToTrayAction_->setChecked(false);
            hideToTrayAction_->setEnabled(false);
            hideToTrayAction_->setToolTip("The desktop system tray is not available.");
        }
    }

    if (hideToTray_ && trayAvailable_) {
        hide();
        event->ignore();
        return;
    }

    // Keep the window alive when CoreHost shutdown cannot be confirmed.
    event->ignore();
    exitApplication();
}
