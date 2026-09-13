#include "qt_app.hpp"
#include "platform_launcher.hpp"
#include "ui_preferences.hpp"
#include <nativedns/autostart.hpp>
#include <nativedns/dns.hpp>
#include <nativedns/ipc.hpp>
#include <nativedns/platform.hpp>
#include <QApplication>
#include <QAbstractTableModel>
#include <QAbstractItemView>
#include <QAction>
#include <QActionGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDesktopServices>
#include <QDateTime>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QIcon>
#include <QInputDialog>
#include <QLineEdit>
#include <QMenuBar>
#include <QMenu>
#include <QMessageBox>
#include <QPaintEvent>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStandardPaths>
#include <QStatusBar>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QTableWidget>
#include <QToolBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPointer>
#include <QMetaObject>
#include <QBrush>
#include <QColor>
#include <QFileInfo>
#include <QFrame>
#include <QSignalBlocker>
#include <QSettings>
#include <QScrollBar>
#include <QStyle>
#include <QStyleOptionComboBox>
#include <QThread>
#include <QThreadPool>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QTextDocument>
#include <QUrl>
#include <thread>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <unordered_map>

namespace {
constexpr auto repositoryUrl="https://github.com/zmorok/NativeDNS";
constexpr int ruleIdRole=Qt::UserRole+1;

QString q(const std::string& value){return QString::fromUtf8(value.c_str(),static_cast<int>(value.size()));}
std::string s(const QString& value){const auto bytes=value.toUtf8();return std::string(bytes.constData(),static_cast<size_t>(bytes.size()));}
std::filesystem::path fsPath(const QString& value){
#ifdef _WIN32
    return std::filesystem::path(value.toStdWString());
#else
    return std::filesystem::path(s(value));
#endif
}
QString qPath(const std::filesystem::path& value){
#ifdef _WIN32
    return QString::fromStdWString(value.wstring());
#else
    return q(value.string());
#endif
}
QString protocolText(nd::Protocol p){
    switch(p){
        case nd::Protocol::udp:return "UDP";
        case nd::Protocol::tcp:return "TCP";
        case nd::Protocol::doh:return "DoH";
        case nd::Protocol::dot:return "DoT";
        case nd::Protocol::doh3:return "DoH3";
        case nd::Protocol::doq:return "DoQ";
        case nd::Protocol::dnscrypt:return "DNSCrypt";
        case nd::Protocol::anonymized_dnscrypt:return uiText("Anonymized DNSCrypt");
    }
    return {};
}
nd::Protocol protocolFrom(int index){static const nd::Protocol values[]{nd::Protocol::udp,nd::Protocol::tcp,nd::Protocol::doh,nd::Protocol::dot,nd::Protocol::doh3,nd::Protocol::doq,nd::Protocol::dnscrypt,nd::Protocol::anonymized_dnscrypt};return values[std::clamp(index,0,7)];}
int protocolIndex(nd::Protocol p){for(int i=0;i<8;++i)if(protocolFrom(i)==p)return i;return 0;}
QString joinPatterns(const std::vector<std::string>& patterns){QStringList list;for(const auto& p:patterns)list<<q(p);return list.join(";\n");}
QString previewPatterns(const std::vector<std::string>& patterns){QStringList list;for(const auto& p:patterns)list<<q(p);return list.join("; ");}
uint32_t nextServerId(const nd::Config& c){uint32_t id=0;for(const auto& v:c.servers)id=std::max(id,v.id);return id+1;}
uint32_t nextRuleId(const nd::Config& c){uint32_t id=0;for(const auto& v:c.rules)id=std::max(id,v.id);return id+1;}

class AnchoredComboBox final:public QComboBox{
public:
    using QComboBox::QComboBox;
    void openPopup(){showPopup();}
protected:
    void showPopup() override{
        const bool dark=palette().color(QPalette::Window).lightness()<128;
        view()->setStyleSheet(dark?
            "QAbstractItemView { background-color: #252526; color: #f0f0f0; selection-background-color: #35495c; selection-color: #f0f0f0; outline: 0; }"
            "QAbstractItemView::item:hover, QAbstractItemView::item:selected { background-color: #35495c; color: #f0f0f0; }"
          : "QAbstractItemView { background-color: #ffffff; color: #202020; selection-background-color: #d7ebf9; selection-color: #202020; outline: 0; }"
            "QAbstractItemView::item:hover, QAbstractItemView::item:selected { background-color: #d7ebf9; color: #202020; }");
        QComboBox::showPopup();
        QPointer<QWidget> popup=view()->window();
        QTimer::singleShot(0,this,[this,popup]{
            if(!popup)return;
            popup->setMinimumWidth(width());
            popup->move(mapToGlobal(QPoint(0,height())));
        });
    }
};

struct ComboOption {
    QString text;
    uint32_t value;
};

class LazyComboDelegate final:public QStyledItemDelegate{
public:
    using Options=std::function<std::vector<ComboOption>()>;
    using Changed=std::function<void(const QModelIndex&,uint32_t)>;

    LazyComboDelegate(Options options,Changed changed,QObject* parent)
        :QStyledItemDelegate(parent),options_(std::move(options)),changed_(std::move(changed)){}

    QWidget* createEditor(QWidget* parent,const QStyleOptionViewItem&,const QModelIndex&) const override{
        auto* editor=new AnchoredComboBox(parent);
        for(const auto& option:options_())editor->addItem(option.text,option.value);
        connect(editor,qOverload<int>(&QComboBox::activated),editor,[this,editor]{
            auto* self=const_cast<LazyComboDelegate*>(this);
            emit self->commitData(editor);
            emit self->closeEditor(editor);
        });
        return editor;
    }

    void paint(QPainter* painter,const QStyleOptionViewItem& option,const QModelIndex& index) const override{
        QStyleOptionComboBox combo;
        combo.rect=option.rect;
        combo.state=option.state;
        combo.direction=option.direction;
        combo.fontMetrics=option.fontMetrics;
        combo.palette=option.palette;
        combo.currentText=index.data(Qt::DisplayRole).toString();
        combo.frame=true;
        auto* style=option.widget?option.widget->style():QApplication::style();
        style->drawComplexControl(QStyle::CC_ComboBox,&combo,painter,option.widget);
        style->drawControl(QStyle::CE_ComboBoxLabel,&combo,painter,option.widget);
    }

    void setEditorData(QWidget* editor,const QModelIndex& index) const override{
        auto* combo=static_cast<AnchoredComboBox*>(editor);
        const int selected=combo->findData(index.data(Qt::UserRole));
        combo->setCurrentIndex(selected>=0?selected:0);
        QTimer::singleShot(0,combo,[combo]{combo->openPopup();});
    }

    void setModelData(QWidget* editor,QAbstractItemModel* model,const QModelIndex& index) const override{
        (void)model;
        const auto* combo=static_cast<QComboBox*>(editor);
        const auto value=combo->currentData().toUInt();
        if(value==index.data(Qt::UserRole).toUInt())return;
        changed_(index,value);
    }

private:
    Options options_;
    Changed changed_;
};

void positionDialog(QDialog& dialog,QWidget* parent){
    if(!parent)return;
    const auto center=parent->window()->frameGeometry().center();
    dialog.move(center-QPoint(dialog.width()/2,dialog.height()/2));
}

void translateDialogButtons(QDialogButtonBox* buttons){
    if(auto* ok=buttons->button(QDialogButtonBox::Ok))ok->setText(uiText("OK"));
    if(auto* cancel=buttons->button(QDialogButtonBox::Cancel))cancel->setText(uiText("Cancel"));
}

void configureFixedTableRows(QTableView* table){
    const int height=table->fontMetrics().height()+8;
    table->setWordWrap(false);
    table->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table->verticalHeader()->setMinimumSectionSize(height);
    table->verticalHeader()->setDefaultSectionSize(height);
}

void setFormFieldEnabled(QFormLayout* form,QWidget* field,bool enabled){
    field->setEnabled(enabled);
    if(auto* label=form->labelForField(field))label->setEnabled(enabled);
}

void showAboutDialog(QWidget* parent){
    QDialog dialog(parent);
    dialog.setWindowTitle(uiText("About"));
    dialog.setWindowIcon(QApplication::windowIcon());
    dialog.setModal(true);

    auto* icon=new QLabel(&dialog);
    icon->setPixmap(QApplication::windowIcon().pixmap(64,64));
    icon->setAlignment(Qt::AlignTop|Qt::AlignHCenter);

    auto* description=new QLabel("<b>NativeDNS</b><br>"+uiText("Cross-platform DNS client")+"<br>Qt 6 + native C++ Core",&dialog);
    description->setTextFormat(Qt::RichText);

    auto* summary=new QHBoxLayout;
    summary->addWidget(icon);
    summary->addSpacing(10);
    summary->addWidget(description,1);

    auto* separator=new QFrame(&dialog);
    separator->setFrameShape(QFrame::HLine);
    separator->setFrameShadow(QFrame::Sunken);

    const auto version=QCoreApplication::applicationVersion().toHtmlEscaped();
    auto* details=new QLabel(uiText("Version")+" "+version+" &nbsp;&nbsp; <a href=\""+QString(repositoryUrl)+"\">"+uiText("GitHub repository")+"</a>",&dialog);
    details->setTextFormat(Qt::RichText);
    details->setTextInteractionFlags(Qt::TextBrowserInteraction);
    details->setOpenExternalLinks(true);

    auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok,&dialog);
    translateDialogButtons(buttons);
    QObject::connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept);

    auto* root=new QVBoxLayout(&dialog);
    root->addLayout(summary);
    root->addWidget(separator);
    root->addWidget(details);
    root->addWidget(buttons);
    dialog.setFixedSize(dialog.sizeHint());
    positionDialog(dialog,parent);
    dialog.exec();
}

QString friendlyCoreStatus(const QString& raw){
    const auto parts=raw.split(' ',Qt::SkipEmptyParts);
    if(parts.isEmpty())return uiText("Core: Unknown");
    auto value=[&](const QString& key){for(const auto& part:parts)if(part.startsWith(key+'='))return part.mid(key.size()+1);return QString{};};
    const auto state=parts.front();
    if(state=="ERROR"){
        const auto marker=raw.indexOf(" error=");
        return marker>=0?uiText("Core: Error")+" | "+raw.mid(marker+7):uiText("Core: Error");
    }
    QString stateText=state.toLower();if(!stateText.isEmpty())stateText[0]=stateText[0].toUpper();
    if(state!="RUNNING")return uiText(("Core: "+stateText).toUtf8().constData());
    const QString mode=value("transparent")=="1"?uiText("Transparent"):uiText("Local proxy");
    const QString udp=value("udp")=="1"?uiText("Active"):uiText("Inactive");
    const QString tcp=value("tcp")=="1"?uiText("Active"):uiText("Inactive");
    return uiText("Core: Running")+" | "+uiText("Mode")+": "+mode+" | "+uiText("DNS port")+": "+value("port")+" | UDP: "+udp+" | TCP: "+tcp;
}

bool editServer(QWidget* parent,nd::Server& server){
    QDialog dialog(parent);dialog.setWindowTitle(server.id?uiText("DNS Server"):uiText("Add DNS Server"));dialog.resize(520,460);
    auto* form=new QFormLayout;
    QLineEdit name(q(server.name)),ip(q(server.ip)),host(q(server.hostname)),url(q(server.url)),port(server.port?QString::number(server.port):QString()),fallbacks,bootstrap,publicKey(q(server.public_key)),provider(q(server.provider_name)),relay(q(server.relay));
    AnchoredComboBox protocol;for(int i=0;i<8;++i)protocol.addItem(protocolText(protocolFrom(i)));protocol.setCurrentIndex(protocolIndex(server.protocol));
    QCheckBox enabled(uiText("Enabled")),dnssec(uiText("DNSSEC supported")),directCertificateFallback(uiText("Allow direct certificate fallback"));enabled.setChecked(server.enabled);dnssec.setChecked(server.dnssec_supported);directCertificateFallback.setChecked(server.allow_direct_certificate_fallback);
    bootstrap.setText([&]{QStringList x;for(const auto& v:server.bootstrap)x<<q(v);return x.join(';');}());
    fallbacks.setText([&]{QStringList x;for(const auto id:server.fallback_ids)x<<QString::number(id);return x.join(';');}());
    form->addRow(uiText("Name:"),&name);form->addRow(uiText("Protocol:"),&protocol);form->addRow(uiText("IP:"),&ip);form->addRow(uiText("Port:"),&port);form->addRow(uiText("Hostname:"),&host);form->addRow(uiText("URL:"),&url);form->addRow(uiText("Fallback server IDs:"),&fallbacks);form->addRow(uiText("Bootstrap:"),&bootstrap);form->addRow(uiText("Public key:"),&publicKey);form->addRow(uiText("Provider:"),&provider);form->addRow(uiText("Relay:"),&relay);form->addRow(&directCertificateFallback);form->addRow(&enabled);form->addRow(&dnssec);
    auto update=[&]{const auto p=protocolFrom(protocol.currentIndex());const bool plain=p==nd::Protocol::udp||p==nd::Protocol::tcp;const bool doh=p==nd::Protocol::doh||p==nd::Protocol::doh3;const bool dot=p==nd::Protocol::dot||p==nd::Protocol::doq;const bool crypt=p==nd::Protocol::dnscrypt||p==nd::Protocol::anonymized_dnscrypt;setFormFieldEnabled(form,&ip,plain||crypt||dot||doh);setFormFieldEnabled(form,&url,doh);setFormFieldEnabled(form,&host,dot||doh);setFormFieldEnabled(form,&publicKey,crypt);setFormFieldEnabled(form,&provider,crypt);setFormFieldEnabled(form,&relay,p==nd::Protocol::anonymized_dnscrypt);directCertificateFallback.setEnabled(p==nd::Protocol::anonymized_dnscrypt);};
    QObject::connect(&protocol,&QComboBox::currentIndexChanged,&dialog,[&]{update();});update();
    auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel);translateDialogButtons(buttons);QObject::connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept);QObject::connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
    auto* root=new QVBoxLayout(&dialog);root->addLayout(form);root->addWidget(buttons);
    positionDialog(dialog,parent);
    if(dialog.exec()!=QDialog::Accepted)return false;
    server.name=s(name.text().trimmed());server.protocol=protocolFrom(protocol.currentIndex());server.ip=s(ip.text().trimmed());server.hostname=s(host.text().trimmed());server.url=s(url.text().trimmed());server.port=static_cast<uint16_t>(port.text().toUInt());server.enabled=enabled.isChecked();server.dnssec_supported=dnssec.isChecked();server.allow_direct_certificate_fallback=directCertificateFallback.isChecked();server.public_key=s(publicKey.text().trimmed());server.provider_name=s(provider.text().trimmed());server.relay=s(relay.text().trimmed());server.fallback_ids.clear();for(const auto& part:fallbacks.text().split(';',Qt::SkipEmptyParts))server.fallback_ids.push_back(part.trimmed().toUInt());server.bootstrap.clear();for(const auto& part:bootstrap.text().split(';',Qt::SkipEmptyParts))server.bootstrap.push_back(s(part.trimmed()));
    return true;
}

class ServerDialog final:public QDialog{
public:
    ServerDialog(QWidget* parent,nd::Config& config,std::function<bool()> changed)
        :QDialog(parent),target_(config),original_(config),working_(config),changed_(std::move(changed)){
        setWindowTitle(uiText("DNS Servers"));
        resize(860,460);
        table_=new QTableWidget(this);
        table_->setColumnCount(5);
        table_->setHorizontalHeaderLabels({uiText("Name"),uiText("Protocol"),uiText("Address"),uiText("Status"),"RTT"});
        table_->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Stretch);
        table_->horizontalHeader()->setSectionResizeMode(2,QHeaderView::Stretch);
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        configureFixedTableRows(table_);

        auto* add=new QPushButton(uiText("Add..."));
        auto* edit=new QPushButton(uiText("Edit..."));
        auto* remove=new QPushButton(uiText("Remove"));
        auto* check=new QPushButton(uiText("Check"));
        auto* ok=new QPushButton(uiText("OK"));
        auto* close=new QPushButton(uiText("Close"));
        auto* side=new QVBoxLayout;
        side->addWidget(add);side->addWidget(edit);side->addWidget(remove);
        side->addSpacing(add->sizeHint().height());
        side->addWidget(check);side->addStretch();
        auto* content=new QHBoxLayout;
        content->addWidget(table_,1);content->addLayout(side);
        auto* bottom=new QHBoxLayout;
        bottom->addWidget(ok);bottom->addStretch();bottom->addWidget(close);
        auto* root=new QVBoxLayout(this);
        root->addLayout(content,1);root->addLayout(bottom);

        connect(add,&QPushButton::clicked,this,[this]{
            nd::Server server;server.id=nextServerId(working_);server.name=s(uiText("New DNS Server"));
            if(!editServer(this,server))return;
            try{nd::ConfigEditor editor(working_);editor.add_server(server);working_=editor.get();reload(server.id);}
            catch(const std::exception& e){QMessageBox::critical(this,"NativeDNS",e.what());}
        });
        connect(edit,&QPushButton::clicked,this,[this]{
            const int row=table_->currentRow();if(row<0)return;
            auto server=working_.servers[static_cast<size_t>(row)];
            if(!editServer(this,server))return;
            try{nd::ConfigEditor editor(working_);editor.update_server(server);working_=editor.get();reload(server.id);}
            catch(const std::exception& e){QMessageBox::critical(this,"NativeDNS",e.what());}
        });
        connect(remove,&QPushButton::clicked,this,[this]{
            const int row=table_->currentRow();if(row<0)return;
            if(QMessageBox::question(this,"NativeDNS",uiText("Remove selected DNS server?"))!=QMessageBox::Yes)return;
            try{nd::ConfigEditor editor(working_);editor.remove_server(working_.servers[static_cast<size_t>(row)].id);working_=editor.get();reload();}
            catch(const std::exception& e){QMessageBox::critical(this,"NativeDNS",e.what());}
        });
        connect(check,&QPushButton::clicked,this,[this]{checkSelected();});
        connect(ok,&QPushButton::clicked,this,[this]{commit();});
        connect(close,&QPushButton::clicked,this,&QDialog::reject);
        connect(table_,&QTableWidget::cellDoubleClicked,this,[edit](int,int){edit->click();});
        reload();
    }
private:
    static std::string address(const nd::Server& server){
        return !server.url.empty()?server.url:(!server.hostname.empty()?server.hostname:server.ip+(server.port?":"+std::to_string(server.port):""));
    }
    static void bold(QTableWidgetItem* item,bool enabled){auto font=item->font();font.setBold(enabled);item->setFont(font);}
    const nd::Server* original(uint32_t id) const{
        const auto found=std::find_if(original_.servers.begin(),original_.servers.end(),[id](const nd::Server& server){return server.id==id;});
        return found==original_.servers.end()?nullptr:&*found;
    }
    void commit(){
        if(working_==original_){accept();return;}
        const auto previous=target_;
        target_=working_;
        if(changed_()){original_=working_;accept();}
        else target_=previous;
    }
    void reload(uint32_t selectedId=0){
        table_->setUpdatesEnabled(false);table_->clearContents();table_->setRowCount(static_cast<int>(working_.servers.size()));
        int selectedRow=-1;
        for(int row=0;row<table_->rowCount();++row){
            const auto& server=working_.servers[static_cast<size_t>(row)];
            if(server.id==selectedId)selectedRow=row;
            auto* name=new QTableWidgetItem(q(server.name));
            auto* protocol=new QTableWidgetItem(protocolText(server.protocol));
            auto* serverAddress=new QTableWidgetItem(q(address(server)));
            auto* status=new QTableWidgetItem(uiText("Not tested"));
            auto* rtt=new QTableWidgetItem("—");
            const auto* before=original(server.id);
            const bool added=!before;
            bold(name,added||before->name!=server.name||before->enabled!=server.enabled||before->dnssec_supported!=server.dnssec_supported);
            bold(protocol,added||before->protocol!=server.protocol);
            bold(serverAddress,added||address(*before)!=address(server)||before->bootstrap!=server.bootstrap||before->public_key!=server.public_key||before->provider_name!=server.provider_name||before->relay!=server.relay);
            table_->setItem(row,0,name);table_->setItem(row,1,protocol);table_->setItem(row,2,serverAddress);table_->setItem(row,3,status);table_->setItem(row,4,rtt);
        }
        if(selectedRow>=0)table_->selectRow(selectedRow);
        table_->setUpdatesEnabled(true);table_->viewport()->update();
    }
    void colorRow(int row,const QColor& background,const QColor& foreground){for(int column=0;column<table_->columnCount();++column)if(auto* item=table_->item(row,column)){item->setBackground(QBrush(background));item->setForeground(QBrush(foreground));}}
    static nd::TestResult testServer(nd::Server server){
        if((server.protocol==nd::Protocol::doh||server.protocol==nd::Protocol::dot)&&server.ip.empty()&&server.bootstrap.empty()){
            try{auto config=nd::default_config();config.servers.push_back(server);nd::prepare_secure_endpoints(config);server=std::move(config.servers.back());}
            catch(const nd::Error& error){nd::TestResult result;result.protocol=server.protocol;result.server_id=server.id;result.error_code=error.code;result.message=error.what();return result;}
            catch(const std::exception& error){nd::TestResult result;result.protocol=server.protocol;result.server_id=server.id;result.error_code="INTERNAL";result.message=error.what();return result;}
        }
        return nd::test_server(server);
    }
    void checkSelected(){auto rows=table_->selectionModel()->selectedRows();if(rows.isEmpty()&&table_->currentRow()>=0)rows<<table_->model()->index(table_->currentRow(),0);for(const auto& index:rows){const int row=index.row();if(row<0||row>=static_cast<int>(working_.servers.size()))continue;auto server=working_.servers[static_cast<size_t>(row)];table_->item(row,3)->setText(uiText("Testing..."));table_->item(row,4)->setText("—");colorRow(row,palette().color(QPalette::Base),palette().color(QPalette::Text));QPointer<ServerDialog> self(this);std::thread([self,server]{auto result=testServer(server);QMetaObject::invokeMethod(qApp,[self,serverId=server.id,result]{if(!self)return;const auto found=std::find_if(self->working_.servers.begin(),self->working_.servers.end(),[&](const nd::Server& value){return value.id==serverId;});if(found==self->working_.servers.end())return;const int row=static_cast<int>(std::distance(self->working_.servers.begin(),found));auto* status=self->table_->item(row,3);auto* rtt=self->table_->item(row,4);if(!status||!rtt)return;status->setText(result.success?"OK":q(result.error_code+": "+result.message));rtt->setText(result.success?QString::number(result.rtt_ms,'f',1)+" ms":"—");self->colorRow(row,result.success?QColor(220,245,224):QColor(255,224,224),result.success?QColor(20,105,35):QColor(150,0,0));},Qt::QueuedConnection);}).detach();}}
    nd::Config& target_;
    nd::Config original_;
    nd::Config working_;
    std::function<bool()> changed_;
    QTableWidget* table_=nullptr;
};

bool editRule(QWidget* parent,nd::Config& config,nd::Rule& rule){
    QDialog dialog(parent);
    dialog.setWindowTitle(rule.is_default?uiText("Default Rule"):uiText("DNS Rule"));
    dialog.resize(560,420);
    auto* form=new QFormLayout;
    QLineEdit name(q(rule.name));
    QPlainTextEdit hosts;
    hosts.setPlainText(joinPatterns(rule.patterns));
    hosts.setMinimumHeight(150);
    AnchoredComboBox action;
    action.addItems({uiText("process"),uiText("bypass"),uiText("block")});
    action.setCurrentIndex(rule.action==nd::Action::process?0:rule.action==nd::Action::bypass?1:2);
    AnchoredComboBox server;
    server.addItem(uiText("Original/System"),0);
    for(const auto& value:config.servers)server.addItem(q(value.name),value.id);
    const int found=server.findData(rule.server_id);
    if(found>=0)server.setCurrentIndex(found);
    QCheckBox enabled(uiText("Enabled"));
    enabled.setChecked(rule.enabled);
    AnchoredComboBox block;
    block.addItems({"0.0.0.0 / ::","NXDOMAIN","REFUSED",uiText("Silent drop")});
    block.setCurrentIndex(static_cast<int>(rule.block_mode));
    form->addRow(uiText("Name:"),&name);
    form->addRow(uiText("Hostnames:"),&hosts);
    form->addRow(uiText("Action:"),&action);
    form->addRow(uiText("DNS Server:"),&server);
    form->addRow(uiText("Block mode:"),&block);
    form->addRow(&enabled);
    auto update=[&]{
        setFormFieldEnabled(form,&server,action.currentIndex()==0);
        setFormFieldEnabled(form,&block,action.currentIndex()==2);
        setFormFieldEnabled(form,&name,!rule.is_default);
        setFormFieldEnabled(form,&hosts,!rule.is_default);
        enabled.setEnabled(!rule.is_default);
    };
    QObject::connect(&action,&QComboBox::currentIndexChanged,&dialog,[&]{update();});
    update();
    auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel);
    translateDialogButtons(buttons);
    QObject::connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept);
    QObject::connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
    auto* root=new QVBoxLayout(&dialog);
    root->addLayout(form);
    root->addWidget(buttons);
    positionDialog(dialog,parent);
    if(dialog.exec()!=QDialog::Accepted)return false;
    rule.name=s(name.text().trimmed());
    rule.patterns=nd::split_patterns(s(hosts.toPlainText()));
    rule.enabled=enabled.isChecked();
    rule.action=action.currentIndex()==0?nd::Action::process:action.currentIndex()==1?nd::Action::bypass:nd::Action::block;
    rule.server_id=rule.action==nd::Action::process?server.currentData().toUInt():0;
    rule.block_mode=static_cast<nd::BlockMode>(block.currentIndex());
    return true;
}

class RulesTableModel final:public QAbstractTableModel{
public:
    RulesTableModel(const nd::Config& current,const nd::Config& original,QObject* parent)
        :QAbstractTableModel(parent),current_(current),original_(original){rebuildIndexes();}

    int rowCount(const QModelIndex& parent={}) const override{return parent.isValid()?0:static_cast<int>(current_.rules.size());}
    int columnCount(const QModelIndex& parent={}) const override{return parent.isValid()?0:5;}
    QVariant headerData(int section,Qt::Orientation orientation,int role) const override{
        if(orientation!=Qt::Horizontal||role!=Qt::DisplayRole)return {};
        static const char* keys[]{"Enabled","Name","Hostnames","Action","DNS Server"};
        return section>=0&&section<5?uiText(keys[section]):QVariant{};
    }
    QVariant data(const QModelIndex& index,int role=Qt::DisplayRole) const override{
        if(!index.isValid()||index.row()<0||static_cast<size_t>(index.row())>=current_.rules.size())return {};
        const auto& rule=current_.rules[static_cast<size_t>(index.row())];
        if(role==ruleIdRole)return rule.id;
        if(role==Qt::UserRole){
            if(index.column()==3)return rule.action==nd::Action::process?0:rule.action==nd::Action::bypass?1:2;
            if(index.column()==4)return rule.server_id;
            return {};
        }
        if(role==Qt::ToolTipRole&&index.column()==2)return joinPatterns(rule.patterns);
        if(role==Qt::DisplayRole){
            if(index.column()==0)return rule.enabled?QStringLiteral("✓"):QString{};
            if(index.column()==1)return q(rule.name);
            if(index.column()==2)return previewPatterns(rule.patterns);
            if(index.column()==3)return uiText(rule.action==nd::Action::process?"process":rule.action==nd::Action::bypass?"bypass":"block");
            if(index.column()==4){
                if(rule.action!=nd::Action::process||!rule.server_id)return uiText("Original/System");
                const auto server=server_names_.find(rule.server_id);return server==server_names_.end()?uiText("Original/System"):server->second;
            }
        }
        if(role==Qt::ForegroundRole&&!rule.enabled)return QBrush(Qt::gray);
        if(role==Qt::FontRole&&changed(rule,index.column())){auto font=QApplication::font();font.setBold(true);return font;}
        return {};
    }
    Qt::ItemFlags flags(const QModelIndex& index) const override{
        if(!index.isValid())return Qt::NoItemFlags;
        auto result=Qt::ItemIsEnabled|Qt::ItemIsSelectable;
        if(index.column()==3)result|=Qt::ItemIsEditable;
        if(index.column()==4){
            const auto& rule=current_.rules[static_cast<size_t>(index.row())];
            if(rule.action==nd::Action::process)result|=Qt::ItemIsEditable;
            else result&=~Qt::ItemIsEnabled;
        }
        return result;
    }
    void refresh(){beginResetModel();rebuildIndexes();endResetModel();}

private:
    bool changed(const nd::Rule& rule,int column) const{
        const auto found=original_rules_.find(rule.id);if(found==original_rules_.end())return true;
        const auto& before=*found->second;
        if(column==0)return before.enabled!=rule.enabled;
        if(column==1){const auto row=original_rows_.find(rule.id);return before.name!=rule.name||before.interface_id!=rule.interface_id||before.metadata!=rule.metadata||row==original_rows_.end()||row->second!=static_cast<size_t>(&rule-current_.rules.data());}
        if(column==2)return before.patterns!=rule.patterns;
        if(column==3)return before.action!=rule.action||before.block_mode!=rule.block_mode||before.dnssec_validate!=rule.dnssec_validate||before.dnssec_reject_unsigned!=rule.dnssec_reject_unsigned;
        return column==4&&before.server_id!=rule.server_id;
    }
    void rebuildIndexes(){
        original_rules_.clear();original_rows_.clear();server_names_.clear();
        original_rules_.reserve(original_.rules.size());original_rows_.reserve(original_.rules.size());server_names_.reserve(current_.servers.size());
        for(size_t row=0;row<original_.rules.size();++row){original_rules_.emplace(original_.rules[row].id,&original_.rules[row]);original_rows_.emplace(original_.rules[row].id,row);}
        for(const auto& server:current_.servers)server_names_.emplace(server.id,q(server.name));
    }
    const nd::Config& current_;
    const nd::Config& original_;
    std::unordered_map<uint32_t,const nd::Rule*> original_rules_;
    std::unordered_map<uint32_t,size_t> original_rows_;
    std::unordered_map<uint32_t,QString> server_names_;
};

class RulesDialog final:public QDialog{
public:
    RulesDialog(QWidget* parent,nd::Config& config,std::function<bool()> changed)
        :QDialog(parent),target_(config),changed_(std::move(changed)){
        setWindowTitle(uiText("Rules"));resize(880,480);
        model_=new RulesTableModel(working_,original_,this);
        table_=new QTableView(this);
        table_->setModel(model_);
        table_->horizontalHeader()->setSectionResizeMode(1,QHeaderView::Stretch);
        table_->horizontalHeader()->setSectionResizeMode(2,QHeaderView::Stretch);
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setSelectionMode(QAbstractItemView::SingleSelection);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        configureFixedTableRows(table_);

        auto* up=new QPushButton(uiText("Up"));auto* down=new QPushButton(uiText("Down"));
        auto* add=new QPushButton(uiText("Add..."));auto* edit=new QPushButton(uiText("Edit..."));
        auto* clone=new QPushButton(uiText("Clone"));auto* remove=new QPushButton(uiText("Remove"));
        auto* ok=new QPushButton(uiText("OK"));auto* close=new QPushButton(uiText("Close"));
        auto* side=new QVBoxLayout;
        side->addWidget(up);side->addWidget(down);side->addSpacing(up->sizeHint().height());
        side->addWidget(add);side->addWidget(edit);side->addWidget(clone);side->addWidget(remove);side->addStretch();
        auto* content=new QHBoxLayout;content->addWidget(table_,1);content->addLayout(side);
        auto* bottom=new QHBoxLayout;bottom->addWidget(ok);bottom->addStretch();bottom->addWidget(close);
        auto* root=new QVBoxLayout(this);root->addLayout(content,1);root->addLayout(bottom);
        initializationControls_={table_,up,down,add,edit,clone,remove,ok};
        for(auto* control:initializationControls_)control->setEnabled(false);

        table_->setItemDelegateForColumn(3,new LazyComboDelegate(
            []{return std::vector<ComboOption>{{uiText("process"),0},{uiText("bypass"),1},{uiText("block"),2}};},
            [this](const QModelIndex& index,uint32_t value){
                const auto id=index.siblingAtColumn(0).data(ruleIdRole).toUInt();
                QTimer::singleShot(0,this,[this,id,value]{updateRule(id,[value](nd::Rule& rule){
                    rule.action=value==0?nd::Action::process:value==1?nd::Action::bypass:nd::Action::block;
                    if(rule.action!=nd::Action::process)rule.server_id=0;
                });});
            },table_));
        table_->setItemDelegateForColumn(4,new LazyComboDelegate(
            [this]{
                std::vector<ComboOption> options{{uiText("Original/System"),0}};
                options.reserve(working_.servers.size()+1);
                for(const auto& server:working_.servers)options.push_back({q(server.name),server.id});
                return options;
            },
            [this](const QModelIndex& index,uint32_t value){
                const auto id=index.siblingAtColumn(0).data(ruleIdRole).toUInt();
                QTimer::singleShot(0,this,[this,id,value]{updateRule(id,[value](nd::Rule& rule){
                    if(rule.action==nd::Action::process)rule.server_id=value;
                });});
            },table_));

        connect(up,&QPushButton::clicked,this,[this]{move(-1);});
        connect(down,&QPushButton::clicked,this,[this]{move(1);});
        connect(add,&QPushButton::clicked,this,[this]{nd::Rule rule;rule.id=nextRuleId(working_);rule.name=s(uiText("New Rule"));rule.patterns={"example.com"};if(editRule(this,working_,rule))apply([&](nd::ConfigEditor& editor){editor.add_rule(rule);},rule.id);});
        connect(clone,&QPushButton::clicked,this,[this]{const int row=table_->currentIndex().row();if(row<0)return;const auto id=nextRuleId(working_);apply([&](nd::ConfigEditor& editor){editor.clone_rule(working_.rules[static_cast<size_t>(row)].id,id);},id);});
        connect(edit,&QPushButton::clicked,this,[this]{const int row=table_->currentIndex().row();if(row<0)return;auto rule=working_.rules[static_cast<size_t>(row)];if(editRule(this,working_,rule))apply([&](nd::ConfigEditor& editor){editor.update_rule(rule);},rule.id);});
        connect(remove,&QPushButton::clicked,this,[this]{const int row=table_->currentIndex().row();if(row<0)return;if(working_.rules[static_cast<size_t>(row)].is_default){QMessageBox::information(this,"NativeDNS",uiText("Default rule cannot be removed."));return;}apply([&](nd::ConfigEditor& editor){editor.remove_rule(working_.rules[static_cast<size_t>(row)].id);});});
        connect(ok,&QPushButton::clicked,this,[this]{commit();});
        connect(close,&QPushButton::clicked,this,&QDialog::reject);
        connect(table_,&QTableView::clicked,this,[this](const QModelIndex& index){if(index.column()>=3&&index.column()<=4&&(index.flags()&Qt::ItemIsEnabled))table_->edit(index);});
        connect(table_,&QTableView::doubleClicked,this,[edit](const QModelIndex& index){if(index.column()<3)edit->click();});
    }
protected:
    void paintEvent(QPaintEvent* event) override{
        QDialog::paintEvent(event);
        if(initializationScheduled_)return;
        initializationScheduled_=true;
        QTimer::singleShot(0,this,[this]{
            original_=target_;
            working_=target_;
            model_->refresh();
            for(auto* control:initializationControls_)control->setEnabled(true);
        });
    }
private:
    void commit(){
        if(working_==original_){accept();return;}
        const auto previous=target_;
        target_=working_;
        if(changed_()){original_=working_;accept();}
        else target_=previous;
    }
    template<class F>void apply(F fn,uint32_t selectedId=0){
        try{nd::ConfigEditor editor(working_);fn(editor);working_=editor.get();reload(selectedId);}
        catch(const std::exception& e){QMessageBox::critical(this,"NativeDNS",e.what());}
    }
    void updateRule(uint32_t id,const std::function<void(nd::Rule&)>& update){
        try{
            const auto found=std::find_if(working_.rules.begin(),working_.rules.end(),[id](const nd::Rule& rule){return rule.id==id;});
            if(found==working_.rules.end())return;
            auto rule=*found;update(rule);if(rule==*found)return;
            nd::ConfigEditor editor(working_);editor.update_rule(std::move(rule));working_=editor.get();reload(id);
        }catch(const std::exception& e){QMessageBox::critical(this,"NativeDNS",e.what());reload(id);}
    }
    void move(int direction){
        const int row=table_->currentIndex().row();if(row<0)return;
        const auto id=working_.rules[static_cast<size_t>(row)].id;
        apply([&](nd::ConfigEditor& editor){editor.move_rule(id,direction);},id);
    }
    void reload(uint32_t selectedId=0){
        model_->refresh();
        int selectedRow=-1;
        if(selectedId)for(size_t row=0;row<working_.rules.size();++row)if(working_.rules[row].id==selectedId){selectedRow=static_cast<int>(row);break;}
        if(selectedRow>=0)table_->selectRow(selectedRow);
    }
    nd::Config& target_;
    nd::Config original_;
    nd::Config working_;
    std::function<bool()> changed_;
    RulesTableModel* model_=nullptr;
    QTableView* table_=nullptr;
    std::vector<QWidget*> initializationControls_;
    bool initializationScheduled_=false;
};
}

NativeDnsWindow::NativeDnsWindow(bool background){
    (void)background;
    loadConfiguration();
    buildUi();
    connect(&statusTimer_,&QTimer::timeout,this,[this]{refreshStatus();});
    connect(&logTimer_,&QTimer::timeout,this,[this]{refreshLogs();});
    connect(qApp,&QCoreApplication::aboutToQuit,this,[this]{shutdownCoreForExit();});
    statusTimer_.start(1000);
    logTimer_.start(500);
    statusTimer_.setTimerType(Qt::CoarseTimer);
    logTimer_.setTimerType(Qt::CoarseTimer);
    QTimer::singleShot(100,this,[this]{refreshStatus();ensureCoreStarted();});
}

NativeDnsWindow::~NativeDnsWindow(){
    shutdownCoreForExit();
    if(tray_)tray_->hide();
}

void NativeDnsWindow::ensureCoreStarted(){startCore(true);}
std::filesystem::path NativeDnsWindow::configPath() const{return nd::platform::user_config_directory()/"NativeDNS.xml";}

void NativeDnsWindow::showAndActivate(){
    showNormal();
    show();
    raise();
    activateWindow();
}

void NativeDnsWindow::buildUi(){
    setWindowTitle("NativeDNS "+QCoreApplication::applicationVersion());
    setWindowIcon(QApplication::windowIcon());
    resize(900,560);
    setMinimumSize(680,420);
    auto mark=[](QAction* action,const char* key){
        action->setProperty("uiTextKey",QString::fromUtf8(key));
        action->setText(uiText(key));
        return action;
    };
    auto addMenu=[this,&mark](const char* key){auto* menu=menuBar()->addMenu(QString{});mark(menu->menuAction(),key);return menu;};
    auto addAction=[&mark](QMenu* menu,const char* key){return mark(menu->addAction(QString{}),key);};
    auto addSubMenu=[&mark](QMenu* parent,const char* key){auto* menu=parent->addMenu(QString{});mark(menu->menuAction(),key);return menu;};

    log_=new QPlainTextEdit(this);
    log_->setReadOnly(true);
    log_->setLineWrapMode(QPlainTextEdit::NoWrap);
    log_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    constexpr int maximumVisibleLogRows=2000;
    log_->document()->setMaximumBlockCount(maximumVisibleLogRows);
    setCentralWidget(log_);
    coreStatus_=new QLabel(uiText("Core: unknown"),this);
    statusBar()->addPermanentWidget(coreStatus_);

    auto* file=addMenu("&File");
    auto* newCfg=addAction(file,"New Configuration");
    auto* import=addAction(file,"Import Configuration...");
    auto* exportCfg=addAction(file,"Export Configuration...");
    file->addSeparator();
    auto* autostart=addAction(file,"Autostart");
    autostart->setCheckable(true);
    file->addSeparator();
    auto* exit=addAction(file,"Exit");

    auto* config=addMenu("&Configuration");
    auto* servers=addAction(config,"DNS Servers...");
    auto* rules=addAction(config,"Rules...");

    auto* advanced=addMenu("&Advanced");
    auto* note=addAction(advanced,"Additional modules will appear here");
    note->setEnabled(false);

    auto* logMenu=addMenu("&Log");
    auto* clear=addAction(logMenu,"Clear Display");
    auto* screen=addSubMenu(logMenu,"Screen");
    auto* group=new QActionGroup(this);
    group->setExclusive(true);
    const int configuredLevel=std::clamp(static_cast<int>(config_.logging.screen),0,3);
    for(int i=0;i<4;++i){
        static constexpr const char* levelKeys[]{"Errors Only","Normal","Verbose","Debug"};
        auto* action=addAction(screen,levelKeys[i]);
        action->setCheckable(true);
        action->setData(i);
        group->addAction(action);
        if(i==configuredLevel)action->setChecked(true);
        connect(action,&QAction::triggered,this,[this,i]{config_.logging.screen=static_cast<nd::Level>(i);saveConfiguration();});
    }
    logMenu->addSeparator();
    auto* fileEnabled=addAction(logMenu,"Write diagnostic file");
    fileEnabled->setCheckable(true);
    fileEnabled->setChecked(config_.logging.file_enabled);
    connect(fileEnabled,&QAction::toggled,this,[this](bool enabled){config_.logging.file_enabled=enabled;applyFileLogging();});
    auto* fileLevel=addSubMenu(logMenu,"File level");
    auto* fileGroup=new QActionGroup(this);
    fileGroup->setExclusive(true);
    const int configuredFileLevel=std::clamp(static_cast<int>(config_.logging.file),0,3);
    for(int i=0;i<4;++i){
        static constexpr const char* levelKeys[]{"Errors Only","Normal","Verbose","Debug"};
        auto* action=addAction(fileLevel,levelKeys[i]);
        action->setCheckable(true);
        fileGroup->addAction(action);
        if(i==configuredFileLevel)action->setChecked(true);
        connect(action,&QAction::triggered,this,[this,i]{config_.logging.file=static_cast<nd::Level>(i);applyFileLogging();});
    }
    auto* clearFile=addAction(logMenu,"Clear Diagnostic File");
    auto* openLogFolder=addAction(logMenu,"Open Log Folder");
    connect(clearFile,&QAction::triggered,this,[this]{
        try{
            const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::clear_file_log,{},500);
            if(response.status)throw std::runtime_error(response.payload);
        }catch(const std::exception& error){QMessageBox::warning(this,"NativeDNS Log",error.what());}
    });
    connect(openLogFolder,&QAction::triggered,this,[this]{
        try{
            const auto directory=nd::platform::application_root_directory()/"logs";
            std::filesystem::create_directories(directory);
            QDesktopServices::openUrl(QUrl::fromLocalFile(qPath(directory)));
        }catch(...){ }
    });

    auto* window=addMenu("&Window");
    hideToTrayAction_=addAction(window,"Hide to tray");
    hideToTrayAction_->setCheckable(true);
    QSettings uiSettings;
    hideToTray_=uiSettings.value("ui/hideToTray",true).toBool();
    darkTheme_=uiSettings.value("ui/darkTheme",false).toBool();
    hideToTrayAction_->setChecked(hideToTray_);

    auto* other=addMenu("&Other");
    auto* language=addSubMenu(other,"Language");
    auto* english=addAction(language,"English");
    english->setCheckable(true);
    auto* russian=addAction(language,"Русский");
    russian->setCheckable(true);
    auto* languageGroup=new QActionGroup(this);
    languageGroup->setExclusive(true);
    languageGroup->addAction(english);languageGroup->addAction(russian);
    english->setChecked(uiLanguage()==UiLanguage::english);
    russian->setChecked(uiLanguage()==UiLanguage::russian);
    auto* theme=addSubMenu(other,"Theme");
    auto* light=addAction(theme,"Light");
    light->setCheckable(true);
    light->setChecked(!darkTheme_);
    auto* dark=addAction(theme,"Dark");
    dark->setCheckable(true);
    dark->setChecked(darkTheme_);
    auto* themeGroup=new QActionGroup(this);
    themeGroup->setExclusive(true);
    themeGroup->addAction(light);themeGroup->addAction(dark);

    auto* help=addMenu("&Help");
    auto* about=addAction(help,"About NativeDNS");

    auto* bar=addToolBar("Main");
    bar->setObjectName("mainToolBar");
    bar->setMovable(false);
    bar->addAction(servers);
    bar->addAction(rules);
    bar->addSeparator();
    bar->addAction(clear);

    trayAvailable_=QSystemTrayIcon::isSystemTrayAvailable();
    QIcon trayIcon=QApplication::windowIcon();
    if(trayIcon.isNull())trayIcon=style()->standardIcon(QStyle::SP_ComputerIcon);
    tray_=new QSystemTrayIcon(trayIcon,this);
    tray_->setToolTip("NativeDNS");
    auto* trayMenu=new QMenu(this);
    auto* open=addAction(trayMenu,"Open");
    trayMenu->addAction(servers);
    trayMenu->addAction(rules);
    trayMenu->addSeparator();
    trayMenu->addAction(exit);
    tray_->setContextMenu(trayMenu);
    if(trayAvailable_)tray_->show();
    else{
        hideToTray_=false;
        hideToTrayAction_->setChecked(false);
        hideToTrayAction_->setEnabled(false);
        hideToTrayAction_->setToolTip("The desktop system tray is not available.");
    }

    connect(tray_,&QSystemTrayIcon::activated,this,[this](QSystemTrayIcon::ActivationReason reason){
        if(reason==QSystemTrayIcon::Trigger||reason==QSystemTrayIcon::DoubleClick)showAndActivate();
    });
    connect(open,&QAction::triggered,this,[this]{showAndActivate();});
    connect(english,&QAction::triggered,this,[this]{
        setUiLanguage(UiLanguage::english);QSettings().setValue("ui/language","en");retranslateUi();
    });
    connect(russian,&QAction::triggered,this,[this]{
        setUiLanguage(UiLanguage::russian);QSettings().setValue("ui/language","ru");retranslateUi();
    });
    connect(light,&QAction::triggered,this,[this]{darkTheme_=false;QSettings().setValue("ui/darkTheme",false);applyUiTheme(*qApp,false);});
    connect(dark,&QAction::triggered,this,[this]{darkTheme_=true;QSettings().setValue("ui/darkTheme",true);applyUiTheme(*qApp,true);});

    connect(newCfg,&QAction::triggered,this,[this]{
        if(QMessageBox::question(this,"NativeDNS",uiText("Create a new configuration?"))==QMessageBox::Yes){
            config_=nd::default_config();
            if(applyConfiguration())log_->clear();
        }
    });
    connect(import,&QAction::triggered,this,[this]{importConfiguration();});
    connect(exportCfg,&QAction::triggered,this,[this]{exportConfiguration();});
    connect(servers,&QAction::triggered,this,[this]{openServers();});
    connect(rules,&QAction::triggered,this,[this]{openRules();});
    connect(clear,&QAction::triggered,this,[this]{
        log_->clear();
        logSequence_=0;
        try{(void)nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::clear_display,{},100);}catch(...){}
    });
    connect(hideToTrayAction_,&QAction::toggled,this,[this](bool enabled){
        if(enabled&&!trayAvailable_){
            QSignalBlocker blocker(hideToTrayAction_);
            hideToTrayAction_->setChecked(false);
            return;
        }
        hideToTray_=enabled;
        QSettings settings;
        settings.setValue("ui/hideToTray",enabled);
    });
    connect(exit,&QAction::triggered,this,[this]{exitApplication();});
    connect(about,&QAction::triggered,this,[this]{showAboutDialog(this);});

    connect(autostart,&QAction::toggled,this,[this,autostart](bool enabled){try{
#ifdef _WIN32
        // Registering a highest-privilege Scheduled Task requires elevation.
        // Keep the Qt GUI unprivileged and elevate only NativeDNSCoreHost.exe,
        // which also acts as a tiny one-shot privileged helper.
        const QString coreHost=QCoreApplication::applicationDirPath()+"/NativeDNSCoreHost.exe";
        if(!QFileInfo(coreHost).isFile())throw std::runtime_error("NativeDNSCoreHost.exe is missing");

        QStringList args;
        if(enabled)args<<"--register-autostart"<<qPath(configPath())
                       <<"--gui-executable"<<QCoreApplication::applicationFilePath();
        else args<<"--unregister-autostart";

        int exitCode=-1;
        QString launchError;
        if(!runNativeDnsHelper(coreHost,args,true,&exitCode,&launchError))
            throw std::runtime_error(s(launchError));
        if(exitCode!=0)
            throw std::runtime_error("Elevated autostart helper failed with exit code "+std::to_string(exitCode));
#else
        // Linux autostart is a user-level desktop entry. Transparent CoreHost
        // elevation still happens separately through pkexec when Core starts.
        const auto executable=fsPath(QCoreApplication::applicationFilePath());
        if(enabled)nd::enable_autostart(executable,configPath());else nd::disable_autostart();
#endif
        autostart->setText(uiText("Autostart"));
        autostart->setProperty("uiTextKey","Autostart");
        autostart->setToolTip(QString());
    }catch(const std::exception& e){
        QMessageBox::critical(this,"Autostart",e.what());
        QSignalBlocker blocker(autostart);
        autostart->setChecked(!enabled);
    }});
    try{
        QSignalBlocker blocker(autostart);
        const auto status=nd::autostart_status();
        autostart->setChecked(status.enabled);
        if(status.needs_repair){
            autostart->setText(uiText("Autostart (repair required)"));
            autostart->setProperty("uiTextKey","Autostart (repair required)");
            autostart->setToolTip("Autostart registration is outdated. Turn Autostart off and on again to repair it.");
        }
    }catch(...){}
}

void NativeDnsWindow::retranslateUi(){
    const auto actions=findChildren<QAction*>();
    for(auto* action:actions){
        const auto key=action->property("uiTextKey").toString();
        if(!key.isEmpty())action->setText(uiText(key.toUtf8().constData()));
    }
    refreshStatus();
}

void NativeDnsWindow::loadConfiguration(){
    const auto path=configPath();
    try{
        if(std::filesystem::exists(path))config_=nd::load_config(path);
        else{
            std::filesystem::create_directories(path.parent_path());
            config_=nd::default_config();
            nd::save_config(config_,path);
        }
    }catch(const std::exception& e){
        QMessageBox::critical(this,uiText("Configuration"),e.what());
        config_=nd::default_config();
    }
}

bool NativeDnsWindow::saveConfiguration(){
    try{
        nd::save_config(config_,configPath());
        return true;
    }catch(const std::exception& e){
        QMessageBox::critical(this,uiText("Configuration"),e.what());
        return false;
    }
}
bool NativeDnsWindow::applyConfiguration(){
    if(!saveConfiguration())return false;
    try{
        const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::restart,{},500);
        if(response.status)throw std::runtime_error(response.payload);
        coreLaunchPending_=true;
        coreLaunchTimer_.restart();
        logSequence_=0;
        setStatusText(uiText("Core: restarting..."));
    }catch(const nd::Error& error){
        if(error.code!="IPC_CONNECT"){
            QMessageBox::critical(this,"NativeDNS",error.what());
            return false;
        }
        coreLaunchPending_=false;
        startCore(true);
    }catch(const std::exception& error){
        QMessageBox::critical(this,"NativeDNS",error.what());
        return false;
    }
    return true;
}
void NativeDnsWindow::applyFileLogging(){
    if(!saveConfiguration())return;
    try{
        const auto payload=std::string(config_.logging.file_enabled?"1":"0")+'\t'+std::to_string(static_cast<unsigned>(config_.logging.file));
        const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::configure_file_log,payload,500);
        if(response.status)throw std::runtime_error(response.payload);
    }catch(...){
        // The setting is persisted and will be applied when CoreHost starts.
    }
}
void NativeDnsWindow::openServers(){ServerDialog dialog(this,config_,[this]{return applyConfiguration();});positionDialog(dialog,this);dialog.exec();}
void NativeDnsWindow::openRules(){RulesDialog dialog(this,config_,[this]{return applyConfiguration();});positionDialog(dialog,this);dialog.exec();}
void NativeDnsWindow::importConfiguration(){const auto file=QFileDialog::getOpenFileName(this,uiText("Import Configuration..."),{},"DNS configuration (*.xml);;All files (*)");if(file.isEmpty())return;try{const auto path=fsPath(file);try{config_=nd::load_config(path);}catch(const nd::Error&){config_=nd::import_yoga(path).config;}if(applyConfiguration())QMessageBox::information(this,"NativeDNS",uiText("Configuration imported."));}catch(const std::exception& e){QMessageBox::critical(this,uiText("Import"),e.what());}}
void NativeDnsWindow::exportConfiguration(){const auto file=QFileDialog::getSaveFileName(this,uiText("Export Configuration..."),"NativeDNS.xml","XML (*.xml)");if(file.isEmpty())return;try{nd::save_config(config_,fsPath(file));}catch(const std::exception& e){QMessageBox::critical(this,uiText("Export"),e.what());}}

void NativeDnsWindow::startCore(bool transparent){
    if(coreLaunchPending_&&coreLaunchTimer_.isValid()&&coreLaunchTimer_.elapsed()<45000)return;
    if(coreStartOperationPending_.exchange(true))return;
    const QString helper=QCoreApplication::applicationDirPath()+
#ifdef _WIN32
        "/NativeDNSCoreHost.exe";
#else
        "/NativeDNSCoreHost";
#endif
    QStringList args{"--config",qPath(configPath())};
    if(transparent)args<<"--transparent";
    const auto configuration=configPath();
    const auto cancellation=coreStartCancelled_;
    cancellation->store(false);
    coreLaunchPending_=true;
    coreLaunchTimer_.restart();
    setStatusText(uiText("Core: starting..."));
    QPointer<NativeDnsWindow> self(this);
    QThreadPool::globalInstance()->start([self,helper,args,configuration,transparent,cancellation]{
        bool success=false,running=false;
        QString failure;
        try{
            const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::status,{},150);
            if(response.status)throw std::runtime_error(response.payload);
            if(response.payload.rfind("RUNNING",0)==0||response.payload.rfind("STARTING",0)==0){success=true;running=true;}
            else{
                const auto started=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::start,{},500);
                if(started.status)throw std::runtime_error(started.payload);
                success=true;running=true;
            }
        }catch(const nd::Error& error){
            if(error.code!="IPC_CONNECT"&&error.code!="IPC_TIMEOUT")failure=q(error.what());
        }catch(const std::exception& error){failure=q(error.what());}
        if(!success&&failure.isEmpty()&&!cancellation->load()){
            bool launched=false;
#ifdef _WIN32
            if(transparent){
                try{launched=nd::start_autostart_core(fsPath(helper),configuration);}
                catch(...){/* Fall back to the normal elevation prompt. */}
            }
#endif
            QString launch_error;
            if(!launched&&!cancellation->load())launched=launchNativeDnsCore(helper,args,transparent,&launch_error);
            success=launched;
            if(!success&&!cancellation->load())failure=launch_error;
        }
        QMetaObject::invokeMethod(qApp,[self,success,running,failure,cancellation]{
            if(!self)return;
            self->coreStartOperationPending_=false;
            if(cancellation->load())return;
            if(!success){self->coreLaunchPending_=false;self->setStatusText(uiText("Core: stopped"),true);QMessageBox::critical(self,"NativeDNS",failure);return;}
            self->coreLaunchPending_=!running;
            if(running)self->refreshStatus();else{self->coreLaunchTimer_.restart();self->setStatusText(uiText("Core: starting..."));}
        },Qt::QueuedConnection);
    });
}

bool NativeDnsWindow::waitForCoreShutdown(int timeoutMs){
    QElapsedTimer timer;
    timer.start();
    while(timer.elapsed()<timeoutMs){
        try{
            const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::status,{},100);
            if(response.status)return false;
        }catch(const nd::Error& error){
            if(error.code=="IPC_CONNECT")return true;
        }catch(...){
            return false;
        }
        QThread::msleep(50);
    }
    return false;
}

void NativeDnsWindow::shutdownCoreForExit(){
    if(coreShutdownAttempted_)return;
    coreShutdownAttempted_=true;
    coreStartCancelled_->store(true);

    statusTimer_.stop();
    logTimer_.stop();

    // If the user closes NativeDNS immediately after Start/UAC, wait briefly
    // for the just-launched CoreHost pipe instead of orphaning that process.
    if(coreLaunchPending_&&coreLaunchTimer_.isValid()){
        QElapsedTimer startupWait;
        startupWait.start();
        while(startupWait.elapsed()<5000){
            try{
                const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::status,{},100);
                if(!response.status)break;
            }catch(const nd::Error& error){
                if(error.code!="IPC_CONNECT")break;
            }catch(...){break;}
            QThread::msleep(50);
        }
    }
    coreLaunchPending_=false;

    try{
        const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::shutdown,{},500);
        if(!response.status)(void)waitForCoreShutdown(4000);
    }catch(...){
        // No CoreHost is a valid shutdown state. Actual process singleton
        // enforcement prevents a failed IPC probe from spawning duplicates.
    }
}

void NativeDnsWindow::exitApplication(){
    if(exiting_)return;
    exiting_=true;
    hide();
    if(tray_)tray_->hide();
    shutdownCoreForExit();
    QCoreApplication::quit();
}

void NativeDnsWindow::refreshStatus(){
    if(statusRefreshPending_.exchange(true))return;
    QPointer<NativeDnsWindow> self(this);
    QThreadPool::globalInstance()->start([self]{
        QString status;
        bool failed=false;
        try{
            const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::status,{},100);
            if(response.status)throw std::runtime_error(response.payload);
            status=q(response.payload);
        }catch(...){failed=true;}
        QMetaObject::invokeMethod(qApp,[self,status=std::move(status),failed]{
            if(!self)return;
            self->statusRefreshPending_=false;
            if(!failed){
                self->coreLaunchPending_=false;
                self->setStatusText(friendlyCoreStatus(status),status.startsWith("ERROR"));
            }else if(self->coreLaunchPending_&&self->coreLaunchTimer_.isValid()&&self->coreLaunchTimer_.elapsed()<45000){
                self->setStatusText(uiText("Core: starting..."));
            }else{
                self->coreLaunchPending_=false;
                self->setStatusText(uiText("Core: stopped"));
            }
        },Qt::QueuedConnection);
    });
}

void NativeDnsWindow::refreshLogs(){
    if(logRefreshPending_.exchange(true))return;
    const auto request=std::to_string(logSequence_)+"\t0\t"+std::to_string(static_cast<unsigned>(config_.logging.screen));
    QPointer<NativeDnsWindow> self(this);
    QThreadPool::globalInstance()->start([self,request]{
        QString payload;
        try{auto response=nd::pipe_request(nd::core_log_pipe_name,nd::IpcOperation::logs,request,120);if(!response.status)payload=q(response.payload);}catch(...){}
        QMetaObject::invokeMethod(qApp,[self,payload=std::move(payload)]{
            if(!self)return;
            self->logRefreshPending_=false;
            self->appendLogLines(payload);
        },Qt::QueuedConnection);
    });
}
void NativeDnsWindow::appendLogLines(const QString& payload){
    if(payload.isEmpty())return;
    auto* scrollBar=log_->verticalScrollBar();
    const int scrollPosition=scrollBar->value();
    const bool follow=scrollPosition>=scrollBar->maximum()-2;
    log_->setUpdatesEnabled(false);
    auto cursor=QTextCursor(log_->document());
    cursor.movePosition(QTextCursor::End);
    cursor.beginEditBlock();
    for(const auto& line:payload.split('\n',Qt::SkipEmptyParts)){
        const auto fields=line.split('\t');
        if(fields.size()<4)continue;
        bool ok=false;
        const auto seq=fields[0].toULongLong(&ok);
        if(ok)logSequence_=std::max(logSequence_,static_cast<uint64_t>(seq));
        QString timestamp;
        int messageField=3;
        if(fields.size()>=5){
            bool timeOk=false;
            const auto milliseconds=fields[2].toLongLong(&timeOk);
            if(timeOk){timestamp=QDateTime::fromMSecsSinceEpoch(milliseconds).toString("dd.MM HH:mm:ss");messageField=4;}
        }
        if(timestamp.isEmpty())timestamp=QDateTime::currentDateTime().toString("dd.MM HH:mm:ss");
        QTextCharFormat format;
        if(fields[1].toUInt()==0)format.setForeground(darkTheme_?QColor(255,105,105):QColor(190,0,0));
        cursor.insertText('['+timestamp+"] "+fields.mid(messageField).join('\t')+'\n',format);
    }
    cursor.endEditBlock();
    log_->setUpdatesEnabled(true);
    scrollBar->setValue(follow?scrollBar->maximum():std::min(scrollPosition,scrollBar->maximum()));
    log_->viewport()->update();
}
void NativeDnsWindow::setStatusText(const QString& text,bool error){
    coreStatus_->setText(text);
    auto colors=coreStatus_->palette();
    colors.setColor(QPalette::WindowText,error?QColor(190,0,0):palette().color(QPalette::Text));
    coreStatus_->setPalette(colors);
}

void NativeDnsWindow::closeEvent(QCloseEvent* event){
    if(exiting_){
        event->accept();
        return;
    }

    if(hideToTray_&&trayAvailable_){
        hide();
        event->ignore();
        return;
    }

    event->accept();
    exitApplication();
}
