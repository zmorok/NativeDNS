#include "qt_app.hpp"
#include "platform_launcher.hpp"
#include <nativedns/autostart.hpp>
#include <nativedns/dns.hpp>
#include <nativedns/ipc.hpp>
#include <nativedns/platform.hpp>
#include <QApplication>
#include <QAction>
#include <QActionGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QIcon>
#include <QInputDialog>
#include <QLineEdit>
#include <QMenuBar>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStandardPaths>
#include <QStatusBar>
#include <QTableWidget>
#include <QToolBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPointer>
#include <QMetaObject>
#include <QBrush>
#include <QColor>
#include <QFileInfo>
#include <QSignalBlocker>
#include <QSettings>
#include <QStyle>
#include <QThread>
#include <QTextCursor>
#include <QTextCharFormat>
#include <thread>
#include <algorithm>
#include <functional>
#include <stdexcept>

namespace {
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
QString protocolText(nd::Protocol p){return q(nd::protocol_name(p));}
QString actionText(nd::Action a){return q(nd::action_name(a));}
nd::Protocol protocolFrom(int index){static const nd::Protocol values[]{nd::Protocol::udp,nd::Protocol::tcp,nd::Protocol::doh,nd::Protocol::dot,nd::Protocol::doh3,nd::Protocol::doq,nd::Protocol::dnscrypt,nd::Protocol::anonymized_dnscrypt};return values[std::clamp(index,0,7)];}
int protocolIndex(nd::Protocol p){for(int i=0;i<8;++i)if(protocolFrom(i)==p)return i;return 0;}
QString joinPatterns(const std::vector<std::string>& patterns){QStringList list;for(const auto& p:patterns)list<<q(p);return list.join(";\n");}
uint32_t nextServerId(const nd::Config& c){uint32_t id=0;for(const auto& v:c.servers)id=std::max(id,v.id);return id+1;}
uint32_t nextRuleId(const nd::Config& c){uint32_t id=0;for(const auto& v:c.rules)id=std::max(id,v.id);return id+1;}

bool editServer(QWidget* parent,nd::Server& server){
    QDialog dialog(parent);dialog.setWindowTitle(server.id?"DNS Server":"Add DNS Server");dialog.resize(520,390);
    auto* form=new QFormLayout;
    QLineEdit name(q(server.name)),ip(q(server.ip)),host(q(server.hostname)),url(q(server.url)),port(server.port?QString::number(server.port):QString()),bootstrap,publicKey(q(server.public_key)),provider(q(server.provider_name)),relay(q(server.relay));
    QComboBox protocol;for(int i=0;i<8;++i)protocol.addItem(protocolText(protocolFrom(i)));protocol.setCurrentIndex(protocolIndex(server.protocol));
    QCheckBox enabled("Enabled"),dnssec("DNSSEC supported");enabled.setChecked(server.enabled);dnssec.setChecked(server.dnssec_supported);
    bootstrap.setText([&]{QStringList x;for(const auto& v:server.bootstrap)x<<q(v);return x.join(';');}());
    form->addRow("Name:",&name);form->addRow("Protocol:",&protocol);form->addRow("IP:",&ip);form->addRow("Port:",&port);form->addRow("Hostname:",&host);form->addRow("URL:",&url);form->addRow("Bootstrap:",&bootstrap);form->addRow("Public key:",&publicKey);form->addRow("Provider:",&provider);form->addRow("Relay:",&relay);form->addRow(&enabled);form->addRow(&dnssec);
    auto update=[&]{const auto p=protocolFrom(protocol.currentIndex());const bool plain=p==nd::Protocol::udp||p==nd::Protocol::tcp;const bool doh=p==nd::Protocol::doh||p==nd::Protocol::doh3;const bool dot=p==nd::Protocol::dot||p==nd::Protocol::doq;const bool crypt=p==nd::Protocol::dnscrypt||p==nd::Protocol::anonymized_dnscrypt;ip.setEnabled(plain||crypt||dot||doh);url.setEnabled(doh);host.setEnabled(dot||doh);publicKey.setEnabled(crypt);provider.setEnabled(crypt);relay.setEnabled(p==nd::Protocol::anonymized_dnscrypt);};
    QObject::connect(&protocol,&QComboBox::currentIndexChanged,&dialog,[&]{update();});update();
    auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel);QObject::connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept);QObject::connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
    auto* root=new QVBoxLayout(&dialog);root->addLayout(form);root->addWidget(buttons);
    if(dialog.exec()!=QDialog::Accepted)return false;
    server.name=s(name.text().trimmed());server.protocol=protocolFrom(protocol.currentIndex());server.ip=s(ip.text().trimmed());server.hostname=s(host.text().trimmed());server.url=s(url.text().trimmed());server.port=static_cast<uint16_t>(port.text().toUInt());server.enabled=enabled.isChecked();server.dnssec_supported=dnssec.isChecked();server.public_key=s(publicKey.text().trimmed());server.provider_name=s(provider.text().trimmed());server.relay=s(relay.text().trimmed());server.bootstrap.clear();for(const auto& part:bootstrap.text().split(';',Qt::SkipEmptyParts))server.bootstrap.push_back(s(part.trimmed()));
    return true;
}

class ServerDialog final:public QDialog{
public:
    ServerDialog(QWidget* parent,nd::Config& config,std::function<void()> changed):QDialog(parent),config_(config),changed_(std::move(changed)){
        setWindowTitle("DNS Servers");resize(780,430);table_=new QTableWidget(this);table_->setColumnCount(5);table_->setHorizontalHeaderLabels({"Name","Protocol","Address","Status","RTT"});table_->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Stretch);table_->horizontalHeader()->setSectionResizeMode(2,QHeaderView::Stretch);table_->setSelectionBehavior(QAbstractItemView::SelectRows);table_->setSelectionMode(QAbstractItemView::ExtendedSelection);table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        auto* add=new QPushButton("Add...");auto* edit=new QPushButton("Edit...");auto* remove=new QPushButton("Remove");auto* check=new QPushButton("Check");auto* close=new QPushButton("Close");auto* row=new QHBoxLayout;row->addWidget(add);row->addWidget(edit);row->addWidget(remove);row->addStretch();row->addWidget(check);row->addWidget(close);auto* root=new QVBoxLayout(this);root->addWidget(table_);root->addLayout(row);
        connect(add,&QPushButton::clicked,this,[this]{nd::Server server;server.id=nextServerId(config_);server.name="New DNS Server";if(editServer(this,server)){try{nd::ConfigEditor editor(config_);editor.add_server(server);config_=editor.get();changed_();reload();}catch(const std::exception& e){QMessageBox::critical(this,"NativeDNS",e.what());}}});
        connect(edit,&QPushButton::clicked,this,[this]{const int row=table_->currentRow();if(row<0)return;auto server=config_.servers[static_cast<size_t>(row)];if(editServer(this,server)){try{nd::ConfigEditor editor(config_);editor.update_server(server);config_=editor.get();changed_();reload();}catch(const std::exception& e){QMessageBox::critical(this,"NativeDNS",e.what());}}});
        connect(remove,&QPushButton::clicked,this,[this]{const int row=table_->currentRow();if(row<0)return;if(QMessageBox::question(this,"NativeDNS","Remove selected DNS server?")!=QMessageBox::Yes)return;try{nd::ConfigEditor editor(config_);editor.remove_server(config_.servers[static_cast<size_t>(row)].id);config_=editor.get();changed_();reload();}catch(const std::exception& e){QMessageBox::critical(this,"NativeDNS",e.what());}});
        connect(check,&QPushButton::clicked,this,[this]{checkSelected();});connect(close,&QPushButton::clicked,this,&QDialog::accept);connect(table_,&QTableWidget::cellDoubleClicked,this,[edit](int,int){edit->click();});reload();
    }
private:
    void reload(){table_->setRowCount(static_cast<int>(config_.servers.size()));for(int r=0;r<table_->rowCount();++r){const auto& v=config_.servers[static_cast<size_t>(r)];table_->setItem(r,0,new QTableWidgetItem(q(v.name)));table_->setItem(r,1,new QTableWidgetItem(protocolText(v.protocol)));const auto address=!v.url.empty()?v.url:(!v.hostname.empty()?v.hostname:v.ip+(v.port?":"+std::to_string(v.port):""));table_->setItem(r,2,new QTableWidgetItem(q(address)));table_->setItem(r,3,new QTableWidgetItem("Not tested"));table_->setItem(r,4,new QTableWidgetItem("—"));}}
    void checkSelected(){auto rows=table_->selectionModel()->selectedRows();if(rows.isEmpty()&&table_->currentRow()>=0)rows<<table_->model()->index(table_->currentRow(),0);for(const auto& index:rows){const int row=index.row();if(row<0||row>=static_cast<int>(config_.servers.size()))continue;auto server=config_.servers[static_cast<size_t>(row)];table_->item(row,3)->setText("Testing...");table_->item(row,3)->setForeground(QBrush(Qt::black));QPointer<ServerDialog> self(this);std::thread([self,row,server]{auto result=nd::test_server(server);QMetaObject::invokeMethod(qApp,[self,row,result]{if(!self)return;auto* status=self->table_->item(row,3);auto* rtt=self->table_->item(row,4);if(!status||!rtt)return;status->setText(result.success?"OK":q(result.error_code+": "+result.message));status->setForeground(QBrush(result.success?QColor(0,128,0):QColor(190,0,0)));rtt->setText(QString::number(result.rtt_ms,'f',1)+" ms");},Qt::QueuedConnection);}).detach();}}
    nd::Config& config_;std::function<void()> changed_;QTableWidget* table_=nullptr;
};

bool editRule(QWidget* parent,nd::Config& config,nd::Rule& rule){
    QDialog dialog(parent);dialog.setWindowTitle(rule.is_default?"Default Rule":"DNS Rule");dialog.resize(560,420);auto* form=new QFormLayout;
    QLineEdit name(q(rule.name));QPlainTextEdit hosts;hosts.setPlainText(joinPatterns(rule.patterns));hosts.setMinimumHeight(150);QComboBox action;action.addItems({"process","bypass","block"});action.setCurrentIndex(rule.action==nd::Action::process?0:rule.action==nd::Action::bypass?1:2);QComboBox server;server.addItem("Original/System",0);for(const auto& v:config.servers)server.addItem(q(v.name),v.id);const int found=server.findData(rule.server_id);if(found>=0)server.setCurrentIndex(found);QCheckBox enabled("Enabled");enabled.setChecked(rule.enabled);QComboBox block;block.addItems({"0.0.0.0 / ::","NXDOMAIN","REFUSED","Silent drop"});block.setCurrentIndex(static_cast<int>(rule.block_mode));form->addRow("Name:",&name);form->addRow("Hostnames:",&hosts);form->addRow("Action:",&action);form->addRow("DNS Server:",&server);form->addRow("Block mode:",&block);form->addRow(&enabled);auto update=[&]{server.setEnabled(action.currentIndex()==0);block.setEnabled(action.currentIndex()==2);name.setEnabled(!rule.is_default);hosts.setEnabled(!rule.is_default);enabled.setEnabled(!rule.is_default);};QObject::connect(&action,&QComboBox::currentIndexChanged,&dialog,[&]{update();});update();auto* buttons=new QDialogButtonBox(QDialogButtonBox::Ok|QDialogButtonBox::Cancel);QObject::connect(buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept);QObject::connect(buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);auto* root=new QVBoxLayout(&dialog);root->addLayout(form);root->addWidget(buttons);if(dialog.exec()!=QDialog::Accepted)return false;rule.name=s(name.text().trimmed());rule.patterns=nd::split_patterns(s(hosts.toPlainText()));rule.enabled=enabled.isChecked();rule.action=action.currentIndex()==0?nd::Action::process:action.currentIndex()==1?nd::Action::bypass:nd::Action::block;rule.server_id=rule.action==nd::Action::process?server.currentData().toUInt():0;rule.block_mode=static_cast<nd::BlockMode>(block.currentIndex());return true;
}

class RulesDialog final:public QDialog{
public:
    RulesDialog(QWidget* parent,nd::Config& config,std::function<void()> changed):QDialog(parent),config_(config),changed_(std::move(changed)){
        setWindowTitle("Rules");resize(800,450);table_=new QTableWidget(this);table_->setColumnCount(4);table_->setHorizontalHeaderLabels({"Enabled","Name","Action","DNS Server"});table_->horizontalHeader()->setSectionResizeMode(1,QHeaderView::Stretch);table_->setSelectionBehavior(QAbstractItemView::SelectRows);table_->setSelectionMode(QAbstractItemView::SingleSelection);table_->setEditTriggers(QAbstractItemView::NoEditTriggers);auto* up=new QPushButton("Up");auto* down=new QPushButton("Down");auto* add=new QPushButton("Add...");auto* clone=new QPushButton("Clone");auto* edit=new QPushButton("Edit...");auto* remove=new QPushButton("Remove");auto* close=new QPushButton("Close");auto* row=new QHBoxLayout;for(auto* b:{up,down,add,clone,edit,remove})row->addWidget(b);row->addStretch();row->addWidget(close);auto* root=new QVBoxLayout(this);root->addWidget(table_);root->addLayout(row);
        connect(up,&QPushButton::clicked,this,[this]{move(-1);});connect(down,&QPushButton::clicked,this,[this]{move(1);});connect(add,&QPushButton::clicked,this,[this]{nd::Rule r;r.id=nextRuleId(config_);r.name="New Rule";r.patterns={"example.com"};if(editRule(this,config_,r))apply([&](nd::ConfigEditor& e){e.add_rule(r);});});connect(clone,&QPushButton::clicked,this,[this]{const int row=table_->currentRow();if(row<0)return;apply([&](nd::ConfigEditor& e){e.clone_rule(config_.rules[static_cast<size_t>(row)].id,nextRuleId(config_));});});connect(edit,&QPushButton::clicked,this,[this]{const int row=table_->currentRow();if(row<0)return;auto r=config_.rules[static_cast<size_t>(row)];if(editRule(this,config_,r))apply([&](nd::ConfigEditor& e){e.update_rule(r);});});connect(remove,&QPushButton::clicked,this,[this]{const int row=table_->currentRow();if(row<0)return;if(config_.rules[static_cast<size_t>(row)].is_default){QMessageBox::information(this,"NativeDNS","Default rule cannot be removed.");return;}apply([&](nd::ConfigEditor& e){e.remove_rule(config_.rules[static_cast<size_t>(row)].id);});});connect(close,&QPushButton::clicked,this,&QDialog::accept);connect(table_,&QTableWidget::cellDoubleClicked,this,[edit](int,int){edit->click();});reload();
    }
private:
    template<class F>void apply(F fn){try{nd::ConfigEditor editor(config_);fn(editor);config_=editor.get();changed_();reload();}catch(const std::exception& e){QMessageBox::critical(this,"NativeDNS",e.what());}}
    void move(int dir){const int row=table_->currentRow();if(row<0)return;const auto id=config_.rules[static_cast<size_t>(row)].id;apply([&](nd::ConfigEditor& e){e.move_rule(id,dir);});const int target=std::clamp(row+dir,0,table_->rowCount()-1);table_->selectRow(target);}
    void reload(){table_->setRowCount(static_cast<int>(config_.rules.size()));for(int r=0;r<table_->rowCount();++r){const auto& v=config_.rules[static_cast<size_t>(r)];auto* enabled=new QTableWidgetItem(v.enabled?"✓":"");if(!v.enabled)enabled->setForeground(QBrush(Qt::gray));table_->setItem(r,0,enabled);table_->setItem(r,1,new QTableWidgetItem(q(v.name)));table_->setItem(r,2,new QTableWidgetItem(actionText(v.action)));QString server="—";if(v.action==nd::Action::process){if(!v.server_id)server="Original/System";else for(const auto& s:config_.servers)if(s.id==v.server_id)server=q(s.name);}table_->setItem(r,3,new QTableWidgetItem(server));}}
    nd::Config& config_;std::function<void()> changed_;QTableWidget* table_=nullptr;
};
}

NativeDnsWindow::NativeDnsWindow(bool background):background_(background){
    loadConfiguration();
    buildUi();
    connect(&statusTimer_,&QTimer::timeout,this,[this]{refreshStatus();});
    connect(&logTimer_,&QTimer::timeout,this,[this]{refreshLogs();});
    connect(qApp,&QCoreApplication::aboutToQuit,this,[this]{shutdownCoreForExit();});
    statusTimer_.start(1000);
    logTimer_.start(500);
    QTimer::singleShot(100,this,[this]{refreshStatus();if(background_)ensureCoreStarted();});
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
    setWindowTitle("NativeDNS");
    setWindowIcon(QApplication::windowIcon());
    resize(900,560);
    setMinimumSize(680,420);

    log_=new QPlainTextEdit(this);
    log_->setReadOnly(true);
    log_->setLineWrapMode(QPlainTextEdit::NoWrap);
    setCentralWidget(log_);
    coreStatus_=new QLabel("Core: unknown",this);
    statusBar()->addPermanentWidget(coreStatus_);

    auto* file=menuBar()->addMenu("&File");
    auto* newCfg=file->addAction("New Configuration");
    auto* import=file->addAction("Import Configuration...");
    auto* exportCfg=file->addAction("Export Configuration...");
    file->addSeparator();
    auto* autostart=file->addAction("Autostart");
    autostart->setCheckable(true);
    file->addSeparator();
    auto* exit=file->addAction("Exit");

    auto* config=menuBar()->addMenu("&Configuration");
    auto* servers=config->addAction("DNS Servers...");
    auto* rules=config->addAction("Rules...");

    auto* advanced=menuBar()->addMenu("&Advanced");
    auto* note=advanced->addAction("Additional modules will appear here");
    note->setEnabled(false);

    auto* logMenu=menuBar()->addMenu("&Log");
    auto* clear=logMenu->addAction("Clear Display");
    auto* screen=logMenu->addMenu("Screen");
    auto* group=new QActionGroup(this);
    group->setExclusive(true);
    const int configuredLevel=std::clamp(static_cast<int>(config_.logging.screen),0,3);
    for(int i=0;i<4;++i){
        auto* action=screen->addAction(QStringList{"Errors Only","Normal","Verbose","Debug"}[i]);
        action->setCheckable(true);
        action->setData(i);
        group->addAction(action);
        if(i==configuredLevel)action->setChecked(true);
        connect(action,&QAction::triggered,this,[this,i]{config_.logging.screen=static_cast<nd::Level>(i);saveConfiguration();});
    }

    auto* window=menuBar()->addMenu("&Window");
    hideToTrayAction_=window->addAction("Hide to tray");
    hideToTrayAction_->setCheckable(true);
    QSettings uiSettings;
    hideToTray_=uiSettings.value("ui/hideToTray",true).toBool();
    hideToTrayAction_->setChecked(hideToTray_);

    auto* help=menuBar()->addMenu("&Help");
    auto* about=help->addAction("About NativeDNS");

    auto* bar=addToolBar("Main");
    bar->setMovable(false);
    auto* start=bar->addAction("Start");
    auto* stop=bar->addAction("Stop");
    bar->addSeparator();
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
    auto* open=trayMenu->addAction("Open");
    trayMenu->addAction(servers);
    trayMenu->addAction(rules);
    trayMenu->addSeparator();
    trayMenu->addAction(start);
    trayMenu->addAction(stop);
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

    connect(newCfg,&QAction::triggered,this,[this]{
        if(QMessageBox::question(this,"NativeDNS","Create a new configuration?")==QMessageBox::Yes){
            config_=nd::default_config();
            saveConfiguration();
            log_->clear();
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
    connect(start,&QAction::triggered,this,[this]{startCore(true);});
    connect(stop,&QAction::triggered,this,[this]{stopCore();});
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
    connect(about,&QAction::triggered,this,[this]{
        QMessageBox::about(this,"NativeDNS","NativeDNS\nCross-platform DNS client\nQt 6 + native C++ Core");
    });

    connect(autostart,&QAction::toggled,this,[this,autostart](bool enabled){try{
#ifdef _WIN32
        // Registering a highest-privilege Scheduled Task requires elevation.
        // Keep the Qt GUI unprivileged and elevate only NativeDNSCoreHost.exe,
        // which also acts as a tiny one-shot privileged helper.
        const QString coreHost=QCoreApplication::applicationDirPath()+"/NativeDNSCoreHost.exe";
        if(!QFileInfo(coreHost).isFile())throw std::runtime_error("NativeDNSCoreHost.exe is missing");

        QStringList args;
        if(enabled)args<<"--register-autostart"<<qPath(configPath());
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
    }catch(const std::exception& e){
        QMessageBox::critical(this,"Autostart",e.what());
        QSignalBlocker blocker(autostart);
        autostart->setChecked(!enabled);
    }});
    try{
        QSignalBlocker blocker(autostart);
        autostart->setChecked(nd::autostart_status().enabled);
    }catch(...){}
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
        QMessageBox::critical(this,"Configuration",e.what());
        config_=nd::default_config();
    }
}

void NativeDnsWindow::saveConfiguration(){try{nd::save_config(config_,configPath());}catch(const std::exception& e){QMessageBox::critical(this,"Configuration",e.what());}}
void NativeDnsWindow::openServers(){ServerDialog dialog(this,config_,[this]{saveConfiguration();});dialog.exec();}
void NativeDnsWindow::openRules(){RulesDialog dialog(this,config_,[this]{saveConfiguration();});dialog.exec();}
void NativeDnsWindow::importConfiguration(){const auto file=QFileDialog::getOpenFileName(this,"Import Configuration",{},"DNS configuration (*.xml);;All files (*)");if(file.isEmpty())return;try{const auto path=fsPath(file);try{config_=nd::load_config(path);}catch(const nd::Error&){config_=nd::import_yoga(path).config;}saveConfiguration();QMessageBox::information(this,"NativeDNS","Configuration imported.");}catch(const std::exception& e){QMessageBox::critical(this,"Import",e.what());}}
void NativeDnsWindow::exportConfiguration(){const auto file=QFileDialog::getSaveFileName(this,"Export Configuration","NativeDNS.xml","XML (*.xml)");if(file.isEmpty())return;try{nd::save_config(config_,fsPath(file));}catch(const std::exception& e){QMessageBox::critical(this,"Export",e.what());}}

void NativeDnsWindow::startCore(bool transparent){
    if(coreLaunchPending_&&coreLaunchTimer_.isValid()&&coreLaunchTimer_.elapsed()<10000)return;

    try{
        const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::status,{},150);
        if(response.status)throw std::runtime_error(response.payload);
        coreLaunchPending_=false;
        if(response.payload.rfind("RUNNING",0)==0||response.payload.rfind("STARTING",0)==0)return;

        const auto started=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::start,{},500);
        if(started.status)throw std::runtime_error(started.payload);
        return;
    }catch(const nd::Error& error){
        if(error.code!="IPC_CONNECT"&&error.code!="IPC_TIMEOUT"){
            QMessageBox::critical(this,"NativeDNS",error.what());
            return;
        }
    }catch(const std::exception& error){
        QMessageBox::critical(this,"NativeDNS",error.what());
        return;
    }

    const QString helper=QCoreApplication::applicationDirPath()+
#ifdef _WIN32
        "/NativeDNSCoreHost.exe";
#else
        "/NativeDNSCoreHost";
#endif
    QString error;
    QStringList args{"--config",qPath(configPath())};
    if(transparent)args<<"--transparent";
    if(!launchNativeDnsCore(helper,args,transparent,&error)){
        coreLaunchPending_=false;
        QMessageBox::critical(this,"NativeDNS",error);
        return;
    }
    coreLaunchPending_=true;
    coreLaunchTimer_.restart();
    setStatusText("Core: starting...");
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

void NativeDnsWindow::stopCore(){
    coreLaunchPending_=false;
    try{
        const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::shutdown,{},500);
        if(response.status)throw std::runtime_error(response.payload);
        if(waitForCoreShutdown(3000))setStatusText("Core: stopped");
        else setStatusText("Core: shutdown timed out",true);
    }catch(const nd::Error& error){
        if(error.code=="IPC_CONNECT")setStatusText("Core: stopped");
        else setStatusText(QString("Core: %1").arg(error.what()),true);
    }catch(const std::exception& error){
        setStatusText(QString("Core: %1").arg(error.what()),true);
    }
}

void NativeDnsWindow::shutdownCoreForExit(){
    if(coreShutdownAttempted_)return;
    coreShutdownAttempted_=true;

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
    try{
        const auto response=nd::pipe_request(nd::core_pipe_name,nd::IpcOperation::status,{},100);
        if(response.status)throw std::runtime_error(response.payload);
        coreLaunchPending_=false;
        setStatusText("Core: "+q(response.payload),response.payload.rfind("ERROR",0)==0);
    }catch(...){
        if(coreLaunchPending_&&coreLaunchTimer_.isValid()&&coreLaunchTimer_.elapsed()<10000){
            setStatusText("Core: starting...");
        }else{
            coreLaunchPending_=false;
            setStatusText("Core: stopped");
        }
    }
}

void NativeDnsWindow::refreshLogs(){try{const auto payload=std::to_string(logSequence_)+"\t0\t"+std::to_string(static_cast<unsigned>(config_.logging.screen));auto r=nd::pipe_request(nd::core_log_pipe_name,nd::IpcOperation::logs,payload,120);if(r.status)return;QString text=q(r.payload);for(const auto& line:text.split('\n',Qt::SkipEmptyParts)){const auto fields=line.split('\t');if(fields.size()<4)continue;bool ok=false;const auto seq=fields[0].toULongLong(&ok);if(ok)logSequence_=std::max(logSequence_,seq);applyLogLine(fields.mid(3).join('\t'),fields[1].toUInt());}}catch(...) {}}
void NativeDnsWindow::applyLogLine(const QString& line,unsigned level){const QColor color=level==0?QColor(190,0,0):palette().color(QPalette::Text);QTextCharFormat format;format.setForeground(color);auto cursor=log_->textCursor();cursor.movePosition(QTextCursor::End);cursor.insertText(line+'\n',format);log_->setTextCursor(cursor);log_->ensureCursorVisible();}
void NativeDnsWindow::setStatusText(const QString& text,bool error){coreStatus_->setText(text);coreStatus_->setStyleSheet(error?"color: rgb(190,0,0);":"");}

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
