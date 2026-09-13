#include "ui_preferences.hpp"

#include <QApplication>
#include <QColor>
#include <QPalette>
#include <QStyleFactory>
#include <array>

namespace {
UiLanguage currentLanguage=UiLanguage::english;

QPalette lightPalette(){
    QPalette palette;
    const QColor window(245,245,245);
    const QColor base(255,255,255);
    const QColor text(32,32,32);
    const QColor disabledText(125,125,125);
    palette.setColor(QPalette::Window,window);
    palette.setColor(QPalette::WindowText,text);
    palette.setColor(QPalette::Base,base);
    palette.setColor(QPalette::AlternateBase,QColor(248,248,248));
    palette.setColor(QPalette::Text,text);
    palette.setColor(QPalette::Button,window);
    palette.setColor(QPalette::ButtonText,text);
    palette.setColor(QPalette::ToolTipBase,base);
    palette.setColor(QPalette::ToolTipText,text);
    palette.setColor(QPalette::BrightText,QColor(190,0,0));
    palette.setColor(QPalette::Link,QColor(0,102,204));
    palette.setColor(QPalette::Highlight,QColor(0,120,215));
    palette.setColor(QPalette::HighlightedText,Qt::white);
    palette.setColor(QPalette::PlaceholderText,QColor(120,120,120));
    palette.setColor(QPalette::Disabled,QPalette::WindowText,disabledText);
    palette.setColor(QPalette::Disabled,QPalette::Text,disabledText);
    palette.setColor(QPalette::Disabled,QPalette::Base,QColor(226,226,226));
    palette.setColor(QPalette::Disabled,QPalette::Button,QColor(226,226,226));
    palette.setColor(QPalette::Disabled,QPalette::ButtonText,disabledText);
    palette.setColor(QPalette::Disabled,QPalette::HighlightedText,QColor(230,230,230));
    return palette;
}

QPalette darkPalette(){
    QPalette palette;
    const QColor window(37,37,38);
    const QColor base(30,30,30);
    const QColor text(232,232,232);
    const QColor disabledText(135,135,135);
    palette.setColor(QPalette::Window,window);
    palette.setColor(QPalette::WindowText,text);
    palette.setColor(QPalette::Base,base);
    palette.setColor(QPalette::AlternateBase,QColor(45,45,46));
    palette.setColor(QPalette::Text,text);
    palette.setColor(QPalette::Button,QColor(51,51,53));
    palette.setColor(QPalette::ButtonText,text);
    palette.setColor(QPalette::ToolTipBase,QColor(55,55,57));
    palette.setColor(QPalette::ToolTipText,text);
    palette.setColor(QPalette::BrightText,QColor(255,105,105));
    palette.setColor(QPalette::Link,QColor(86,156,214));
    palette.setColor(QPalette::Highlight,QColor(0,120,215));
    palette.setColor(QPalette::HighlightedText,Qt::white);
    palette.setColor(QPalette::PlaceholderText,QColor(155,155,155));
    palette.setColor(QPalette::Disabled,QPalette::WindowText,disabledText);
    palette.setColor(QPalette::Disabled,QPalette::Text,disabledText);
    palette.setColor(QPalette::Disabled,QPalette::Base,QColor(46,46,48));
    palette.setColor(QPalette::Disabled,QPalette::Button,QColor(46,46,48));
    palette.setColor(QPalette::Disabled,QPalette::ButtonText,disabledText);
    palette.setColor(QPalette::Disabled,QPalette::HighlightedText,QColor(175,175,175));
    return palette;
}

struct Translation { const char* english; const char* russian; };
constexpr std::array translations{
    Translation{"About","О программе"},
    Translation{"Version","Версия"},
    Translation{"Cross-platform DNS client","Кроссплатформенный DNS-клиент"},
    Translation{"GitHub repository","Репозиторий GitHub"},
    Translation{"DNS Servers","DNS-серверы"},
    Translation{"Add DNS Server","Добавление DNS-сервера"},
    Translation{"New DNS Server","Новый DNS-сервер"},
    Translation{"Name:","Имя:"}, Translation{"Protocol:","Протокол:"},
    Translation{"IP:","IP:"}, Translation{"Port:","Порт:"},
    Translation{"Hostname:","Имя хоста:"}, Translation{"URL:","URL:"},
    Translation{"Bootstrap:","Bootstrap:"}, Translation{"Public key:","Публичный ключ:"},
    Translation{"Provider:","Провайдер:"}, Translation{"Relay:","Ретранслятор:"},
    Translation{"Enabled","Включено"}, Translation{"Name","Имя"}, Translation{"DNSSEC supported","Поддерживает DNSSEC"},
    Translation{"Add...","Добавить..."}, Translation{"Edit...","Изменить..."},
    Translation{"Remove","Удалить"}, Translation{"Check","Проверить"},
    Translation{"Close","Закрыть"}, Translation{"OK","ОК"}, Translation{"Cancel","Отмена"},
    Translation{"Protocol","Протокол"},
    Translation{"Address","Адрес"}, Translation{"Status","Состояние"},
    Translation{"Not tested","Не проверен"}, Translation{"Testing...","Проверка..."},
    Translation{"Default Rule","Правило по умолчанию"}, Translation{"DNS Rule","DNS-правило"},
    Translation{"Hostnames:","Доменные имена:"}, Translation{"Action:","Действие:"},
    Translation{"DNS Server:","DNS-сервер:"}, Translation{"Block mode:","Режим блокировки:"},
    Translation{"Original/System","Исходный/системный"}, Translation{"Silent drop","Без ответа"},
    Translation{"process","обрабатывать"}, Translation{"bypass","обходить"}, Translation{"block","блокировать"},
    Translation{"Rules","Правила"}, Translation{"Action","Действие"}, Translation{"Hostnames","Доменные имена"},
    Translation{"DNS Server","DNS-сервер"}, Translation{"Up","Вверх"},
    Translation{"Down","Вниз"}, Translation{"Clone","Копировать"},
    Translation{"New Rule","Новое правило"},
    Translation{"Default rule cannot be removed.","Правило по умолчанию нельзя удалить."},
    Translation{"&File","&Файл"}, Translation{"New Configuration","Новая конфигурация"},
    Translation{"Import Configuration...","Импорт конфигурации..."},
    Translation{"Export Configuration...","Экспорт конфигурации..."},
    Translation{"Autostart","Автозапуск"}, Translation{"Exit","Выход"},
    Translation{"Autostart (repair required)","Автозапуск (требуется исправление)"},
    Translation{"&Configuration","&Конфигурация"}, Translation{"DNS Servers...","DNS-серверы..."},
    Translation{"Rules...","Правила..."}, Translation{"&Advanced","&Дополнительно"},
    Translation{"Additional modules will appear here","Здесь появятся дополнительные модули"},
    Translation{"&Log","&Журнал"}, Translation{"Clear Display","Очистить экран"},
    Translation{"Screen","Экран"}, Translation{"Errors Only","Только ошибки"},
    Translation{"Normal","Обычный"}, Translation{"Verbose","Подробный"},
    Translation{"Debug","Отладка"}, Translation{"Write diagnostic file","Записывать файл диагностики"},
    Translation{"File level","Уровень файла"}, Translation{"Clear Diagnostic File","Очистить файл диагностики"},
    Translation{"Open Log Folder","Открыть папку журнала"}, Translation{"&Window","&Окно"},
    Translation{"Hide to tray","Сворачивать в трей"}, Translation{"&Other","&Другое"},
    Translation{"Language","Язык"}, Translation{"English","English"}, Translation{"Русский","Русский"},
    Translation{"Theme","Тема"}, Translation{"Light","Светлая"}, Translation{"Dark","Тёмная"},
    Translation{"&Help","&Справка"}, Translation{"About NativeDNS","О NativeDNS"},
    Translation{"Open","Открыть"}, Translation{"Create a new configuration?","Создать новую конфигурацию?"},
    Translation{"Remove selected DNS server?","Удалить выбранный DNS-сервер?"},
    Translation{"Configuration imported.","Конфигурация импортирована."},
    Translation{"Configuration","Конфигурация"}, Translation{"Import","Импорт"},
    Translation{"Export","Экспорт"}, Translation{"Core: unknown","Ядро: состояние неизвестно"},
    Translation{"Core: starting...","Ядро: запуск..."}, Translation{"Core: restarting...","Ядро: перезапуск..."},
    Translation{"Core: stopped","Ядро: остановлено"}, Translation{"Core: Unknown","Ядро: состояние неизвестно"},
    Translation{"Core: Error","Ядро: ошибка"}, Translation{"Core: Running","Ядро: работает"},
    Translation{"Core: Stopped","Ядро: остановлено"}, Translation{"Core: Starting","Ядро: запускается"},
    Translation{"Transparent","Прозрачный перехват"}, Translation{"Local proxy","Локальный прокси"},
    Translation{"Active","Активен"}, Translation{"Inactive","Неактивен"},
    Translation{"Mode","Режим"}, Translation{"DNS port","Порт DNS"}, Translation{"UDP","UDP"}, Translation{"TCP","TCP"},
    Translation{"Anonymized DNSCrypt","Анонимизированный DNSCrypt"}
};
}

UiLanguage uiLanguage(){return currentLanguage;}
void setUiLanguage(UiLanguage language){currentLanguage=language;}

QString uiText(const char* english){
    if(currentLanguage==UiLanguage::russian){
        for(const auto& entry:translations)if(QString::fromUtf8(entry.english)==QString::fromUtf8(english))return QString::fromUtf8(entry.russian);
    }
    return QString::fromUtf8(english);
}

void applyUiTheme(QApplication& application,bool dark){
    application.setStyle(QStyleFactory::create("Fusion"));
    application.setPalette(dark?darkPalette():lightPalette());
    application.setStyleSheet(dark?
        "QMenuBar, QToolBar, QStatusBar { background-color: #252526; color: #e8e8e8; }"
        "QMenu { background-color: #333335; color: #e8e8e8; border: 1px solid #555557; }"
        "QMenuBar::item:selected, QMenu::item:selected { background-color: #0078d7; color: #ffffff; }"
        "QMenu::item:disabled, QToolButton:disabled { color: #878787; }"
        "QLineEdit, QPlainTextEdit, QComboBox { background-color: #1e1e1e; border: 1px solid #5d5d60; }"
        "QLineEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled { background-color: #2e2e30; color: #878787; border-color: #3d3d40; }"
        "QToolButton:hover, QPushButton:hover, QTabBar::tab:hover { background-color: #454547; border-color: #777779; }"
        "QTableView::item:hover, QListView::item:hover, QTreeView::item:hover { background-color: #3f4f5f; color: #ffffff; }"
        "QComboBox QAbstractItemView::item:selected { background-color: #0078d7; color: #ffffff; }"
        "QToolBar#mainToolBar QToolButton { min-height: 42px; padding-left: 12px; padding-right: 12px; }"
      : "QMenuBar, QMenu, QToolBar, QToolButton, QStatusBar { color: #202020; }"
        "QMenuBar, QToolBar, QStatusBar { background-color: #f5f5f5; }"
        "QMenu { background-color: #ffffff; }"
        "QMenuBar::item:selected, QMenu::item:selected { background-color: #0078d7; color: #ffffff; }"
        "QMenu::item:disabled, QToolButton:disabled { color: #7d7d7d; }"
        "QLineEdit, QPlainTextEdit, QComboBox { background-color: #ffffff; border: 1px solid #8a8a8a; }"
        "QLineEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled { background-color: #e2e2e2; color: #7d7d7d; border-color: #c4c4c4; }"
        "QToolButton:hover, QPushButton:hover, QTabBar::tab:hover { background-color: #dcecf9; border-color: #7eb4dd; }"
        "QTableView::item:hover, QListView::item:hover, QTreeView::item:hover { background-color: #e5f1fb; color: #202020; }"
        "QComboBox QAbstractItemView::item:selected { background-color: #0078d7; color: #ffffff; }"
        "QToolBar#mainToolBar QToolButton { min-height: 42px; padding-left: 12px; padding-right: 12px; }");
}
