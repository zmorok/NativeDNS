#include "ui_preferences.hpp"

#include <QApplication>
#include <QColor>
#include <QPalette>
#include <QStyleFactory>
#include <array>

namespace {
UiLanguage currentLanguage = UiLanguage::english;

QPalette lightPalette() {
    QPalette palette;
    const QColor window(245, 245, 245);
    const QColor base(255, 255, 255);
    const QColor text(32, 32, 32);
    const QColor disabledText(125, 125, 125);
    palette.setColor(QPalette::Window, window);
    palette.setColor(QPalette::WindowText, text);
    palette.setColor(QPalette::Base, base);
    palette.setColor(QPalette::AlternateBase, QColor(248, 248, 248));
    palette.setColor(QPalette::Text, text);
    palette.setColor(QPalette::Button, window);
    palette.setColor(QPalette::ButtonText, text);
    palette.setColor(QPalette::ToolTipBase, base);
    palette.setColor(QPalette::ToolTipText, text);
    palette.setColor(QPalette::BrightText, QColor(190, 0, 0));
    palette.setColor(QPalette::Link, QColor(0, 102, 204));
    palette.setColor(QPalette::Highlight, QColor(0, 120, 215));
    palette.setColor(QPalette::HighlightedText, Qt::white);
    palette.setColor(QPalette::PlaceholderText, QColor(120, 120, 120));
    palette.setColor(QPalette::Disabled, QPalette::WindowText, disabledText);
    palette.setColor(QPalette::Disabled, QPalette::Text, disabledText);
    palette.setColor(QPalette::Disabled, QPalette::Base, QColor(226, 226, 226));
    palette.setColor(QPalette::Disabled, QPalette::Button, QColor(226, 226, 226));
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, disabledText);
    palette.setColor(QPalette::Disabled, QPalette::HighlightedText, QColor(230, 230, 230));
    return palette;
}

QPalette darkPalette() {
    QPalette palette;
    const QColor window(37, 37, 38);
    const QColor base(30, 30, 30);
    const QColor text(232, 232, 232);
    const QColor disabledText(135, 135, 135);
    palette.setColor(QPalette::Window, window);
    palette.setColor(QPalette::WindowText, text);
    palette.setColor(QPalette::Base, base);
    palette.setColor(QPalette::AlternateBase, QColor(45, 45, 46));
    palette.setColor(QPalette::Text, text);
    palette.setColor(QPalette::Button, QColor(51, 51, 53));
    palette.setColor(QPalette::ButtonText, text);
    palette.setColor(QPalette::ToolTipBase, QColor(55, 55, 57));
    palette.setColor(QPalette::ToolTipText, text);
    palette.setColor(QPalette::BrightText, QColor(255, 105, 105));
    palette.setColor(QPalette::Link, QColor(86, 156, 214));
    palette.setColor(QPalette::Highlight, QColor(0, 120, 215));
    palette.setColor(QPalette::HighlightedText, Qt::white);
    palette.setColor(QPalette::PlaceholderText, QColor(155, 155, 155));
    palette.setColor(QPalette::Disabled, QPalette::WindowText, disabledText);
    palette.setColor(QPalette::Disabled, QPalette::Text, disabledText);
    palette.setColor(QPalette::Disabled, QPalette::Base, QColor(46, 46, 48));
    palette.setColor(QPalette::Disabled, QPalette::Button, QColor(46, 46, 48));
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, disabledText);
    palette.setColor(QPalette::Disabled, QPalette::HighlightedText, QColor(175, 175, 175));
    return palette;
}

struct Translation {
    const char* english;
    const char* russian;
};
constexpr std::array translations{
    Translation{"Import log filters", "Импорт фильтров логов"},
    Translation{"Export log filters", "Экспорт фильтров логов"},
    Translation{"Log filter configuration (*.xml)", "Конфигурация фильтров логов (*.xml)"},
    Translation{"Invalid log filter configuration.", "Неверная конфигурация фильтров логов."},
    Translation{"Filter IDs must be unique and nonempty.", "Идентификаторы фильтров должны быть уникальными и непустыми."},
    Translation{"Filter name must contain 1..256 characters.", "Имя фильтра должно содержать от 1 до 256 символов."},
    Translation{"Filter configuration exceeds 1 MiB.", "Конфигурация фильтров превышает 1 МиБ."},
    Translation{"Log filter help", "Справка по фильтрам логов"},
    Translation{"Manage log filters", "Управление фильтрами логов"},
    Translation{"Filter name", "Имя фильтра"},
    Translation{"Filter expression", "Выражение фильтра"},
    Translation{"Help", "Справка"},
    Translation{"New filter", "Новый фильтр"},
    Translation{"Maximum 256 saved filters.", "Можно сохранить не более 256 фильтров."},
    Translation{"Invalid filter", "Неверный фильтр"},
    Translation{"Filter name must not be empty.", "Имя фильтра не должно быть пустым."},
    Translation{"Filter %1: %2", "Фильтр %1: %2"},
    Translation{"Saved log filters", "Сохранённые фильтры логов"},
    Translation{"Apply filter (Enter)", "Применить фильтр (Enter)"},
    Translation{"Shown: %1 of %2", "Показано: %1 из %2"},
    Translation{"The buffer retains the latest 2000 received log records.",
                "Буфер хранит последние 2000 полученных записей лога."},
    Translation{"Cannot save log filters.", "Не удалось сохранить фильтры логов."},
    Translation{"Save this filter", "Сохранить этот фильтр"},
    Translation{"Delete this filter", "Удалить этот фильтр"},
    Translation{"Manage filters...", "Управление фильтрами..."},
    Translation{"Filter name:", "Имя фильтра:"},
    Translation{"All logs", "Все записи"},
    Translation{
        "Use &&, ||, ! and parentheses. Empty input shows all logs. Ctrl+/ focuses this field.",
        "Используйте &&, ||, ! и скобки. Пустое поле показывает все записи. Ctrl+/ переводит фокус "
        "в это поле."},
    Translation{"Filter is too long (maximum 4096 characters).",
                "Фильтр слишком длинный (не более 4096 символов)."},
    Translation{"At character %1.", "В позиции %1."},
    Translation{"Expected && or || between conditions.", "Между условиями нужны && или ||."},
    Translation{"Too many filter conditions (maximum 128).",
                "Слишком много условий в фильтре (не более 128 узлов)."},
    Translation{"Filter nesting is too deep (maximum 32).",
                "Слишком большая вложенность фильтра (не более 32 уровней)."},
    Translation{"Expected a closing parenthesis.", "Ожидается закрывающая скобка."},
    Translation{"Unknown field. Use addr, dns_type, rule, err or action.",
                "Неизвестное поле. Используйте addr, dns_type, rule, err или action."},
    Translation{"Expected = after the field name.", "После имени поля ожидается =."},
    Translation{"Put the value in double quotes.", "Заключите значение в двойные кавычки."},
    Translation{"Incomplete escape sequence.", "Незавершённая escape-последовательность."},
    Translation{"Only double quotes and backslashes can be escaped.",
                "Экранировать можно только двойные кавычки и обратный слеш."},
    Translation{"Expected a closing double quote.", "Ожидается закрывающая двойная кавычка."},
    Translation{"The field value must not be empty.", "Значение поля не должно быть пустым."},
    Translation{"Action must be process, block or bypass.",
                "Действие должно быть process, block или bypass."},
    Translation{"DNS type number must be 0..65535.",
                "Номер типа DNS должен быть в диапазоне 0..65535."},
    Translation{"About", "О программе"},
    Translation{"Version", "Версия"},
    Translation{"Cross-platform DNS client", "Кроссплатформенный DNS-клиент"},
    Translation{"GitHub repository", "Репозиторий GitHub"},
    Translation{"DNS Servers", "DNS-серверы"},
    Translation{"Add DNS Server", "Добавление DNS-сервера"},
    Translation{"New DNS Server", "Новый DNS-сервер"},
    Translation{"Name:", "Имя:"},
    Translation{"Protocol:", "Протокол:"},
    Translation{"IP:", "IP:"},
    Translation{"Port:", "Порт:"},
    Translation{"Hostname:", "Имя хоста:"},
    Translation{"URL:", "URL:"},
    Translation{"Bootstrap:", "Bootstrap:"},
    Translation{"Public key:", "Публичный ключ:"},
    Translation{"Provider:", "Провайдер:"},
    Translation{"Relay:", "Ретранслятор:"},
    Translation{"Enabled", "Включено"},
    Translation{"Name", "Имя"},
    Translation{"DNSSEC supported", "Поддерживает DNSSEC"},
    Translation{"Add...", "Добавить..."},
    Translation{"Edit...", "Изменить..."},
    Translation{"Remove", "Удалить"},
    Translation{"Check", "Проверить"},
    Translation{"Check All", "Проверить все"},
    Translation{"Close", "Закрыть"},
    Translation{"OK", "ОК"},
    Translation{"Cancel", "Отмена"},
    Translation{"Protocol", "Протокол"},
    Translation{"Address", "Адрес"},
    Translation{"Status", "Состояние"},
    Translation{"Not tested", "Не проверен"},
    Translation{"Testing...", "Проверка..."},
    Translation{"Default Rule", "Правило по умолчанию"},
    Translation{"DNS Rule", "DNS-правило"},
    Translation{"Hostnames:", "Доменные имена:"},
    Translation{"Action:", "Действие:"},
    Translation{"DNS Server:", "DNS-сервер:"},
    Translation{"Block mode:", "Режим блокировки:"},
    Translation{"Original/System", "Исходный/системный"},
    Translation{"Silent drop", "Без ответа"},
    Translation{"process", "обрабатывать"},
    Translation{"bypass", "обходить"},
    Translation{"block", "блокировать"},
    Translation{"Rules", "Правила"},
    Translation{"Action", "Действие"},
    Translation{"Hostnames", "Доменные имена"},
    Translation{"DNS Server", "DNS-сервер"},
    Translation{"Up", "Вверх"},
    Translation{"Down", "Вниз"},
    Translation{"Clone", "Копировать"},
    Translation{"New Rule", "Новое правило"},
    Translation{"Default rule cannot be removed.", "Правило по умолчанию нельзя удалить."},
    Translation{"&File", "&Файл"},
    Translation{"New Configuration", "Новая конфигурация"},
    Translation{"Import Configuration...", "Импорт конфигурации..."},
    Translation{"Export Configuration...", "Экспорт конфигурации..."},
    Translation{"Autostart", "Автозапуск"},
    Translation{"Exit", "Выход"},
    Translation{"Autostart (repair required)", "Автозапуск (требуется исправление)"},
    Translation{"&Configuration", "&Конфигурация"},
    Translation{"DNS Servers...", "DNS-серверы..."},
    Translation{"Rules...", "Правила..."},
    Translation{"&Advanced", "&Дополнительно"},
    Translation{"Additional modules will appear here", "Здесь появятся дополнительные модули"},
    Translation{"&Log", "&Журнал"},
    Translation{"Clear Display", "Очистить экран"},
    Translation{"Restart", "Перезапустить"},
    Translation{"Screen", "Экран"},
    Translation{"Errors Only", "Только ошибки"},
    Translation{"Normal", "Обычный"},
    Translation{"Verbose", "Подробный"},
    Translation{"Debug", "Отладка"},
    Translation{"Write diagnostic file", "Записывать файл диагностики"},
    Translation{"File level", "Уровень файла"},
    Translation{"Clear Diagnostic File", "Очистить файл диагностики"},
    Translation{"Open Log Folder", "Открыть папку журнала"},
    Translation{"&Window", "&Окно"},
    Translation{"Hide to tray", "Сворачивать в трей"},
    Translation{"&Other", "&Другое"},
    Translation{"Language", "Язык"},
    Translation{"English", "English"},
    Translation{"Русский", "Русский"},
    Translation{"Theme", "Тема"},
    Translation{"Light", "Светлая"},
    Translation{"Dark", "Тёмная"},
    Translation{"&Help", "&Справка"},
    Translation{"About NativeDNS", "О NativeDNS"},
    Translation{"Open", "Открыть"},
    Translation{"Open NativeDNS", "Открыть NativeDNS"},
    Translation{"Create a new configuration?", "Создать новую конфигурацию?"},
    Translation{"Remove selected DNS server?", "Удалить выбранный DNS-сервер?"},
    Translation{"Configuration imported.", "Конфигурация импортирована."},
    Translation{"Configuration", "Конфигурация"},
    Translation{"Import", "Импорт"},
    Translation{"Export", "Экспорт"},
    Translation{"Core: unknown", "Ядро: состояние неизвестно"},
    Translation{"Core: starting...", "Ядро: запуск..."},
    Translation{"Core: checking network...", "Ядро: проверка сети..."},
    Translation{"Core: restarting...", "Ядро: перезапуск..."},
    Translation{"Core: stopped", "Ядро: остановлено"},
    Translation{"Core: waiting for network", "Ядро: ожидание сети"},
    Translation{"Offline", "Нет сети"},
    Translation{"Internet connection lost. DNS resolution may fail; core startup will wait for the "
                "network.",
                "Подключение к интернету потеряно. DNS-запросы могут завершаться ошибкой; запуск "
                "ядра дождётся сети."},
    Translation{"Internet connection restored.", "Подключение к интернету восстановлено."},
    Translation{"DNS configuration reloaded without stopping the core.",
                "Конфигурация DNS обновлена без остановки ядра."},
    Translation{"Reloading DNS configuration...", "Обновление конфигурации DNS..."},
    Translation{"Cannot resolve secure DNS upstream: ",
                "Не удаётся определить адрес защищённого DNS-сервера: "},
    Translation{"DNS configuration reload failed: ", "Ошибка обновления конфигурации DNS: "},
    Translation{"Core startup failed: ", "Ошибка запуска ядра: "},
    Translation{"Core startup timed out. Check network and DNS configuration.",
                "Время ожидания запуска ядра истекло. Проверьте сеть и конфигурацию DNS."},
    Translation{"Core: Unknown", "Ядро: состояние неизвестно"},
    Translation{"Core: Error", "Ядро: ошибка"},
    Translation{"Core: Running", "Ядро: работает"},
    Translation{"Core: Stopped", "Ядро: остановлено"},
    Translation{"Core: Starting", "Ядро: запускается"},
    Translation{"Transparent", "Прозрачный перехват"},
    Translation{"Local proxy", "Локальный прокси"},
    Translation{"Active", "Активен"},
    Translation{"Inactive", "Неактивен"},
    Translation{"Mode", "Режим"},
    Translation{"DNS port", "Порт DNS"},
    Translation{"UDP", "UDP"},
    Translation{"TCP", "TCP"},
    Translation{"Anonymized DNSCrypt", "Анонимизированный DNSCrypt"}};
} // namespace

UiLanguage uiLanguage() {
    return currentLanguage;
}
void setUiLanguage(UiLanguage language) {
    currentLanguage = language;
}

QString uiText(const char* english) {
    if (currentLanguage == UiLanguage::russian) {
        for (const auto& entry : translations)
            if (QString::fromUtf8(entry.english) == QString::fromUtf8(english))
                return QString::fromUtf8(entry.russian);
    }
    return QString::fromUtf8(english);
}

void applyUiTheme(QApplication& application, bool dark) {
    application.setStyle(QStyleFactory::create("Fusion"));
    application.setPalette(dark ? darkPalette() : lightPalette());
    application.setStyleSheet(
        dark ? "QMenuBar, QToolBar, QStatusBar { background-color: #252526; color: #e8e8e8; }"
               "QMenu { background-color: #333335; color: #e8e8e8; border: 1px solid #555557; }"
               "QMenuBar::item:selected, QMenu::item:selected { background-color: #0078d7; color: "
               "#ffffff; }"
               "QMenu::item:disabled, QToolButton:disabled { color: #878787; }"
               "QLineEdit, QPlainTextEdit, QComboBox { background-color: #1e1e1e; border: 1px "
               "solid #5d5d60; }"
               "QLineEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled { "
               "background-color: #2e2e30; color: #878787; border-color: #3d3d40; }"
               "QToolButton:hover, QPushButton:hover, QTabBar::tab:hover { background-color: "
               "#454547; border-color: #777779; }"
               "QTableView::item:hover, QListView::item:hover, QTreeView::item:hover { "
               "background-color: #3f4f5f; color: #ffffff; }"
               "QToolBar#mainToolBar QToolButton { min-height: 64px; min-width: 86px; "
               "padding: 2px 7px; }"
             : "QMenuBar, QMenu, QToolBar, QToolButton, QStatusBar { color: #202020; }"
               "QMenuBar, QToolBar, QStatusBar { background-color: #f5f5f5; }"
               "QMenu { background-color: #ffffff; }"
               "QMenuBar::item:selected, QMenu::item:selected { background-color: #0078d7; color: "
               "#ffffff; }"
               "QMenu::item:disabled, QToolButton:disabled { color: #7d7d7d; }"
               "QLineEdit, QPlainTextEdit, QComboBox { background-color: #ffffff; border: 1px "
               "solid #8a8a8a; }"
               "QLineEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled { "
               "background-color: #e2e2e2; color: #7d7d7d; border-color: #c4c4c4; }"
               "QToolButton:hover, QPushButton:hover, QTabBar::tab:hover { background-color: "
               "#dcecf9; border-color: #7eb4dd; }"
               "QTableView::item:hover, QListView::item:hover, QTreeView::item:hover { "
               "background-color: #e5f1fb; color: #202020; }"
               "QToolBar#mainToolBar QToolButton { min-height: 64px; min-width: 86px; "
               "padding: 2px 7px; }");
}
