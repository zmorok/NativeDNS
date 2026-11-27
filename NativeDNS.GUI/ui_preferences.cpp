#include "ui_preferences.hpp"

#include <QApplication>
#include <QColor>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QPalette>
#include <QProxyStyle>
#include <QStyleFactory>
#include <QStyleOptionMenuItem>
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
    Translation{"Interception Diagnostics", "Диагностика перехвата"},
    Translation{"Applying DNS configuration...", "Применение конфигурации DNS..."},
    Translation{"Restore the last valid backup? Choose No to reset to defaults. The "
                "unreadable file will be archived without overwriting the backup.",
                "Восстановить последнюю рабочую резервную копию? Выберите «Нет», чтобы сбросить "
                "настройки по умолчанию. Повреждённый файл будет сохранён отдельно без перезаписи "
                "резервной копии."},
    Translation{"The unreadable configuration will be archived and reset to defaults.",
                "Повреждённый файл конфигурации будет сохранён отдельно, а настройки сброшены по "
                "умолчанию."},
    Translation{"Archived unreadable configuration to: ",
                "Повреждённая конфигурация перенесена в: "},
    Translation{"Running means the mechanism is started. Verified requires a successful active "
                "UDP/IPv4 test.",
                "Работает – механизм запущен. Для подтверждения перехвата требуется успешный "
                "активный тест UDP/IPv4."},
    Translation{"Run safe interception test", "Проверить перехват"},
    Translation{"Sends one UDP/53 query to a reserved TEST-NET address with TTL 1. It may leave "
                "the computer if interception fails.",
                "Один запрос UDP/53 к зарезервированному адресу TEST-NET с TTL 1. При отказе "
                "перехвата пакет может покинуть компьютер."},
    Translation{"Interception unverified", "Перехват не проверен"},
    Translation{"Interception degraded", "Проблема перехвата"},
    Translation{
        "Interception degraded: transparent DNS capture or packet delivery reported errors.\nWhat to do: open Diagnostics -> Interception Diagnostics and click \"Run safe interception test\", check for conflicting VPN/firewall software, or click Restart.",
        "Проблема перехвата: при прозрачном перехвате или отправке DNS-пакетов возникли ошибки.\nЧто делать: откройте «Диагностика → Диагностика перехвата» и нажмите «Проверить перехват», проверьте наличие конфликтующего VPN/фаервола или нажмите «Перезапустить»."},
    Translation{
        "Offline: no active external network connection was detected.\nWhat to do: check your network adapter, Wi-Fi/Ethernet, or VPN connection. CoreHost remains running and will resume DNS resolution automatically when connectivity returns.",
        "Нет сети: активное внешнее сетевое подключение не обнаружено.\nЧто делать: проверьте сетевой адаптер, Wi-Fi/Ethernet или VPN-подключение. CoreHost продолжает работать и автоматически возобновит разрешение DNS после восстановления связи."},
    Translation{
        "Core error: DNS interception backend reported an error.\nWhat to do: open Diagnostics -> Interception Diagnostics for details or click Restart.",
        "Ошибка ядра: модуль перехвата DNS сообщил об ошибке.\nЧто делать: откройте «Диагностика → Диагностика перехвата» для просмотра подробностей или нажмите «Перезапустить»."},
    Translation{"Scheduled CoreHost launch failed: ",
                "Ошибка запуска CoreHost через планировщик: "},
    Translation{"CoreHost startup or IPC connection timed out.",
                "Истекло время запуска CoreHost или подключения IPC."},
    Translation{"Debug logging enabled after scheduled startup; early initialization used the "
                "task's logging profile.",
                "Debug включён после запуска через планировщик; ранние события записывались "
                "согласно профилю задания."},
    Translation{"Show...", "Показывать..."},
    Translation{"Filters", "Фильтры"},
    Translation{"Selected record", "Выбранная запись"},
    Translation{"Cannot save display preferences.", "Не удалось сохранить настройки отображения."},
    Translation{"Details", "Подробность"},
    Translation{"View", "Вид"},
    Translation{"Short line", "Короткая строка"},
    Translation{"Show only action...", "Показывать только действия..."},
    Translation{"Show only commands...", "Показывать служебные события..."},
    Translation{"Show only errors...", "Показывать ошибки..."},
    Translation{"Only", "Только"},
    Translation{"With", "Вместе с остальными"},
    Translation{"Cannot save log commands view.", "Не удалось сохранить вид служебных событий."},
    Translation{"Cannot save log errors view.", "Не удалось сохранить вид ошибок журнала."},
    Translation{"All", "Все"},
    Translation{"Cannot save log action filter.", "Не удалось сохранить фильтр действий журнала."},
    Translation{"Table", "Таблица"},
    Translation{"Line with details", "Строка с подробностями"},
    Translation{"Cannot save log view.", "Не удалось сохранить вид журнала."},
    Translation{"Time", "Время"},
    Translation{"Event", "Событие"},
    Translation{"Domain / type", "Домен / тип"},
    Translation{"Action", "Действие"},
    Translation{"DNS server", "DNS-сервер"},
    Translation{"Rule", "Правило"},
    Translation{"Rule: %1", "Правило: %1"},
    Translation{"Time, ms", "Время, мс"},
    Translation{"Error", "Ошибка"},
    Translation{"Cache", "Кэш"},
    Translation{"Original record", "Исходная запись"},
    Translation{"Network interfaces updated", "Обновлены сетевые интерфейсы"},
    Translation{"Changed interfaces", "Изменившиеся интерфейсы"},
    Translation{"CoreHost is running", "CoreHost работает"},
    Translation{"Selected record details", "Подробности выбранной записи"},
    Translation{"Select a record to read its complete original text.",
                "Выберите запись, чтобы прочитать её полный исходный текст."},
    Translation{"Check for updates", "Проверить обновления"},
    Translation{"Check update on start", "Проверять обновления при запуске"},
    Translation{"Cannot save update preferences.",
                "Не удалось сохранить настройки проверки обновлений."},
    Translation{"Checking for updates...", "Проверка обновлений..."},
    Translation{"Installed version: %1", "Установленная версия: %1"},
    Translation{"Release version: %1", "Версия релиза: %1"},
    Translation{"What's new", "Что нового"},
    Translation{"What's new (last successful check)", "Что нового (последняя успешная проверка)"},
    Translation{"Open release", "Открыть релиз"},
    Translation{"Update", "Обновить"},
    Translation{"Downloading update...", "Загрузка обновления..."},
    Translation{"Downloading %1...", "Загрузка %1..."},
    Translation{"Verifying integrity (SHA-256)...", "Проверка целостности (SHA-256)..."},
    Translation{"Download failed.", "Ошибка загрузки обновления."},
    Translation{"Download canceled.", "Загрузка отменена."},
    Translation{"The download timed out.", "Истекло время ожидания загрузки."},
    Translation{"The downloaded file size does not match the release manifest.",
                "Размер загруженного файла не совпадает с манифестом релиза."},
    Translation{"The downloaded file failed SHA-256 verification.",
                "Загруженный файл не прошёл проверку контрольной суммы SHA-256."},
    Translation{"Cannot save update file.", "Не удалось сохранить файл обновления."},
    Translation{"Update downloaded and verified.", "Обновление загружено и проверено."},
    Translation{"Starting updater...", "Запуск установщика обновлений..."},
    Translation{"Cannot launch the updater.", "Не удалось запустить программу обновления."},
    Translation{"Updater.exe was not found next to NativeDNS.exe.",
                "Файл Updater.exe не найден рядом с NativeDNS.exe."},
    Translation{"Cannot access the system temporary directory.",
                "Не удалось получить доступ к временной папке системы."},
    Translation{"Cannot prepare temporary updater directory.",
                "Не удалось подготовить временную папку обновления."},
    Translation{"Cannot copy Updater.exe to temporary directory.",
                "Не удалось скопировать Updater.exe во временную папку."},
    Translation{"Launching updater and closing NativeDNS...",
                "Запуск программы обновления и закрытие NativeDNS..."},
    Translation{"Automatic installation is currently supported on Windows only. Use Open release "
                "to download manually.",
                "Автоматическая установка пока поддерживается только на Windows. Используйте "
                "«Открыть релиз» для ручной загрузки."},
    Translation{"Retry", "Повторить"},
    Translation{"A new NativeDNS version is available.", "Доступна новая версия NativeDNS."},
    Translation{"NativeDNS is up to date.", "Установлена актуальная версия NativeDNS."},
    Translation{"The installed version is newer than the published release.",
                "Установленная версия новее опубликованного релиза."},
    Translation{"Could not check for updates.", "Не удалось проверить обновления."},
    Translation{"Invalid update information.", "Неверные данные об обновлении."},
    Translation{"Unsupported update information format.",
                "Неподдерживаемый формат данных об обновлении."},
    Translation{"The installed version is invalid.", "Неверный номер установленной версии."},
    Translation{"The update check timed out.", "Истекло время ожидания проверки обновлений."},
    Translation{"Update information is too large.",
                "Данные об обновлении превышают допустимый размер."},
    Translation{"The latest release does not provide update.json yet.",
                "В последнем релизе пока нет файла update.json."},
    Translation{"The update server returned HTTP %1.", "Сервер обновлений вернул HTTP %1."},
    Translation{"Could not connect to the update server. %1",
                "Не удалось подключиться к серверу обновлений. %1"},
    Translation{"Could not download update information. %1",
                "Не удалось загрузить данные об обновлении. %1"},
    Translation{"No release notes were provided.", "Описание изменений отсутствует."},
    Translation{"Import log filters", "Импорт фильтров логов"},
    Translation{"Export log filters", "Экспорт фильтров логов"},
    Translation{"Log filter configuration (*.xml)", "Конфигурация фильтров логов (*.xml)"},
    Translation{"Invalid log filter configuration.", "Неверная конфигурация фильтров логов."},
    Translation{"Filter IDs must be unique and nonempty.",
                "Идентификаторы фильтров должны быть уникальными и непустыми."},
    Translation{"Filter name must contain 1..256 characters.",
                "Имя фильтра должно содержать от 1 до 256 символов."},
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
    Translation{"Manage filters", "Управление фильтрами"},
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
    Translation{"Temporarily disable Windows encrypted DNS",
                "Временно отключать шифрование DNS Windows"},
    Translation{"Configuration saved; CoreHost confirmation is pending.",
                "Конфигурация сохранена; подтверждение от CoreHost ещё не получено."},
    Translation{"Original Windows DNS encryption is restored on Stop or Exit, or on the next start "
                "after a crash. DNS addresses and hosts are preserved.",
                "Исходное шифрование DNS Windows восстанавливается при остановке, выходе или "
                "следующем запуске после сбоя. Адреса DNS и файл hosts сохраняются."},
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
    Translation{"Add", "Добавить"},
    Translation{"Edit", "Изменить"},
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
    Translation{"Default rule must remain enabled.",
                "Правило Default должно оставаться включённым."},
    Translation{"&File", "&Файл"},
    Translation{"New Configuration", "Новая конфигурация"},
    Translation{"Import Configuration", "Импорт конфигурации"},
    Translation{"Export Configuration", "Экспорт конфигурации"},
    Translation{"Autostart", "Автозапуск"},
    Translation{"Exit", "Выход"},
    Translation{"Autostart (reselect to apply)", "Автозапуск (выберите повторно для применения)"},
    Translation{
        "Autostart registration is outdated. Click Autostart to apply the current application path.",
        "Регистрация автозапуска устарела. Нажмите «Автозапуск», чтобы применить текущий путь приложения."},
    Translation{"&Configuration", "&Конфигурация"},
    Translation{"&Advanced", "&Дополнительно"},
    Translation{"Additional modules will appear here", "Здесь появятся дополнительные модули"},
    Translation{"&Log", "&Журнал"},
    Translation{"&Diagnostics", "&Диагностика"},
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
    Translation{"&View", "&Вид"},
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
    Translation{"Collect diagnostic report...", "Собрать диагностический отчёт..."},
    Translation{"Domain to test:", "Домен для проверки:"},
    Translation{"Collecting diagnostic report...", "Сбор диагностического отчёта..."},
    Translation{"Diagnostic collection failed. Check the logs folder.",
                "Не удалось собрать диагностику. Проверьте папку logs."},
    Translation{"Diagnostic capture", "Диагностическая запись"},
    Translation{"NativeDNS is already running in another mode. Exit it before switching between "
                "normal and diagnostic mode.",
                "NativeDNS уже работает в другом режиме. Завершите приложение перед переключением "
                "обычного и диагностического режима."},
    Translation{"Configuration file: ", "Файл конфигурации: "},
    Translation{"CoreHost did not confirm the expected configuration",
                "CoreHost не подтвердил ожидаемую конфигурацию"},
    Translation{"Configuration", "Конфигурация"},
    Translation{"Import", "Импорт"},
    Translation{"Export", "Экспорт"},
    Translation{"Core: unknown", "Ядро: состояние неизвестно"},
    Translation{"Core: starting...", "Ядро: запуск..."},
    Translation{"Core: checking network...", "Ядро: проверка сети..."},
    Translation{"Core: restarting...", "Ядро: перезапуск..."},
    Translation{"Core: stopped", "Ядро: остановлено"},
    Translation{"Core: control unavailable", "Ядро: управление недоступно"},
    Translation{"Connection to CoreHost was lost.",
                "Связь с CoreHost потеряна или ядро сообщило об ошибке."},
    Translation{"Core control is unavailable. Terminate NativeDNS and CoreHost, or close this "
                "window to keep waiting for recovery.",
                "Завершите NativeDNS вместе с CoreHost или закройте это окно, чтобы продолжить "
                "ожидание восстановления."},
    Translation{"Terminate application", "Завершить работу"},
    Translation{"Last CoreHost response:", "Последний ответ CoreHost:"},
    Translation{"None", "Нет"},
    Translation{"CoreHost process lock:", "Блокировка процесса CoreHost:"},
    Translation{"Held", "Удерживается"},
    Translation{"Released", "Освобождена"},
    Translation{"Core: terminating...", "Ядро: принудительное завершение..."},
    Translation{"Core: shutting down...", "Ядро: завершение работы..."},
    Translation{
        "CoreHost could not be terminated.",
        "Не удалось завершить CoreHost. NativeDNS остаётся открытым для повторной попытки."},
    Translation{"CoreHost is running but its control channel is unavailable.",
                "CoreHost работает, но канал управления недоступен."},
    Translation{
        "CoreHost did not exit. NativeDNS remains open so shutdown can be retried.",
        "CoreHost не завершился. NativeDNS остаётся открытым для повторной попытки выхода."},
    Translation{"Core: waiting for network", "Ядро: ожидание сети"},
    Translation{"Offline", "Нет сети"},
    Translation{
        "Internet connection lost. DNS resolution may fail; core continues running offline.",
        "Подключение к интернету потеряно. DNS-запросы могут завершаться ошибкой; ядро продолжает "
        "работать без сети."},
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
class NativeDnsStyle final : public QProxyStyle {
public:
    NativeDnsStyle() : QProxyStyle(QStyleFactory::create("Fusion")) {
    }

    QSize sizeFromContents(ContentsType type,
                           const QStyleOption* option,
                           const QSize& size,
                           const QWidget* widget) const override {
        auto result = QProxyStyle::sizeFromContents(type, option, size, widget);
        if (type == CT_MenuItem && hasMenuWarning(option, widget))
            result.rwidth() += 24;
        return result;
    }

    void drawControl(ControlElement element,
                     const QStyleOption* option,
                     QPainter* painter,
                     const QWidget* widget) const override {
        QProxyStyle::drawControl(element, option, painter, widget);
        if (element != CE_MenuItem || !hasMenuWarning(option, widget))
            return;

        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        const QRectF r(option->rect.right() - 22.0, option->rect.center().y() - 7.5, 15.0, 15.0);
        QPainterPath triangle;
        triangle.moveTo(r.center().x(), r.top() + 1.0);
        triangle.lineTo(r.right() - 1.0, r.bottom() - 1.0);
        triangle.lineTo(r.left() + 1.0, r.bottom() - 1.0);
        triangle.closeSubpath();
        painter->setPen(QPen(QColor(140, 95, 0), 1.1, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        painter->setBrush(QColor(245, 184, 0));
        painter->drawPath(triangle);

        const QColor markColor(32, 24, 0);
        painter->setPen(QPen(markColor, 1.6, Qt::SolidLine, Qt::RoundCap));
        painter->drawLine(QPointF(r.center().x(), r.top() + 5.2),
                          QPointF(r.center().x(), r.top() + 9.6));
        painter->setPen(Qt::NoPen);
        painter->setBrush(markColor);
        painter->drawEllipse(QPointF(r.center().x(), r.top() + 12.1), 0.9, 0.9);
        painter->restore();
    }

private:
    static bool hasMenuWarning(const QStyleOption* option, const QWidget* widget) {
        const auto* menu = qobject_cast<const QMenu*>(widget);
        const auto* menuItem = qstyleoption_cast<const QStyleOptionMenuItem*>(option);
        if (!menu || !menuItem || menuItem->menuItemType != QStyleOptionMenuItem::Normal)
            return false;
        const QAction* action = menu->actionAt(option->rect.center());
        if (!action) {
            for (const auto* candidate : menu->actions()) {
                if (!candidate->isSeparator() && candidate->text() == menuItem->text) {
                    action = candidate;
                    break;
                }
            }
        }
        return action && action->property("warningIcon").toBool();
    }
};
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
    application.setStyle(new NativeDnsStyle());
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
               "QToolTip { background-color: #373739; color: #e8e8e8; border: 1px solid #5d5d60; "
               "padding: 4px; }"
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
               "padding: 2px 7px; }"
               "QToolTip { background-color: #ffffff; color: #202020; border: 1px solid #a6adb7; "
               "padding: 4px; }");
}
