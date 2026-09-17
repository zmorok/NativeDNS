#pragma once

#include <QIcon>

enum class ActionIcon { dns_servers, rules, clear_display, restart };

QIcon makeActionIcon(ActionIcon icon, bool dark);
