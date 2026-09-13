#pragma once

#include <QString>

class QApplication;

enum class UiLanguage { english, russian };

UiLanguage uiLanguage();
void setUiLanguage(UiLanguage language);
QString uiText(const char* english);
void applyUiTheme(QApplication& application, bool dark);
