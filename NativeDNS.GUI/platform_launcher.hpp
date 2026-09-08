#pragma once
#include <QString>
#include <QStringList>

bool launchNativeDnsCore(const QString& executable,const QStringList& arguments,bool elevated,QString* error);
bool runNativeDnsHelper(const QString& executable,const QStringList& arguments,bool elevated,int* exitCode,QString* error);
