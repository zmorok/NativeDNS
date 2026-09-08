#include "platform_launcher.hpp"
#include <QProcess>
#include <QStandardPaths>

bool launchNativeDnsCore(const QString& executable,const QStringList& arguments,bool elevated,QString* error){
    QString program=executable;QStringList args=arguments;
    if(elevated){const auto pkexec=QStandardPaths::findExecutable("pkexec");if(pkexec.isEmpty()){if(error)*error="pkexec is required for transparent DNS interception";return false;}args.prepend(executable);program=pkexec;}
    if(!QProcess::startDetached(program,args)){if(error)*error="Cannot start NativeDNSCoreHost";return false;}return true;
}

bool runNativeDnsHelper(const QString& executable,const QStringList& arguments,bool elevated,int* exitCode,QString* error){
    QString program=executable;
    QStringList args=arguments;
    if(elevated){
        const auto pkexec=QStandardPaths::findExecutable("pkexec");
        if(pkexec.isEmpty()){
            if(error)*error="pkexec is required for elevated NativeDNS helper operations";
            return false;
        }
        args.prepend(executable);
        program=pkexec;
    }

    QProcess process;
    process.start(program,args);
    if(!process.waitForStarted()){
        if(error)*error="Cannot start NativeDNS helper";
        return false;
    }
    if(!process.waitForFinished(-1)){
        if(error)*error="NativeDNS helper did not finish";
        return false;
    }
    if(exitCode)*exitCode=process.exitCode();
    return process.exitStatus()==QProcess::NormalExit;
}
