#ifndef StageDir
  #error StageDir must point to the staged NativeDNS portable directory
#endif
#ifndef OutputDir
  #error OutputDir must point to the installer output directory
#endif
#ifndef Configuration
  #define Configuration "Release"
#endif
#ifndef AppVersion
  #error AppVersion must be provided by the build script
#endif

#if Configuration == "Debug"
  #define ConfigurationSuffix "-debug"
#else
  #define ConfigurationSuffix ""
#endif

[Setup]
AppId={{2F47E185-E56B-42F0-A85F-D6F276F3AF6B}
AppName=NativeDNS
AppVersion={#AppVersion}
AppPublisher=NativeDNS
DefaultDirName={autopf}\NativeDNS
DefaultGroupName=NativeDNS
DisableProgramGroupPage=yes
SetupIconFile=..\NativeDNS.GUI\resources\nativedns.ico
OutputDir={#OutputDir}
OutputBaseFilename=NativeDNS-{#AppVersion}-windows-x64-setup{#ConfigurationSuffix}
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\NativeDNS.exe
CloseApplications=yes
CloseApplicationsFilter=NativeDNS.exe,NativeDNS.Debug.exe,NativeDNS.GUI.exe,NativeDNS.CoreHost.exe,NativeDNSCoreHost.exe
SetupLogging=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{app}\logs"; Permissions: users-modify

[Icons]
Name: "{group}\NativeDNS"; Filename: "{app}\NativeDNS.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\NativeDNS"; Filename: "{app}\NativeDNS.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\NativeDNS.exe"; Description: "Launch NativeDNS"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\NativeDNS.exe"; Parameters: "--cli core shutdown --quiet"; Flags: runhidden skipifdoesntexist; RunOnceId: "ShutdownNativeDNSCore"
Filename: "{app}\NativeDNS.exe"; Parameters: "--cli network restore --quiet"; Flags: runhidden skipifdoesntexist; RunOnceId: "RestoreNativeDNSNetwork"
Filename: "{app}\NativeDNS.exe"; Parameters: "--cli autostart disable --quiet"; Flags: runhidden skipifdoesntexist; RunOnceId: "DisableNativeDNSAutostart"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Launcher: String;
  ResultCode: Integer;
begin
  Result := '';
  Launcher := ExpandConstant('{app}\NativeDNS.exe');
  if FileExists(Launcher) then
  begin
    Exec(Launcher, '--cli core shutdown --quiet', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(500);
  end;
end;
