#ifndef StageDir
  #error StageDir must point to the staged NativeDNS portable directory
#endif
#ifndef OutputDir
  #error OutputDir must point to the installer output directory
#endif
#ifndef Configuration
  #define Configuration "Release"
#endif

#if Configuration == "Debug"
  #define ConfigurationSuffix "-debug"
#else
  #define ConfigurationSuffix ""
#endif

[Setup]
AppId={{2F47E185-E56B-42F0-A85F-D6F276F3AF6B}
AppName=NativeDNS
AppVersion=0.4.0
AppPublisher=NativeDNS
DefaultDirName={autopf}\NativeDNS
DefaultGroupName=NativeDNS
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=NativeDNS-0.4.0-windows-x64-setup{#ConfigurationSuffix}
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\NativeDNS.exe
CloseApplications=yes
SetupLogging=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NativeDNS"; Filename: "{app}\NativeDNS.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\NativeDNS"; Filename: "{app}\NativeDNS.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\NativeDNS.exe"; Description: "Launch NativeDNS"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\tools\nativednsctl.exe"; Parameters: "autostart disable"; Flags: runhidden skipifdoesntexist; RunOnceId: "DisableNativeDNSAutostart"
