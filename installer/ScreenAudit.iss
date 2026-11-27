; ScreenAudit Windows installer
#define MyAppName "ScreenAudit"
#define MyAppVersion "0.2.0"
#define MyAppPublisher "V. K. Singh"
#define MyAppExeName "ScreenAudit.exe"

[Setup]
AppId={{B49F95AC-8C2B-4D7C-9D63-7F3D4A60A8A1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\ScreenAudit
DefaultGroupName=ScreenAudit
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=ScreenAudit-Setup-x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "startup"; Description: "Run ScreenAudit when I sign in"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "..\ScreenAudit.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\ScreenAudit"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\ScreenAudit"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\ScreenAudit"; Filename: "{app}\{#MyAppExeName}"; Tasks: startup

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch ScreenAudit"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\"
