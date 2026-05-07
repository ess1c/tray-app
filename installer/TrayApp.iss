; ─────────────────────────────────────────────────────────────────
;  TrayApp installer (Inno Setup)
;  Сборка: ISCC.exe TrayApp.iss
; ─────────────────────────────────────────────────────────────────

#define MyAppName        "TrayApp"
#define MyAppVersion     "1.0.0"
#define MyAppPublisher   "MTUCI"
#define MyServiceName    "TrayAppService"
#define MyAppExeName     "TrayApp.exe"
#define MyServiceExeName "TrayService.exe"

[Setup]
AppId={{F2A3B7D2-9E4C-4E8B-AC91-2F5C6E8B3A12}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir={#SourcePath}\out
OutputBaseFilename=TrayApp-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayName={#MyAppName}
CloseApplications=force

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; --- основные артефакты сборки ---
Source: "..\build\bin\Release\{#MyAppExeName}";     DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\bin\Release\{#MyServiceExeName}"; DestDir: "{app}"; Flags: ignoreversion
; --- зависимости ---
Source: "vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Run]
; --- установка зависимостей (тихо), с тайм-аутом ---
Filename: "{tmp}\vc_redist.x64.exe"; \
    Parameters: "/install /quiet /norestart"; \
    StatusMsg: "Установка Microsoft Visual C++ Redistributable..."; \
    Flags: skipifsilent runascurrentuser; \
    Check: VCRedistNeeded
; --- регистрация службы (автозапуск при загрузке системы) ---
Filename: "{sys}\sc.exe"; \
    Parameters: "create {#MyServiceName} binPath= ""\""{app}\{#MyServiceExeName}\"""" start= auto DisplayName= ""TrayApp Service"""; \
    StatusMsg: "Регистрация службы..."; \
    Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; \
    Parameters: "description {#MyServiceName} ""TrayApp background service (RPC over ALPC, license management)"""; \
    Flags: runhidden waituntilterminated
; --- запуск службы (без ожидания, в фоне) ---
Filename: "{sys}\sc.exe"; \
    Parameters: "start {#MyServiceName}"; \
    StatusMsg: "Запуск службы..."; \
    Flags: runhidden nowait

[UninstallRun]
; --- корректная остановка службы через RPC ---
; (taskkill не сработает — процессы защищены DACL DENY PROCESS_TERMINATE)
Filename: "{app}\{#MyAppExeName}"; \
    Parameters: "--stop-service"; \
    StatusMsg: "Остановка службы..."; \
    Flags: runhidden waituntilterminated; RunOnceId: "StopService"
; --- удаление службы из диспетчера ---
Filename: "{sys}\sc.exe"; \
    Parameters: "delete {#MyServiceName}"; \
    Flags: runhidden; RunOnceId: "DeleteService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
{ ----- проверка нужен ли VC++ Redistributable ----- }
function VCRedistNeeded: Boolean;
var
  Installed: Cardinal;
begin
  Result := True;
  if RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64',
                        'Installed', Installed) then
  begin
    if Installed = 1 then
      Result := False;
  end;
end;
