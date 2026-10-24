; NetWarden installer. Built by scripts\build-release.ps1, which passes:
;   /DAppVersion=x.y.z  /DStage=<folder with client\ and service\>  /DOutDir=<output folder>
; Installs the client and the service, registers the service (auto start, restart on
; failure) and removes it again on uninstall. Rules and settings in
; %ProgramData%\NetWarden are kept on uninstall.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef Stage
  #define Stage "..\artifacts\release\stage"
#endif
#ifndef OutDir
  #define OutDir "..\artifacts\release"
#endif

#define ServiceName "NetWarden"

[Setup]
AppId={{6B0E2C5A-7C1F-4E8B-9A57-3D2F0C9B1E44}
AppName=NetWarden
AppVersion={#AppVersion}
AppVerName=NetWarden {#AppVersion}
AppPublisher=NetWarden
DefaultDirName={autopf}\NetWarden
DefaultGroupName=NetWarden
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutDir}
OutputBaseFilename=NetWarden-Setup-{#AppVersion}
SetupIconFile=..\src\NetWarden.Client\Assets\NetWarden.ico
UninstallDisplayIcon={app}\NetWarden.exe
UninstallDisplayName=NetWarden
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#Stage}\client\NetWarden.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Stage}\service\*"; DestDir: "{app}\service"; Excludes: "WinDivert.dll,WinDivert64.sys"; Flags: ignoreversion recursesubdirs createallsubdirs
; The driver keeps WinDivert64.sys open while it is loaded. Without ignoreversion an
; identical version is skipped instead of replaced (the driver is also stopped first).
Source: "{#Stage}\service\WinDivert.dll"; DestDir: "{app}\service"
Source: "{#Stage}\service\WinDivert64.sys"; DestDir: "{app}\service"
Source: "..\third_party\WinDivert\LICENSE"; DestDir: "{app}\licenses"; DestName: "WinDivert-LICENSE.txt"
Source: "..\third_party\GeoIP\LICENSE"; DestDir: "{app}\licenses"; DestName: "DB-IP-LICENSE.txt"

[Icons]
Name: "{group}\NetWarden"; Filename: "{app}\NetWarden.exe"
Name: "{group}\Uninstall NetWarden"; Filename: "{uninstallexe}"
Name: "{autodesktop}\NetWarden"; Filename: "{app}\NetWarden.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\NetWarden.exe"; Description: "{cm:LaunchProgram,NetWarden}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
; Runs before files are removed: stop the service (closing WinDivert) and unregister it.
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\timeout.exe"; Parameters: "/t 3 /nobreak"; Flags: runhidden waituntilterminated; RunOnceId: "WaitService"
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"
; Unload the WinDivert driver (it removes its own registration once stopped). Fails
; harmlessly if another program still has it open.
Filename: "{sys}\sc.exe"; Parameters: "stop WinDivert"; Flags: runhidden waituntilterminated; RunOnceId: "StopWinDivert"

[Code]
function Sc(const Params: String): Integer;
var
  Code: Integer;
begin
  if not Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  Result := Code;
end;

function ServiceStopped(): Boolean;
var
  Code: Integer;
begin
  { find needs a shell for the pipe; exit code 0 means "STOPPED" was in the output. }
  Result := Exec(ExpandConstant('{cmd}'), '/c sc query {#ServiceName} | find "STOPPED" >nul', '', SW_HIDE, ewWaitUntilTerminated, Code)
            and (Code = 0);
end;

{ An existing NetWarden service (older version, or a developer install elsewhere) is
  stopped and removed first, so its files can be replaced and it points at this copy. }
procedure RemoveExistingService();
var
  I: Integer;
begin
  if Sc('query {#ServiceName}') <> 0 then
    exit;
  Sc('stop {#ServiceName}');
  for I := 1 to 20 do
  begin
    if ServiceStopped() then
      break;
    Sleep(500);
  end;
  Sc('delete {#ServiceName}');
  Sleep(1000);
end;

procedure InstallService();
var
  Exe: String;
begin
  Exe := ExpandConstant('{app}\service\NetWarden.Service.exe');
  if Sc('create {#ServiceName} binPath= "\"' + Exe + '\"" start= auto DisplayName= "NetWarden Service"') <> 0 then
  begin
    MsgBox('Registering the NetWarden service failed. Traffic monitoring will not work until it is installed.', mbError, MB_OK);
    exit;
  end;
  Sc('description {#ServiceName} "Monitors, limits and filters network traffic per application."');
  { Restart on crash: after 5 s, 10 s, then 60 s; reset the failure count after a day. }
  Sc('failure {#ServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/60000');
  Sc('start {#ServiceName}');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    RemoveExistingService();
    { Unload WinDivert so its files can be replaced; fails harmlessly if another program uses it. }
    if Sc('stop WinDivert') = 0 then
      Sleep(1000);
  end
  else if CurStep = ssPostInstall then
    InstallService();
end;
