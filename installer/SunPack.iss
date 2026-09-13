#ifndef AppVersion
  #define AppVersion "dev"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\sunpack-x64"
#endif
#ifndef OutputDir
  #define OutputDir "..\release"
#endif
#ifndef OutputBaseFilename
  #define OutputBaseFilename "sunpack-windows-setup"
#endif
#ifndef TargetArch
  #define TargetArch "x64"
#endif
[Setup]
AppId={{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}
AppName=SunPack
AppVersion={#AppVersion}
AppVerName=SunPack {#AppVersion} ({#TargetArch})
AppPublisher=SunPack
DefaultDirName={autopf}\SunPack
PrivilegesRequired=admin
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}
SetupIconFile={#SourceDir}\sunpack.ico
UninstallDisplayIcon={app}\sunpack.ico
LicenseFile=..\LICENSE
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
ChangesAssociations=yes
CloseApplications=yes
RestartApplications=no
UsePreviousAppDir=no
UsePreviousTasks=yes
UsedUserAreasWarning=no

#if TargetArch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "Languages\ChineseSimplified.isl"

[CustomMessages]
english.TaskAddToPath=Add sunpack to the current user's PATH
english.TaskContextMenu=Register the sunpack folder context menu
english.TaskAutostart=Start sunpack Watch when Windows starts
english.GroupShellIntegration=Shell integration:
english.GroupBackgroundWatch=Background watch:
english.WatchBrokerDisplayName=sunpack Watch Broker
english.WatchBrokerDescription=Provides minimal privileged NTFS USN journal reads while sunpack Watch is running.
english.BrokerExecutableMissing=Packaged Watch Broker executable is missing: %s
english.BrokerCreateFailed=Failed to create %s (sc.exe exit code %d).
english.BrokerSidTypeFailed=Failed to set the service SID type (sc.exe exit code %d).
english.BrokerSecurityFailed=Failed to secure the Watch Broker service (sc.exe exit code %d).
english.PrepareRuntimeRunning=sunpack runtime processes are still running. Please stop them and run the installer again.
english.PrepareBrokerRemoveFailed=The existing sunpack Watch Broker service could not be removed. Restart Windows and run the installer again.
english.PrepareOldFilesRemoveFailed=Some old sunpack files could not be removed. Close sunpack and run the installer again.
english.UninstallStopFailed=sunpack runtime processes or the Watch Broker service could not be stopped. Please restart Windows and run the uninstaller again.
chinesesimplified.TaskAddToPath=将 sunpack 添加到当前用户的 PATH
chinesesimplified.TaskContextMenu=注册 sunpack 文件夹右键菜单
chinesesimplified.TaskAutostart=Windows 启动时运行 sunpack 监控
chinesesimplified.GroupShellIntegration=资源管理器集成：
chinesesimplified.GroupBackgroundWatch=后台监控：
chinesesimplified.WatchBrokerDisplayName=sunpack 监控代理服务
chinesesimplified.WatchBrokerDescription=在 sunpack 监控运行期间，以最小权限读取 NTFS USN 日志。
chinesesimplified.BrokerExecutableMissing=安装包中缺少 Watch Broker 可执行文件：%s
chinesesimplified.BrokerCreateFailed=无法创建 %s（sc.exe 退出码 %d）。
chinesesimplified.BrokerSidTypeFailed=无法设置服务 SID 类型（sc.exe 退出码 %d）。
chinesesimplified.BrokerSecurityFailed=无法设置 Watch Broker 服务权限（sc.exe 退出码 %d）。
chinesesimplified.PrepareRuntimeRunning=sunpack 运行时进程仍在运行。请先停止这些进程，然后重新运行安装程序。
chinesesimplified.PrepareBrokerRemoveFailed=无法删除现有 sunpack Watch Broker 服务。请重启 Windows，然后重新运行安装程序。
chinesesimplified.PrepareOldFilesRemoveFailed=无法删除部分旧版 sunpack 文件。请关闭 sunpack，然后重新运行安装程序。
chinesesimplified.UninstallStopFailed=无法停止 sunpack 运行时进程或 Watch Broker 服务。请重启 Windows，然后重新运行卸载程序。

[Tasks]
Name: "addtopath"; Description: "{cm:TaskAddToPath}"; GroupDescription: "{cm:GroupShellIntegration}"
Name: "contextmenu"; Description: "{cm:TaskContextMenu}"; GroupDescription: "{cm:GroupShellIntegration}"
Name: "autostart"; Description: "{cm:TaskAutostart}"; GroupDescription: "{cm:GroupBackgroundWatch}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "sunpack_watch_roots.txt,builtin_passwords.txt"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\sunpack_watch_roots.txt"; DestDir: "{localappdata}\SunPack"; Flags: onlyifdoesntexist skipifsourcedoesntexist
Source: "{#SourceDir}\builtin_passwords.txt"; DestDir: "{localappdata}\SunPack"; Flags: onlyifdoesntexist skipifsourcedoesntexist

[UninstallDelete]
Type: filesandordirs; Name: "{app}\*"
Type: dirifempty; Name: "{app}"
Type: filesandordirs; Name: "{localappdata}\SunPack"
Type: filesandordirs; Name: "{commonappdata}\SunPack\Service"
Type: dirifempty; Name: "{commonappdata}\SunPack"

[InstallDelete]
Type: files; Name: "{userprograms}\SunPack\SunPack Command Prompt.lnk"
Type: files; Name: "{userprograms}\SunPack\Uninstall SunPack.lnk"
Type: files; Name: "{userprograms}\SunPack\SunPack Watch Notifications.lnk"
Type: dirifempty; Name: "{userprograms}\SunPack"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SunPackWatchService"; ValueData: """{app}\sunpack.exe"" watch start"; Tasks: autostart; Flags: uninsdeletevalue

[UninstallRun]
Filename: "{app}\sunpack-runtime.exe"; Parameters: "--unregister-toast"; RunOnceId: "SunPackToast"; Flags: runhidden waituntilterminated skipifdoesntexist

[Code]
const
  SunPackRegistryKey = 'Software\SunPack';
  EnvironmentRegistryKey = 'Environment';
  StartupRegistryKey = 'Software\Microsoft\Windows\CurrentVersion\Run';
  StartupValueName = 'SunPackWatchService';
  PathMarkerName = 'PathAddedByInstaller';
  WatchBrokerServiceName = 'SunPackWatchBroker';
  WatchBrokerServiceSddl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LCRP;;;IU)';

function RunServiceControl(const Parameters: string; var ResultCode: Integer): Boolean;
begin
  Result := Exec(
    ExpandConstant('{sys}\sc.exe'),
    Parameters,
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
end;

function WaitForBrokerServiceDeleted: Boolean;
var
  Attempt: Integer;
  ResultCode: Integer;
begin
  for Attempt := 1 to 80 do
  begin
    if RunServiceControl('query ' + WatchBrokerServiceName, ResultCode) and (ResultCode = 1060) then
    begin
      Result := True;
      Exit;
    end;
    Sleep(250);
  end;
  Result := False;
end;

function StopAndDeleteBrokerService: Boolean;
var
  ResultCode: Integer;
begin
  { Stop is best-effort because a fresh install has no service and a released
    demand-start service is normally already stopped. }
  RunServiceControl('stop ' + WatchBrokerServiceName, ResultCode);
  Sleep(250);
  if not RunServiceControl('delete ' + WatchBrokerServiceName, ResultCode) then
  begin
    Result := False;
    Exit;
  end;
  if (ResultCode <> 0) and (ResultCode <> 1060) then
  begin
    Log(Format('Failed to delete %s: sc.exe exit code %d', [WatchBrokerServiceName, ResultCode]));
    Result := False;
    Exit;
  end;
  Result := WaitForBrokerServiceDeleted;
  if not Result then
    Log('Timed out waiting for the Watch Broker service to be deleted.');
end;

procedure RollBackBrokerInstallAndRaise(Message: string);
begin
  if not StopAndDeleteBrokerService then
    Log('The partially installed Watch Broker service also failed to roll back.');
  RaiseException(Message);
end;

procedure InstallBrokerService;
var
  BrokerPath: string;
  QuotedImagePath: string;
  Parameters: string;
  ResultCode: Integer;
begin
  BrokerPath := ExpandConstant('{app}\service\sunpack-watch-broker.exe');
  if not FileExists(BrokerPath) then
    RaiseException(Format(CustomMessage('BrokerExecutableMissing'), [BrokerPath]));
  { sc.exe must receive literal quote characters as part of binPath. The
    outer AddQuotes groups the argument; the backslash-escaped inner quotes
    are persisted in the SCM ImagePath value. }
  QuotedImagePath := '\"' + BrokerPath + '\"';
  Parameters :=
    'create ' + WatchBrokerServiceName +
    ' binPath= ' + AddQuotes(QuotedImagePath) +
    ' type= own start= demand obj= LocalSystem DisplayName= ' + AddQuotes(CustomMessage('WatchBrokerDisplayName'));
  if (not RunServiceControl(Parameters, ResultCode)) or (ResultCode <> 0) then
    RaiseException(Format(CustomMessage('BrokerCreateFailed'), [WatchBrokerServiceName, ResultCode]));
  if (not RunServiceControl('sidtype ' + WatchBrokerServiceName + ' unrestricted', ResultCode)) or (ResultCode <> 0) then
    RollBackBrokerInstallAndRaise(Format(CustomMessage('BrokerSidTypeFailed'), [ResultCode]));
  if (not RunServiceControl('sdset ' + WatchBrokerServiceName + ' ' + WatchBrokerServiceSddl, ResultCode)) or (ResultCode <> 0) then
    RollBackBrokerInstallAndRaise(Format(CustomMessage('BrokerSecurityFailed'), [ResultCode]));
  RunServiceControl(
    'description ' + WatchBrokerServiceName + ' ' +
    AddQuotes(CustomMessage('WatchBrokerDescription')),
    ResultCode
  );
end;

function NormalizePathEntry(Value: string): string;
begin
  Value := Trim(Value);
  if (Length(Value) >= 2) and (Value[1] = '"') and (Value[Length(Value)] = '"') then
    Value := Copy(Value, 2, Length(Value) - 2);
  while (Length(Value) > 3) and ((Value[Length(Value)] = '\') or (Value[Length(Value)] = '/')) do
    Delete(Value, Length(Value), 1);
  Result := Lowercase(Value);
end;

function PopPathEntry(var Remaining: string): string;
var
  Separator: Integer;
begin
  Separator := Pos(';', Remaining);
  if Separator = 0 then
  begin
    Result := Remaining;
    Remaining := '';
  end
  else
  begin
    Result := Copy(Remaining, 1, Separator - 1);
    Delete(Remaining, 1, Separator);
  end;
end;

function PathContains(const PathValue, Entry: string): Boolean;
var
  Remaining: string;
  Token: string;
  NormalizedEntry: string;
begin
  Result := False;
  Remaining := PathValue;
  NormalizedEntry := NormalizePathEntry(Entry);
  while Remaining <> '' do
  begin
    Token := PopPathEntry(Remaining);
    if NormalizePathEntry(Token) = NormalizedEntry then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

procedure AddUserPath;
var
  CurrentPath: string;
  AppPath: string;
  NewPath: string;
begin
  AppPath := ExpandConstant('{app}');
  if not RegQueryStringValue(HKCU, EnvironmentRegistryKey, 'Path', CurrentPath) then
    CurrentPath := '';
  if PathContains(CurrentPath, AppPath) then
    Exit;
  NewPath := CurrentPath;
  if (NewPath <> '') and (NewPath[Length(NewPath)] <> ';') then
    NewPath := NewPath + ';';
  NewPath := NewPath + AppPath;
  if RegWriteExpandStringValue(HKCU, EnvironmentRegistryKey, 'Path', NewPath) then
    RegWriteDWordValue(HKCU, SunPackRegistryKey, PathMarkerName, 1);
end;

procedure RemoveUserPath;
var
  WasAdded: Cardinal;
  CurrentPath: string;
  Remaining: string;
  Token: string;
  NewPath: string;
  AppPath: string;
begin
  if not RegQueryDWordValue(HKCU, SunPackRegistryKey, PathMarkerName, WasAdded) or (WasAdded <> 1) then
    Exit;
  if not RegQueryStringValue(HKCU, EnvironmentRegistryKey, 'Path', CurrentPath) then
    CurrentPath := '';
  Remaining := CurrentPath;
  AppPath := NormalizePathEntry(ExpandConstant('{app}'));
  NewPath := '';
  while Remaining <> '' do
  begin
    Token := PopPathEntry(Remaining);
    if (Trim(Token) <> '') and (NormalizePathEntry(Token) <> AppPath) then
    begin
      if NewPath <> '' then
        NewPath := NewPath + ';';
      NewPath := NewPath + Trim(Token);
    end;
  end;
  RegWriteExpandStringValue(HKCU, EnvironmentRegistryKey, 'Path', NewPath);
  RegDeleteValue(HKCU, SunPackRegistryKey, PathMarkerName);
  RegDeleteKeyIfEmpty(HKCU, SunPackRegistryKey);
end;

procedure RemoveStartupRunValue;
begin
  RegDeleteValue(HKCU, StartupRegistryKey, StartupValueName);
end;

function PowerShellSingleQuotedString(Value: string): string;
begin
  StringChangeEx(Value, '''', '''''', True);
  Result := '''' + Value + '''';
end;

procedure RunContextMenuScript(RegisterMenu: Boolean);
var
  PowerShellPath: string;
  ScriptPath: string;
  Parameters: string;
  ResultCode: Integer;
begin
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if RegisterMenu then
  begin
    ScriptPath := ExpandConstant('{app}\scripts\register_context_menu.ps1');
    Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
      AddQuotes(ScriptPath) + ' -AppPath ' + AddQuotes(ExpandConstant('{app}\sunpack.exe')) +
      ' -IconPath ' + AddQuotes(ExpandConstant('{app}\sunpack.ico'));
  end
  else
  begin
    ScriptPath := ExpandConstant('{app}\scripts\unregister_context_menu.ps1');
    Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + AddQuotes(ScriptPath);
  end;
  if not FileExists(ScriptPath) then
  begin
    Log('Context menu script was not found: ' + ScriptPath);
    Exit;
  end;
  if not Exec(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Failed to start context menu script: ' + ScriptPath)
  else if ResultCode <> 0 then
    Log(Format('Context menu script exited with code %d: %s', [ResultCode, ScriptPath]));
end;

procedure StopExistingProcesses;
var
  ExistingApp: string;
  ResultCode: Integer;
begin
  ExistingApp := ExpandConstant('{app}\sunpack.exe');
  if not FileExists(ExistingApp) then
    Exit;
  if not Exec(ExistingApp, 'watch stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Failed to start existing SunPack watch stop command: ' + ExistingApp)
  else if ResultCode <> 0 then
    Log(Format('Existing SunPack watch stop command exited with code %d', [ResultCode]));
  if not Exec(ExistingApp, '--persistent-shutdown', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Failed to stop existing SunPack persistent process: ' + ExistingApp)
  else if ResultCode <> 0 then
    Log(Format('Existing SunPack persistent shutdown exited with code %d', [ResultCode]));
end;

function WaitForExistingRuntimesToExit: Boolean;
var
  PowerShellPath: string;
  CliAppPath: string;
  RuntimeAppPath: string;
  Command: string;
  Parameters: string;
  ResultCode: Integer;
begin
  Result := True;
  CliAppPath := ExpandConstant('{app}\sunpack.exe');
  RuntimeAppPath := ExpandConstant('{app}\sunpack-runtime.exe');
  if (not FileExists(CliAppPath)) and (not FileExists(RuntimeAppPath)) then
    Exit;
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Command :=
    '$targets = @(' + PowerShellSingleQuotedString(CliAppPath) + ', ' + PowerShellSingleQuotedString(RuntimeAppPath) + '); ' +
    '$deadline = (Get-Date).AddSeconds(20); ' +
    'do { ' +
    '  $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { ' +
    '    try { $processPath = [System.IO.Path]::GetFullPath($_.Path); @($targets | Where-Object { [System.IO.Path]::GetFullPath($_).Equals($processPath, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 } catch { $false } ' +
    '  }); ' +
    '  if ($running.Count -eq 0) { exit 0 }; ' +
    '  Start-Sleep -Milliseconds 250; ' +
    '} while ((Get-Date) -lt $deadline); ' +
    'exit 1';
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' + AddQuotes(Command);
  if not Exec(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log('Failed to wait for existing SunPack runtime processes to exit.');
    Result := False;
  end
  else if ResultCode <> 0 then
  begin
    Log(Format('Timed out waiting for existing SunPack runtime processes to exit: %d', [ResultCode]));
    Result := False;
  end;
end;

function StopExistingProcessesAndWait: Boolean;
begin
  StopExistingProcesses;
  Result := WaitForExistingRuntimesToExit;
end;

function IsPersistentInstallFile(const FileName: string): Boolean;
begin
  Result :=
    (CompareText(FileName, 'sunpack_watch_roots.txt') = 0) or
    (CompareText(FileName, 'builtin_passwords.txt') = 0);
end;

function ClearInstallDirectory: Boolean;
var
  AppPath: string;
  SearchPath: string;
  ItemPath: string;
  FindData: TFindRec;
begin
  Result := True;
  AppPath := ExpandConstant('{app}');
  if not DirExists(AppPath) then
    Exit;

  SearchPath := AddBackslash(AppPath) + '*';
  if not FindFirst(SearchPath, FindData) then
    Exit;
  try
    repeat
      if (FindData.Name <> '.') and (FindData.Name <> '..') then
      begin
        ItemPath := AddBackslash(AppPath) + FindData.Name;
        if DirExists(ItemPath) then
        begin
          if not DelTree(ItemPath, True, True, True) and DirExists(ItemPath) then
          begin
            Log('Failed to remove old SunPack directory: ' + ItemPath);
            Result := False;
          end;
        end
        else if not IsPersistentInstallFile(FindData.Name) then
        begin
          if not DeleteFile(ItemPath) and FileExists(ItemPath) then
          begin
            Log('Failed to remove old SunPack file: ' + ItemPath);
            Result := False;
          end;
        end;
      end;
    until not FindNext(FindData);
  finally
    FindClose(FindData);
  end;
end;

procedure InitializeWizard();
begin
  WizardForm.LicenseAcceptedRadio.Checked := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  if not StopExistingProcessesAndWait then
  begin
    Result := CustomMessage('PrepareRuntimeRunning');
    Exit;
  end;
  if not StopAndDeleteBrokerService then
  begin
    Result := CustomMessage('PrepareBrokerRemoveFailed');
    Exit;
  end;
  RunContextMenuScript(False);
  RemoveStartupRunValue;
  RemoveUserPath;
  if not ClearInstallDirectory then
  begin
    Result := CustomMessage('PrepareOldFilesRemoveFailed');
    Exit;
  end;
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  RemoveStartupRunValue;
  Result := StopExistingProcessesAndWait;
  if Result then
    Result := StopAndDeleteBrokerService;
  if not Result then
    MsgBox(CustomMessage('UninstallStopFailed'), mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    InstallBrokerService;
    if WizardIsTaskSelected('addtopath') then
      AddUserPath;
    if WizardIsTaskSelected('contextmenu') then
      RunContextMenuScript(True)
    else
      RunContextMenuScript(False);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopAndDeleteBrokerService;
    RunContextMenuScript(False);
    RemoveStartupRunValue;
    RemoveUserPath;
  end;
end;
