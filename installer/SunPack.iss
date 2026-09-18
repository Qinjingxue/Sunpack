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
DisableProgramGroupPage=yes
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
UsePreviousAppDir=yes
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
english.StartupEnableLaunchFailed=Failed to run sunpack while configuring startup.
english.StartupEnableCommandFailed=sunpack could not configure startup (exit code %d).
english.ToastRegisterLaunchFailed=Failed to run sunpack while registering machine-wide notifications.
english.ToastRegisterCommandFailed=sunpack could not register machine-wide notifications (exit code %d).
english.TaskAddToPathFailed=Failed to add sunpack to the current user's PATH.
english.TaskContextMenuFailed=Failed to register the sunpack folder context menu.
english.PrepareRuntimeRunning=sunpack runtime processes are still running. Please stop them and run the installer again.
english.PrepareBrokerRemoveFailed=The existing sunpack Watch Broker service could not be removed. Restart Windows and run the installer again.
english.PrepareOldFilesRemoveFailed=Some old sunpack files could not be removed. Close sunpack and run the installer again.
english.UninstallStopFailed=sunpack runtime processes or the Watch Broker service could not be stopped. Please restart Windows and run the uninstaller again.
english.BuiltinPasswordsFileHeader=# Built-in common password list. You can edit this file; use one password per line.
english.BuiltinPasswordsWatchManagedNote=# The following section is managed automatically by SunPack Watch.
english.WatchRootsFileHeader=# Watched folders. Add one folder per line.
english.WatchRootsFileMapping=# Optional output mapping: input folder | output folder
english.WatchRootsFileExample=# Example: C:\Downloads | D:\Extracted
english.EditableConfigCreateFailed=Failed to create the initial editable configuration file: %s
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
chinesesimplified.StartupEnableLaunchFailed=配置开机启动时无法运行 sunpack。
chinesesimplified.StartupEnableCommandFailed=sunpack 无法配置开机启动（退出码 %d）。
chinesesimplified.ToastRegisterLaunchFailed=注册机器级通知时无法运行 sunpack。
chinesesimplified.ToastRegisterCommandFailed=sunpack 无法注册机器级通知（退出码 %d）。
chinesesimplified.TaskAddToPathFailed=无法将 sunpack 添加到当前用户的 PATH。
chinesesimplified.TaskContextMenuFailed=无法注册 sunpack 文件夹右键菜单。
chinesesimplified.PrepareRuntimeRunning=sunpack 运行时进程仍在运行。请先停止这些进程，然后重新运行安装程序。
chinesesimplified.PrepareBrokerRemoveFailed=无法删除现有 sunpack Watch Broker 服务。请重启 Windows，然后重新运行安装程序。
chinesesimplified.PrepareOldFilesRemoveFailed=无法删除部分旧版 sunpack 文件。请关闭 sunpack，然后重新运行安装程序。
chinesesimplified.UninstallStopFailed=无法停止 sunpack 运行时进程或 Watch Broker 服务。请重启 Windows，然后重新运行卸载程序。
chinesesimplified.BuiltinPasswordsFileHeader=# 此文件为内置高频密码配置表，用户可自行编辑，每行一个密码。
chinesesimplified.BuiltinPasswordsWatchManagedNote=# 以下区域由 SunPack Watch 自动维护，请勿手动编辑。
chinesesimplified.WatchRootsFileHeader=# 监控文件夹配置，每行填写一个监控目录。
chinesesimplified.WatchRootsFileMapping=# 可选输出目录映射格式：输入目录 | 输出目录
chinesesimplified.WatchRootsFileExample=# 示例：C:\Downloads | D:\Extracted
chinesesimplified.EditableConfigCreateFailed=无法创建初始可编辑配置文件：%s

[Tasks]
Name: "addtopath"; Description: "{cm:TaskAddToPath}"; GroupDescription: "{cm:GroupShellIntegration}"
Name: "contextmenu"; Description: "{cm:TaskContextMenu}"; GroupDescription: "{cm:GroupShellIntegration}"
Name: "autostart"; Description: "{cm:TaskAutostart}"; GroupDescription: "{cm:GroupBackgroundWatch}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "sunpack_config.json,sunpack_watch_roots.txt,builtin_passwords.txt"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\sunpack_config.json"; DestDir: "{commonappdata}\SunPack"; Flags: onlyifdoesntexist skipifsourcedoesntexist

[Dirs]
Name: "{commonappdata}\SunPack"; Permissions: users-modify

[UninstallDelete]
Type: filesandordirs; Name: "{app}\*"
Type: dirifempty; Name: "{app}"
Type: filesandordirs; Name: "{commonappdata}\SunPack"
Type: files; Name: "{commonprograms}\SunPack\Uninstall SunPack.lnk"

[Icons]
Name: "{autoprograms}\SunPack\Uninstall SunPack"; Filename: "{uninstallexe}"

[UninstallRun]
Filename: "{app}\sunpack-runtime.exe"; Parameters: "--configure-startup-current-user disable"; RunOnceId: "SunPackStartup"; Flags: runhidden waituntilterminated skipifdoesntexist
Filename: "{app}\sunpack-runtime.exe"; Parameters: "--unregister-toast"; RunOnceId: "SunPackToast"; Flags: runhidden waituntilterminated skipifdoesntexist

[Code]
const
  SunPackRegistryKey = 'Software\SunPack';
  EnvironmentRegistryKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';
  StartupRegistryKey = 'Software\Microsoft\Windows\CurrentVersion\Run';
  StartupValueName = 'SunPackWatchService';
  PathMarkerName = 'PathAddedByInstaller';
  UpgradeWatchStateDirValueName = 'UpgradeWatchStateDir';
  WatchBrokerServiceName = 'SunPackWatchBroker';
  WatchClipboardBlockBegin = '#!SUNPACK-WATCH-CLIPBOARD-BEGIN';
  WatchClipboardBlockEnd = '#!SUNPACK-WATCH-CLIPBOARD-END';
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

function AddMachinePath: Boolean;
var
  CurrentPath: string;
  AppPath: string;
  NewPath: string;
begin
  AppPath := ExpandConstant('{app}');
  if not RegQueryStringValue(HKLM, EnvironmentRegistryKey, 'Path', CurrentPath) then
    CurrentPath := '';
  if PathContains(CurrentPath, AppPath) then
  begin
    Result := True;
    Exit;
  end;
  NewPath := CurrentPath;
  if (NewPath <> '') and (NewPath[Length(NewPath)] <> ';') then
    NewPath := NewPath + ';';
  NewPath := NewPath + AppPath;
  Result := RegWriteExpandStringValue(HKLM, EnvironmentRegistryKey, 'Path', NewPath);
  if Result then
    Result := RegWriteDWordValue(HKLM, SunPackRegistryKey, PathMarkerName, 1);
end;

procedure RemoveMachinePath;
var
  WasAdded: Cardinal;
  CurrentPath: string;
  Remaining: string;
  Token: string;
  NewPath: string;
  AppPath: string;
begin
  if not RegQueryDWordValue(HKLM, SunPackRegistryKey, PathMarkerName, WasAdded) or (WasAdded <> 1) then
    Exit;
  if not RegQueryStringValue(HKLM, EnvironmentRegistryKey, 'Path', CurrentPath) then
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
  RegWriteExpandStringValue(HKLM, EnvironmentRegistryKey, 'Path', NewPath);
  RegDeleteValue(HKLM, SunPackRegistryKey, PathMarkerName);
  RegDeleteKeyIfEmpty(HKLM, SunPackRegistryKey);
end;

function PowerShellSingleQuotedString(Value: string): string;
begin
  StringChangeEx(Value, '''', '''''', True);
  Result := '''' + Value + '''';
end;

function HasExplicitTaskSelection: Boolean;
var
  Index: Integer;
  Value: string;
begin
  Result := False;
  for Index := 1 to ParamCount do
  begin
    Value := Uppercase(ParamStr(Index));
    if (Copy(Value, 1, 7) = '/TASKS=') or
       (Copy(Value, 1, 12) = '/MERGETASKS=') then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function QueryOriginalUserStartupEnabled(var Enabled: Boolean): Boolean;
var
  ResultCode: Integer;
begin
  Enabled := False;
  ResultCode := -1;
  if not ExecAsOriginalUser(
    ExpandConstant('{sys}\reg.exe'),
    'query "HKCU\' + StartupRegistryKey + '" /v "' + StartupValueName + '"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
  begin
    Log('Failed to query the original user startup state.');
    Result := False;
    Exit;
  end;

  if ResultCode = 0 then
  begin
    Enabled := True;
    Result := True;
  end
  else if ResultCode = 1 then
    Result := True
  else
  begin
    Log(Format('Original user startup state query failed with exit code %d.', [ResultCode]));
    Result := False;
  end;
end;

function QueryExistingWatchRunning(var WatchStateDir: string): Boolean;
var
  ExistingApp: string;
  PowerShellPath: string;
  Command: string;
  Parameters: string;
  ResultCode: Integer;
begin
  Result := False;
  WatchStateDir := '';
  RegDeleteValue(HKLM, SunPackRegistryKey, UpgradeWatchStateDirValueName);
  ExistingApp := ExpandConstant('{app}\sunpack.exe');
  if not FileExists(ExistingApp) then
    Exit;

  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Command :=
    '$ErrorActionPreference = ''Stop''; ' +
    'try { ' +
    '  $json = (& ' + PowerShellSingleQuotedString(ExistingApp) + ' watch status --json 2>$null | Out-String); ' +
    '  if ($LASTEXITCODE -ne 0) { exit 2 }; ' +
    '  $status = $json | ConvertFrom-Json; ' +
    '  $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(' +
         PowerShellSingleQuotedString(SunPackRegistryKey) + '); ' +
    '  try { $key.SetValue(' + PowerShellSingleQuotedString(UpgradeWatchStateDirValueName) +
         ', [string]$status.summary.state_dir, [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() }; ' +
    '  if ($status.summary.running -eq $true) { exit 0 }; ' +
    '  exit 1; ' +
    '} catch { exit 2 }';
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' + AddQuotes(Command);
  ResultCode := -1;

  if not Exec(
    PowerShellPath,
    Parameters,
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
    Log('Failed to query the existing SunPack Watch state before upgrade.');

  if RegQueryStringValue(HKLM, SunPackRegistryKey, UpgradeWatchStateDirValueName, WatchStateDir) then
  begin
    RegDeleteValue(HKLM, SunPackRegistryKey, UpgradeWatchStateDirValueName);
    Log('Existing SunPack Watch state directory: ' + WatchStateDir);
  end;

  if ResultCode = 0 then
  begin
    Result := True;
    Log('Existing SunPack Watch is running and will be restored after upgrade.');
  end
  else if ResultCode = 1 then
    Log('Existing SunPack Watch is not running; upgrade will leave it stopped.')
  else
    Log(Format('Existing SunPack Watch state query failed with exit code %d; upgrade will not auto-start Watch.', [ResultCode]));
end;

function RunContextMenuScript(RegisterMenu: Boolean): Boolean;
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
    Result := False;
    Exit;
  end;
  if not Exec(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log('Failed to start context menu script: ' + ScriptPath);
    Result := False;
  end
  else if ResultCode <> 0 then
  begin
    Log(Format('Context menu script exited with code %d: %s', [ResultCode, ScriptPath]));
    Result := False;
  end
  else
    Result := True;
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

function IsPersistentProgramDataFile(const FileName: string): Boolean;
begin
  Result :=
    (CompareText(FileName, 'sunpack_config.json') = 0) or
    (CompareText(FileName, 'sunpack_watch_roots.txt') = 0) or
    (CompareText(FileName, 'builtin_passwords.txt') = 0);
end;

function ClearDirectory(Path: string): Boolean;
var
  SearchPath: string;
  ItemPath: string;
  FindData: TFindRec;
begin
  Result := True;
  if not DirExists(Path) then
    Exit;

  SearchPath := AddBackslash(Path) + '*';
  if not FindFirst(SearchPath, FindData) then
    Exit;
  try
    repeat
      if (FindData.Name <> '.') and (FindData.Name <> '..') then
      begin
        ItemPath := AddBackslash(Path) + FindData.Name;
        if DirExists(ItemPath) then
        begin
          if not DelTree(ItemPath, True, True, True) and DirExists(ItemPath) then
          begin
            Log('Failed to remove old SunPack directory: ' + ItemPath);
            Result := False;
          end;
        end
        else if not DeleteFile(ItemPath) and FileExists(ItemPath) then
        begin
          Log('Failed to remove old SunPack file: ' + ItemPath);
          Result := False;
        end;
      end;
    until not FindNext(FindData);
  finally
    FindClose(FindData);
  end;
end;

function IsSameOrChildPath(const PathValue, ParentValue: string): Boolean;
var
  NormalizedPath: string;
  NormalizedParent: string;
begin
  NormalizedPath := NormalizePathEntry(PathValue);
  NormalizedParent := NormalizePathEntry(ParentValue);
  Result :=
    (NormalizedPath <> '') and
    (NormalizedParent <> '') and
    ((NormalizedPath = NormalizedParent) or
     ((Length(NormalizedPath) > Length(NormalizedParent)) and
      (Copy(NormalizedPath, 1, Length(NormalizedParent) + 1) = NormalizedParent + '\')));
end;

function IsPersistentWatchStatePath(
  const ItemPath, ItemName, WatchStateDir: string;
  PreserveWatchState: Boolean
): Boolean;
begin
  Result := False;
  if not PreserveWatchState then
    Exit;
  if CompareText(ItemName, '.sunpack_watch') = 0 then
  begin
    Result := True;
    Exit;
  end;
  if WatchStateDir = '' then
    Exit;
  Result :=
    IsSameOrChildPath(WatchStateDir, ItemPath) or
    IsSameOrChildPath(ItemPath, WatchStateDir);
end;

function ClearProgramDataExceptPersistentFiles(
  PreserveWatchState: Boolean;
  const WatchStateDir: string
): Boolean;
var
  DataPath: string;
  SearchPath: string;
  ItemPath: string;
  FindData: TFindRec;
begin
  Result := True;
  DataPath := ExpandConstant('{commonappdata}\SunPack');
  if not DirExists(DataPath) then
    Exit;

  SearchPath := AddBackslash(DataPath) + '*';
  if not FindFirst(SearchPath, FindData) then
    Exit;
  try
    repeat
      if (FindData.Name <> '.') and (FindData.Name <> '..') then
      begin
        ItemPath := AddBackslash(DataPath) + FindData.Name;
        if DirExists(ItemPath) then
        begin
          if not IsPersistentWatchStatePath(ItemPath, FindData.Name, WatchStateDir, PreserveWatchState) then
          begin
            if not DelTree(ItemPath, True, True, True) and DirExists(ItemPath) then
            begin
              Log('Failed to remove old SunPack runtime state directory: ' + ItemPath);
              Result := False;
            end;
          end;
        end
        else if
          (not IsPersistentProgramDataFile(FindData.Name)) and
          (not IsPersistentWatchStatePath(ItemPath, FindData.Name, WatchStateDir, PreserveWatchState)) then
        begin
          if not DeleteFile(ItemPath) and FileExists(ItemPath) then
          begin
            Log('Failed to remove old SunPack runtime state file: ' + ItemPath);
            Result := False;
          end;
        end;
      end;
    until not FindNext(FindData);
  finally
    FindClose(FindData);
  end;
end;

function ClearInstallDirectory: Boolean;
begin
  Result := ClearDirectory(ExpandConstant('{app}'));
end;

procedure AppendTextLine(var Lines: TArrayOfString; const Line: string);
var
  Index: Integer;
begin
  Index := GetArrayLength(Lines);
  SetArrayLength(Lines, Index + 1);
  Lines[Index] := Line;
end;

function TextLinesContain(var Lines: TArrayOfString; const Needle: string): Boolean;
var
  Index: Integer;
begin
  Result := False;
  for Index := 0 to GetArrayLength(Lines) - 1 do
  begin
    if Pos(Needle, Lines[Index]) > 0 then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

procedure SaveUTF8TextLines(const FilePath: string; const Lines: TArrayOfString);
begin
  if not SaveStringsToUTF8FileWithoutBOM(FilePath, Lines, False) then
    RaiseException(Format(CustomMessage('EditableConfigCreateFailed'), [FilePath]));
end;

procedure EnsureLocalizedEditableConfigFiles;
var
  DataPath: string;
  FilePath: string;
  Contents: TArrayOfString;
begin
  DataPath := ExpandConstant('{commonappdata}\SunPack');
  ForceDirectories(DataPath);

  FilePath := AddBackslash(DataPath) + 'builtin_passwords.txt';
  SetArrayLength(Contents, 0);
  if not FileExists(FilePath) then
  begin
    AppendTextLine(Contents, CustomMessage('BuiltinPasswordsFileHeader'));
    AppendTextLine(Contents, '');
    AppendTextLine(Contents, CustomMessage('BuiltinPasswordsWatchManagedNote'));
    AppendTextLine(Contents, WatchClipboardBlockBegin);
    AppendTextLine(Contents, WatchClipboardBlockEnd);
    SaveUTF8TextLines(FilePath, Contents);
  end
  else
  begin
    if not LoadStringsFromFile(FilePath, Contents) then
      RaiseException(Format(CustomMessage('EditableConfigCreateFailed'), [FilePath]));

    if (not TextLinesContain(Contents, WatchClipboardBlockBegin)) and
       (not TextLinesContain(Contents, WatchClipboardBlockEnd)) then
    begin
      if (GetArrayLength(Contents) = 0) or
         (Contents[GetArrayLength(Contents) - 1] <> '') then
        AppendTextLine(Contents, '');
      AppendTextLine(Contents, CustomMessage('BuiltinPasswordsWatchManagedNote'));
      AppendTextLine(Contents, WatchClipboardBlockBegin);
      AppendTextLine(Contents, WatchClipboardBlockEnd);
      SaveUTF8TextLines(FilePath, Contents);
    end;
  end;

  FilePath := AddBackslash(DataPath) + 'sunpack_watch_roots.txt';
  if not FileExists(FilePath) then
  begin
    SetArrayLength(Contents, 0);
    AppendTextLine(Contents, CustomMessage('WatchRootsFileHeader'));
    AppendTextLine(Contents, CustomMessage('WatchRootsFileMapping'));
    AppendTextLine(Contents, CustomMessage('WatchRootsFileExample'));
    SaveUTF8TextLines(FilePath, Contents);
  end;
end;

var
  ExistingInstallation: Boolean;
  RestartWatchAfterUpgrade: Boolean;
  ExistingWatchStateDir: string;
  StartupTaskDefaultApplied: Boolean;

procedure RestoreWatchAfterUpgrade;
var
  ResultCode: Integer;
begin
  if not RestartWatchAfterUpgrade then
    Exit;

  if not Exec(
    ExpandConstant('{app}\sunpack-runtime.exe'),
    '--launch-watch-unelevated',
    ExpandConstant('{app}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
    Log('Failed to run the unelevated SunPack Watch restore helper after upgrade.')
  else if ResultCode <> 0 then
    Log(Format('SunPack Watch restore helper exited with code %d.', [ResultCode]))
  else
    Log('SunPack Watch was restored after upgrade.');
end;

procedure ApplyStartupTaskDefault;
var
  Enabled: Boolean;
begin
  if StartupTaskDefaultApplied then
    Exit;
  StartupTaskDefaultApplied := True;

  if HasExplicitTaskSelection then
    Exit;
  if not FileExists(ExpandConstant('{app}\sunpack.exe')) then
    Exit;
  if not QueryOriginalUserStartupEnabled(Enabled) then
    Exit;

  if Enabled then
    WizardSelectTasks('autostart')
  else
    WizardSelectTasks('!autostart');
end;

procedure ApplySelectedStartupState;
var
  StartupAction: string;
  ResultCode: Integer;
begin
  if WizardIsTaskSelected('autostart') then
    StartupAction := 'enable'
  else
    StartupAction := 'disable';

  if not Exec(
    ExpandConstant('{app}\sunpack-runtime.exe'),
    '--configure-startup-current-user ' + StartupAction,
    ExpandConstant('{app}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
    RaiseException(CustomMessage('StartupEnableLaunchFailed'))
  else if ResultCode <> 0 then
    RaiseException(Format(CustomMessage('StartupEnableCommandFailed'), [ResultCode]));
end;

procedure InitializeWizard();
begin
  WizardForm.LicenseAcceptedRadio.Checked := True;
  StartupTaskDefaultApplied := False;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpSelectTasks then
    ApplyStartupTaskDefault;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  ApplyStartupTaskDefault;
  ExistingInstallation := FileExists(ExpandConstant('{app}\sunpack.exe'));
  RestartWatchAfterUpgrade := False;
  ExistingWatchStateDir := '';
  if ExistingInstallation then
    RestartWatchAfterUpgrade := QueryExistingWatchRunning(ExistingWatchStateDir);
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
  if not ClearProgramDataExceptPersistentFiles(ExistingInstallation, ExistingWatchStateDir) then
  begin
    Result := CustomMessage('PrepareOldFilesRemoveFailed');
    Exit;
  end;
  if not ClearInstallDirectory then
  begin
    Result := CustomMessage('PrepareOldFilesRemoveFailed');
    Exit;
  end;
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  Result := StopExistingProcessesAndWait;
  if Result then
    Result := StopAndDeleteBrokerService;
  if not Result then
    MsgBox(CustomMessage('UninstallStopFailed'), mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    EnsureLocalizedEditableConfigFiles;
    InstallBrokerService;
    if not Exec(
      ExpandConstant('{app}\sunpack-runtime.exe'),
      '--register-toast',
      '',
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    ) then
      RaiseException(CustomMessage('ToastRegisterLaunchFailed'))
    else if ResultCode <> 0 then
      RaiseException(Format(CustomMessage('ToastRegisterCommandFailed'), [ResultCode]));
    if ExistingInstallation then
      RestoreWatchAfterUpgrade
    else
    begin
      if WizardIsTaskSelected('addtopath') and not AddMachinePath then
        RaiseException(CustomMessage('TaskAddToPathFailed'));
      if WizardIsTaskSelected('contextmenu') then
      begin
        if not RunContextMenuScript(True) then
          RaiseException(CustomMessage('TaskContextMenuFailed'));
      end;
    end;
    ApplySelectedStartupState;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopAndDeleteBrokerService;
    RunContextMenuScript(False);
    RemoveMachinePath;
  end;
end;