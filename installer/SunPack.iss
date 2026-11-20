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
CloseApplicationsFilter=*.exe,*.dll,*.pyd
RestartApplications=no
UsePreviousAppDir=yes
UsePreviousTasks=yes
UsedUserAreasWarning=no
MinVersion=10.0.16299

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
; Traditional Chinese compiler messages from https://github.com/jrsoftware/issrc/blob/c34976f7d107e94d4fce8ac29f72ca33762293d7/Files/Languages/ChineseTraditional.isl
Name: "chinesetraditional"; MessagesFile: "Languages\ChineseTraditional.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"

[CustomMessages]
english.ConfigLanguage=en
english.TaskAddToPath=Add sunpack to the system PATH
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
english.StartupEnableLaunchFailed=Failed to launch the startup configuration script.
english.StartupEnableCommandFailed=The startup configuration script failed (exit code %d).
english.ToastRegisterLaunchFailed=Failed to launch the notification registration script.
english.ToastRegisterCommandFailed=The notification registration script failed (exit code %d).
english.TaskAddToPathFailed=Failed to add sunpack to the system PATH.
english.TaskContextMenuFailed=Failed to register the sunpack folder context menu.
english.TaskContextMenuRemoveFailed=Failed to remove the existing sunpack context menu.
english.PrepareRuntimeRunning=sunpack runtime processes are still running. Please stop them and run the installer again.
english.PrepareBrokerRemoveFailed=The existing sunpack Watch Broker service could not be removed. Restart Windows and run the installer again.
english.PrepareDataUpgradeFailed=Could not prepare the SunPack data upgrade. Check the configuration and folder access before retrying.
english.PrepareOldFilesRemoveFailed=Some old sunpack files could not be removed. Close sunpack and run the installer again.
english.UninstallStopFailed=sunpack runtime processes or the Watch Broker service could not be stopped. Please restart Windows and run the uninstaller again.
english.DataDirectoryPermissionsFailed=Failed to secure the SunPack data directory: %s
english.WatchRootsFileHeader=# Watched folders. Add one folder per line.
english.WatchRootsFileMapping=# Columns: input folder | output folder | deep_detect | initial_scanned | recursive | enabled
english.WatchRootsFileDeepDetect=# deep_detect accepts true or false; blank defaults to false.
english.WatchRootsFileExample=# Example: C:\Downloads | D:\Extracted | true | false | false | true
english.EditableConfigCreateFailed=Failed to create the initial editable configuration file: %s
english.ConfigLanguageInitializationFailed=Failed to initialize SunPack configuration language.
chinesesimplified.ConfigLanguage=zh
chinesesimplified.TaskAddToPath=将 sunpack 添加到系统 PATH
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
chinesesimplified.StartupEnableLaunchFailed=无法运行开机启动配置脚本。
chinesesimplified.StartupEnableCommandFailed=开机启动配置脚本执行失败（退出码 %d）。
chinesesimplified.ToastRegisterLaunchFailed=无法运行通知注册脚本。
chinesesimplified.ToastRegisterCommandFailed=通知注册脚本执行失败（退出码 %d）。
chinesesimplified.TaskAddToPathFailed=无法将 sunpack 添加到系统 PATH。
chinesesimplified.TaskContextMenuFailed=无法注册 sunpack 文件夹右键菜单。
chinesesimplified.TaskContextMenuRemoveFailed=无法清理现有 sunpack 右键菜单。
chinesesimplified.PrepareRuntimeRunning=sunpack 运行时进程仍在运行。请先停止这些进程，然后重新运行安装程序。
chinesesimplified.PrepareBrokerRemoveFailed=无法删除现有 sunpack Watch Broker 服务。请重启 Windows，然后重新运行安装程序。
chinesesimplified.PrepareDataUpgradeFailed=无法准备 SunPack 数据升级。请检查配置和目录权限后重试。
chinesesimplified.PrepareOldFilesRemoveFailed=无法删除部分旧版 sunpack 文件。请关闭 sunpack，然后重新运行安装程序。
chinesesimplified.UninstallStopFailed=无法停止 sunpack 运行时进程或 Watch Broker 服务。请重启 Windows，然后重新运行卸载程序。
chinesesimplified.DataDirectoryPermissionsFailed=无法设置 SunPack 数据目录权限：%s
chinesesimplified.WatchRootsFileHeader=# 监控文件夹配置，每行填写一个监控目录。
chinesesimplified.WatchRootsFileMapping=# 字段格式：输入目录 | 输出目录 | deep_detect | initial_scanned | recursive | enabled
chinesesimplified.WatchRootsFileDeepDetect=# deep_detect 可填写 true 或 false；留空时默认为 false。
chinesesimplified.WatchRootsFileExample=# 示例：C:\Downloads | D:\Extracted | true | false | false | true
chinesesimplified.EditableConfigCreateFailed=无法创建初始可编辑配置文件：%s
chinesesimplified.ConfigLanguageInitializationFailed=无法初始化 SunPack 配置语言。
chinesetraditional.ConfigLanguage=zh-TW
chinesetraditional.TaskAddToPath=將 sunpack 加入系統 PATH
chinesetraditional.TaskContextMenu=註冊 sunpack 資料夾右鍵選單
chinesetraditional.TaskAutostart=Windows 啟動時執行 sunpack 監控
chinesetraditional.GroupShellIntegration=檔案總管整合：
chinesetraditional.GroupBackgroundWatch=背景監控：
chinesetraditional.WatchBrokerDisplayName=sunpack 監控代理服務
chinesetraditional.WatchBrokerDescription=在 sunpack 監控執行期間，以最低必要權限讀取 NTFS USN 日誌。
chinesetraditional.BrokerExecutableMissing=安裝套件缺少 Watch Broker 執行檔：%s
chinesetraditional.BrokerCreateFailed=無法建立 %s（sc.exe 結束代碼 %d）。
chinesetraditional.BrokerSidTypeFailed=無法設定服務 SID 類型（sc.exe 結束代碼 %d）。
chinesetraditional.BrokerSecurityFailed=無法設定 Watch Broker 服務權限（sc.exe 結束代碼 %d）。
chinesetraditional.StartupEnableLaunchFailed=無法執行開機啟動設定指令碼。
chinesetraditional.StartupEnableCommandFailed=開機啟動設定指令碼執行失敗（結束代碼 %d）。
chinesetraditional.ToastRegisterLaunchFailed=無法執行通知註冊指令碼。
chinesetraditional.ToastRegisterCommandFailed=通知註冊指令碼執行失敗（結束代碼 %d）。
chinesetraditional.TaskAddToPathFailed=無法將 sunpack 加入系統 PATH。
chinesetraditional.TaskContextMenuFailed=無法註冊 sunpack 資料夾右鍵選單。
chinesetraditional.TaskContextMenuRemoveFailed=無法移除現有的 sunpack 右鍵選單。
chinesetraditional.PrepareRuntimeRunning=sunpack 執行階段程序仍在執行。請先停止這些程序，再重新執行安裝程式。
chinesetraditional.PrepareBrokerRemoveFailed=無法移除現有的 sunpack Watch Broker 服務。請重新啟動 Windows，再重新執行安裝程式。
chinesetraditional.PrepareDataUpgradeFailed=無法準備 SunPack 資料升級。請檢查設定和資料夾權限後再試一次。
chinesetraditional.PrepareOldFilesRemoveFailed=無法移除部分舊版 sunpack 檔案。請關閉 sunpack，再重新執行安裝程式。
chinesetraditional.UninstallStopFailed=無法停止 sunpack 執行階段程序或 Watch Broker 服務。請重新啟動 Windows，再重新執行解除安裝程式。
chinesetraditional.DataDirectoryPermissionsFailed=無法設定 SunPack 資料目錄權限：%s
chinesetraditional.WatchRootsFileHeader=# 監控資料夾設定，每行填寫一個監控目錄。
chinesetraditional.WatchRootsFileMapping=# 欄位格式：輸入目錄 | 輸出目錄 | deep_detect | initial_scanned | recursive | enabled
chinesetraditional.WatchRootsFileDeepDetect=# deep_detect 可填寫 true 或 false，空白時預設為 false。
chinesetraditional.WatchRootsFileExample=# 例如：C:\Downloads | D:\Extracted | true | false | false | true
chinesetraditional.EditableConfigCreateFailed=無法建立初始的可編輯設定檔：%s
chinesetraditional.ConfigLanguageInitializationFailed=無法初始化 SunPack 的語言設定。
japanese.ConfigLanguage=ja
japanese.TaskAddToPath=システムの PATH に sunpack を追加する
japanese.TaskContextMenu=フォルダーの右クリックメニューに sunpack を登録する
japanese.TaskAutostart=Windows の起動時に sunpack の監視を開始する
japanese.GroupShellIntegration=エクスプローラーとの統合：
japanese.GroupBackgroundWatch=バックグラウンド監視：
japanese.WatchBrokerDisplayName=sunpack 監視ブローカー
japanese.WatchBrokerDescription=sunpack の監視中に、必要最小限の権限で NTFS の USN ジャーナルを読み取ります。
japanese.BrokerExecutableMissing=インストールパッケージに Watch Broker の実行ファイルがありません：%s
japanese.BrokerCreateFailed=%s を作成できませんでした（sc.exe の終了コード %d）。
japanese.BrokerSidTypeFailed=サービスの SID の種類を設定できませんでした（sc.exe の終了コード %d）。
japanese.BrokerSecurityFailed=Watch Broker サービスのアクセス権を設定できませんでした（sc.exe の終了コード %d）。
japanese.StartupEnableLaunchFailed=自動起動を設定するスクリプトを実行できませんでした。
japanese.StartupEnableCommandFailed=自動起動の設定に失敗しました（終了コード %d）。
japanese.ToastRegisterLaunchFailed=通知を登録するスクリプトを実行できませんでした。
japanese.ToastRegisterCommandFailed=通知の登録に失敗しました（終了コード %d）。
japanese.TaskAddToPathFailed=システムの PATH に sunpack を追加できませんでした。
japanese.TaskContextMenuFailed=フォルダーの右クリックメニューに sunpack を登録できませんでした。
japanese.TaskContextMenuRemoveFailed=既存の sunpack の右クリックメニューを削除できませんでした。
japanese.PrepareRuntimeRunning=sunpack のランタイムプロセスが実行中です。終了してから、インストーラーを再実行してください。
japanese.PrepareBrokerRemoveFailed=既存の sunpack Watch Broker サービスを削除できませんでした。Windows を再起動してから、インストーラーを再実行してください。
japanese.PrepareDataUpgradeFailed=SunPack データの更新を準備できませんでした。設定とフォルダーのアクセス権を確認してから再試行してください。
japanese.PrepareOldFilesRemoveFailed=古い sunpack ファイルの一部を削除できませんでした。sunpack を終了してから、インストーラーを再実行してください。
japanese.UninstallStopFailed=sunpack のランタイムプロセスまたは Watch Broker サービスを停止できませんでした。Windows を再起動してから、アンインストーラーを再実行してください。
japanese.DataDirectoryPermissionsFailed=SunPack のデータフォルダーのアクセス権を設定できませんでした：%s
japanese.WatchRootsFileHeader=# 監視するフォルダーを 1 行に 1 つずつ指定します。
japanese.WatchRootsFileMapping=# 列の順序：入力フォルダー | 出力フォルダー | deep_detect | initial_scanned | recursive | enabled
japanese.WatchRootsFileDeepDetect=# deep_detect には true または false を指定します。空欄の場合は false になります。
japanese.WatchRootsFileExample=# 例：C:\Downloads | D:\Extracted | true | false | false | true
japanese.EditableConfigCreateFailed=編集可能な初期設定ファイルを作成できませんでした：%s
japanese.ConfigLanguageInitializationFailed=SunPack の言語設定を初期化できませんでした。
korean.ConfigLanguage=ko
korean.TaskAddToPath=시스템 PATH에 sunpack 추가
korean.TaskContextMenu=폴더의 오른쪽 클릭 메뉴에 sunpack 등록
korean.TaskAutostart=Windows 시작 시 sunpack 모니터링 시작
korean.GroupShellIntegration=파일 탐색기 통합:
korean.GroupBackgroundWatch=백그라운드 모니터링:
korean.WatchBrokerDisplayName=sunpack 모니터링 브로커
korean.WatchBrokerDescription=sunpack 모니터링 중에 필요한 최소 권한으로 NTFS USN 저널을 읽습니다.
korean.BrokerExecutableMissing=설치 패키지에 Watch Broker 실행 파일이 없습니다: %s
korean.BrokerCreateFailed=%s을(를) 만들 수 없습니다(sc.exe 종료 코드 %d).
korean.BrokerSidTypeFailed=서비스 SID 유형을 설정할 수 없습니다(sc.exe 종료 코드 %d).
korean.BrokerSecurityFailed=Watch Broker 서비스 권한을 설정할 수 없습니다(sc.exe 종료 코드 %d).
korean.StartupEnableLaunchFailed=자동 시작 설정 스크립트를 실행할 수 없습니다.
korean.StartupEnableCommandFailed=자동 시작 설정에 실패했습니다(종료 코드 %d).
korean.ToastRegisterLaunchFailed=알림 등록 스크립트를 실행할 수 없습니다.
korean.ToastRegisterCommandFailed=알림을 등록하지 못했습니다(종료 코드 %d).
korean.TaskAddToPathFailed=시스템 PATH에 sunpack을 추가할 수 없습니다.
korean.TaskContextMenuFailed=폴더의 오른쪽 클릭 메뉴에 sunpack을 등록할 수 없습니다.
korean.TaskContextMenuRemoveFailed=기존 sunpack 오른쪽 클릭 메뉴를 제거할 수 없습니다.
korean.PrepareRuntimeRunning=sunpack 런타임 프로세스가 실행 중입니다. 프로세스를 종료한 후 설치 프로그램을 다시 실행하세요.
korean.PrepareBrokerRemoveFailed=기존 sunpack Watch Broker 서비스를 제거할 수 없습니다. Windows를 다시 시작한 후 설치 프로그램을 다시 실행하세요.
korean.PrepareDataUpgradeFailed=SunPack 데이터 업그레이드를 준비할 수 없습니다. 설정과 폴더 권한을 확인한 후 다시 시도하세요.
korean.PrepareOldFilesRemoveFailed=이전 버전의 sunpack 파일 일부를 제거할 수 없습니다. sunpack을 종료한 후 설치 프로그램을 다시 실행하세요.
korean.UninstallStopFailed=sunpack 런타임 프로세스 또는 Watch Broker 서비스를 중지할 수 없습니다. Windows를 다시 시작한 후 제거 프로그램을 다시 실행하세요.
korean.DataDirectoryPermissionsFailed=SunPack 데이터 폴더 권한을 설정할 수 없습니다: %s
korean.WatchRootsFileHeader=# 모니터링할 폴더를 한 줄에 하나씩 입력합니다.
korean.WatchRootsFileMapping=# 열 순서: 입력 폴더 | 출력 폴더 | deep_detect | initial_scanned | recursive | enabled
korean.WatchRootsFileDeepDetect=# deep_detect에는 true 또는 false를 입력합니다. 비워 두면 false로 설정됩니다.
korean.WatchRootsFileExample=# 예: C:\Downloads | D:\Extracted | true | false | false | true
korean.EditableConfigCreateFailed=편집 가능한 초기 설정 파일을 만들 수 없습니다: %s
korean.ConfigLanguageInitializationFailed=SunPack 언어 설정을 초기화할 수 없습니다.

[Tasks]
Name: "addtopath"; Description: "{cm:TaskAddToPath}"; GroupDescription: "{cm:GroupShellIntegration}"
Name: "contextmenu"; Description: "{cm:TaskContextMenu}"; GroupDescription: "{cm:GroupShellIntegration}"
Name: "autostart"; Description: "{cm:TaskAutostart}"; GroupDescription: "{cm:GroupBackgroundWatch}"; Flags: unchecked

[Files]
; Keep preparation inputs first for early extraction with solid compression.
Source: "{#SourceDir}\sunpack_config.json"; DestDir: "{tmp}"; DestName: "sunpack-config-template.json"; Flags: deleteafterinstall
Source: "{#SourceDir}\scripts\upgrade_config.ps1"; DestDir: "{tmp}\SunPackInstallScripts"; Flags: deleteafterinstall
Source: "integration.ps1"; DestName: "sunpack-install-integration.ps1"; Flags: dontcopy
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "sunpack.exe,sunpack_config.json,sunpack_watch_roots.txt,builtin_passwords.json,scripts\upgrade_config.ps1,scripts\initialize_config_language.ps1"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\sunpack.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "integration.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
Source: "{#SourceDir}\sunpack_config.json"; DestDir: "{commonappdata}\SunPack"; Flags: onlyifdoesntexist
Source: "{#SourceDir}\scripts\initialize_config_language.ps1"; DestDir: "{tmp}\SunPackInstallScripts"; Flags: deleteafterinstall
Source: "{#SourceDir}\builtin_passwords.json"; DestDir: "{commonappdata}\SunPack"; Flags: onlyifdoesntexist

[Dirs]
Name: "{app}"; Flags: uninsalwaysuninstall
Name: "{commonappdata}\SunPack"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\*"
Type: dirifempty; Name: "{app}"
Type: filesandordirs; Name: "{commonappdata}\SunPack"
Type: files; Name: "{commonprograms}\SunPack\Uninstall SunPack.lnk"

[Icons]
Name: "{autoprograms}\SunPack\SunPack GUI"; Filename: "{app}\SunPackGUI.exe"; WorkingDir: "{commonappdata}\SunPack"; IconFilename: "{app}\sunpack.ico"
Name: "{autoprograms}\SunPack\Uninstall SunPack"; Filename: "{uninstallexe}"

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\scripts\integration.ps1"" -Action DisableStartup"; RunOnceId: "SunPackStartup"; Flags: runhidden waituntilterminated
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\scripts\integration.ps1"" -Action DisableContextMenu"; RunOnceId: "SunPackContextMenu"; Flags: runhidden waituntilterminated
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\scripts\integration.ps1"" -Action UninstallToast"; RunOnceId: "SunPackToast"; Flags: runhidden waituntilterminated
Filename: "{app}\bin\sunpack.exe"; Parameters: "daemon stop"; RunOnceId: "SunPackFinalRuntimeShutdown"; Flags: runhidden waituntilterminated skipifdoesntexist
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\scripts\wait_sunpack_runtime_exit.ps1"" -CliAppPath ""{app}\bin\sunpack.exe"" -RuntimeAppPath ""{app}\sunpack-runtime.exe"" -TimeoutSeconds 20"; RunOnceId: "SunPackFinalRuntimeWait"; Flags: runhidden waituntilterminated

[Code]
const
  SunPackRegistryKey = 'Software\SunPack';
  EnvironmentRegistryKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';
  StartupRegistryKey = 'Software\Microsoft\Windows\CurrentVersion\Run';
  StartupValueName = 'SunPackWatchService';
  PathMarkerName = 'PathAddedByInstaller';
  WatchBrokerServiceName = 'SunPackWatchBroker';
  WatchBrokerServiceSddl = 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LCRP;;;IU)';

var
  ContextMenuTaskDefaultApplied: Boolean;
  MigrateLegacyContextMenu: Boolean;

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
  StringChangeEx(Value, '/', '\', True);
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

function InstallerOwnsMachinePath: Boolean;
var
  WasAdded: Cardinal;
begin
  Result := RegQueryDWordValue(HKLM, SunPackRegistryKey, PathMarkerName, WasAdded) and (WasAdded = 1);
end;

function PathWithoutEntry(const PathValue, Entry: string): string;
var
  Remaining: string;
  Token: string;
begin
  Result := '';
  Remaining := PathValue;
  while Remaining <> '' do
  begin
    Token := PopPathEntry(Remaining);
    if (Trim(Token) <> '') and (NormalizePathEntry(Token) <> NormalizePathEntry(Entry)) then
    begin
      if Result <> '' then
        Result := Result + ';';
      Result := Result + Trim(Token);
    end;
  end;
end;

function AddMachinePath: Boolean;
var
  CurrentPath: string;
  AppPath: string;
  NewPath: string;
begin
  AppPath := ExpandConstant('{app}\bin');
  if not RegQueryStringValue(HKLM, EnvironmentRegistryKey, 'Path', CurrentPath) then
    CurrentPath := '';
  NewPath := CurrentPath;
  if not PathContains(NewPath, AppPath) then
  begin
    if (NewPath <> '') and (NewPath[Length(NewPath)] <> ';') then
      NewPath := NewPath + ';';
    NewPath := NewPath + AppPath;
  end;
  if NewPath = CurrentPath then
  begin
    Result := True;
    Exit;
  end;
  Result := RegWriteExpandStringValue(HKLM, EnvironmentRegistryKey, 'Path', NewPath);
  if Result then
    Result := RegWriteDWordValue(HKLM, SunPackRegistryKey, PathMarkerName, 1);
end;

function RemoveMachinePath(const AppDirectory: string): Boolean;
var
  CurrentPath: string;
  NewPath: string;
begin
  Result := True;
  if not InstallerOwnsMachinePath then
    Exit;
  if not RegQueryStringValue(HKLM, EnvironmentRegistryKey, 'Path', CurrentPath) then
    CurrentPath := '';
  NewPath := PathWithoutEntry(CurrentPath, AppDirectory);
  NewPath := PathWithoutEntry(NewPath, AddBackslash(AppDirectory) + 'bin');
  Result := RegWriteExpandStringValue(HKLM, EnvironmentRegistryKey, 'Path', NewPath);
  if not Result then
  begin
    Log('Failed to remove SunPack from the system PATH.');
    Exit;
  end;
  RegDeleteValue(HKLM, SunPackRegistryKey, PathMarkerName);
  RegDeleteKeyIfEmpty(HKLM, SunPackRegistryKey);
end;

function PowerShellSingleQuotedString(Value: string): string;
begin
  StringChangeEx(Value, '''', '''''', True);
  Result := '''' + Value + '''';
end;

procedure ConfigureDataDirectoryPermissions(const DataPath: string);
var
  Command, Parameters: string;
  ResultCode: Integer;
begin
  Command :=
    '$ErrorActionPreference = ''Stop''; ' +
    '$dataPath = ' + PowerShellSingleQuotedString(DataPath) + '; ' +
    'if ([IO.File]::GetAttributes($dataPath) -band [IO.FileAttributes]::ReparsePoint) { throw ''SunPack data directory is a reparse point'' }; ' +
    '$acl = [Security.AccessControl.DirectorySecurity]::new(); ' +
    '$acl.SetSecurityDescriptorSddlForm(''D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)'', [Security.AccessControl.AccessControlSections]::Access); ' +
    '[IO.Directory]::SetAccessControl($dataPath, $acl); ' +
    'if ([IO.Directory]::GetFileSystemEntries($dataPath).Length -gt 0) { ' +
    '  & ' + PowerShellSingleQuotedString(ExpandConstant('{sys}\icacls.exe')) + ' ($dataPath + ''\*'') /reset /T /L /Q; ' +
    '  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; ' +
    '}';
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' + AddQuotes(Command);
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
              Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException(Format(CustomMessage('DataDirectoryPermissionsFailed'), [DataPath]))
  else if ResultCode <> 0 then
  begin
    Log(Format('SunPack data directory ACL repair failed: %d', [ResultCode]));
    RaiseException(Format(CustomMessage('DataDirectoryPermissionsFailed'), [DataPath]));
  end;
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

function InstalledVersion: string;
begin
  RegQueryStringValue(HKLM64,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}_is1',
    'DisplayVersion', Result);
end;

function RemoveDataDirectory(const Path: string): Boolean;
begin
  Result := not DirExists(Path);
  if not Result then
    Result := DelTree(Path, True, True, True);
end;

function ExistingApplicationDirectory: string;
begin
  if not RegQueryStringValue(HKLM64,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}_is1',
    'InstallLocation', Result) or (Trim(Result) = '') then
    Result := ExpandConstant('{app}');
end;

function ExistingLauncherPath: string;
begin
  Result := AddBackslash(ExistingApplicationDirectory) + 'bin\sunpack.exe';
  if not FileExists(Result) then
    Result := AddBackslash(ExistingApplicationDirectory) + 'sunpack.exe';
end;

function QueryExistingWatchRunning: Boolean;
var
  ExistingApp, Command, Parameters: string;
  ResultCode: Integer;
begin
  Result := False;
  ExistingApp := ExistingLauncherPath;
  if not FileExists(ExistingApp) then
    Exit;

  Command :=
    '$ErrorActionPreference = ''Stop''; ' +
    'try { ' +
    '  $json = (& ' + PowerShellSingleQuotedString(ExistingApp) + ' watch status -j 2>$null | Out-String); ' +
    '  if ($LASTEXITCODE -ne 0) { exit 2 }; ' +
    '  $status = $json | ConvertFrom-Json; ' +
    '  if ($status.summary.running -isnot [bool]) { exit 2 }; ' +
    '  if ($status.summary.running) { exit 0 }; ' +
    '  exit 1; ' +
    '} catch { exit 2 }';
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' + AddQuotes(Command);
  ResultCode := -1;
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
              Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Failed to query the existing SunPack Watch state before upgrade.')
  else if ResultCode = 0 then
  begin
    Result := True;
    Log('Existing SunPack Watch is running and will be restored after upgrade.');
  end
  else if ResultCode = 1 then
    Log('Existing SunPack Watch is not running; upgrade will leave it stopped.')
  else
    Log(Format('Existing SunPack Watch state query failed with exit code %d; upgrade will not auto-start Watch.', [ResultCode]));
end;

function RunInstallerIntegration(const Action: string; var ResultCode: Integer): Boolean;
var
  Parameters: string;
begin
  ResultCode := -1;
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
    AddQuotes(ExpandConstant('{app}\scripts\integration.ps1')) + ' -Action ' + Action;
  if MigrateLegacyContextMenu and (Action = 'EnableContextMenu') then
    Parameters := Parameters + ' -MigrateContextMenu';
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Parameters, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure ApplySelectedContextMenuState;
var
  Action: string;
  ResultCode: Integer;
begin
  if WizardIsTaskSelected('contextmenu') then
    Action := 'EnableContextMenu'
  else
    Action := 'DisableContextMenu';

  if not RunInstallerIntegration(Action, ResultCode) or (ResultCode <> 0) then
  begin
    Log(Format('Current-user context menu helper (%s) failed with code %d.', [Action, ResultCode]));
    if Action = 'EnableContextMenu' then
      RaiseException(CustomMessage('TaskContextMenuFailed'))
    else
      RaiseException(CustomMessage('TaskContextMenuRemoveFailed'));
  end;
end;

procedure StopExistingProcesses;
var
  ExistingApp: string;
  ResultCode: Integer;
begin
  ExistingApp := ExistingLauncherPath;
  if not FileExists(ExistingApp) then
    Exit;
  // This internal command also works with the version being upgraded.
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
  GuiAppPath: string;
  Command: string;
  Parameters: string;
  ResultCode: Integer;
begin
  Result := True;
  CliAppPath := ExistingLauncherPath;
  RuntimeAppPath := AddBackslash(ExistingApplicationDirectory) + 'sunpack-runtime.exe';
  GuiAppPath := AddBackslash(ExistingApplicationDirectory) + 'SunPackGUI.exe';
  if (not FileExists(CliAppPath)) and (not FileExists(RuntimeAppPath)) and (not FileExists(GuiAppPath)) then
    Exit;
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Command :=
    '$gui = ' + PowerShellSingleQuotedString(GuiAppPath) + '; ' +
    'Get-Process SunPackGUI -ErrorAction SilentlyContinue | Where-Object { try { $_.Path.Equals($gui, [System.StringComparison]::OrdinalIgnoreCase) } catch { $false } } | ForEach-Object { [void]$_.CloseMainWindow() }; ' +
    '$targets = @(' + PowerShellSingleQuotedString(CliAppPath) + ', ' + PowerShellSingleQuotedString(RuntimeAppPath) + ', $gui); ' +
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

procedure AppendTextLine(var Lines: TArrayOfString; const Line: string);
var
  Index: Integer;
begin
  Index := GetArrayLength(Lines);
  SetArrayLength(Lines, Index + 1);
  Lines[Index] := Line;
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
  if not ForceDirectories(DataPath) then
    RaiseException(Format(CustomMessage('EditableConfigCreateFailed'), [DataPath]));
  { [Dirs]/[Files] already created this directory before ssPostInstall.
    Repair upgrades too, including children created by elevated installers. }
  ConfigureDataDirectoryPermissions(DataPath);

  FilePath := AddBackslash(DataPath) + 'sunpack_watch_roots.txt';
  if not FileExists(FilePath) then
  begin
    SetArrayLength(Contents, 0);
    AppendTextLine(Contents, CustomMessage('WatchRootsFileHeader'));
    AppendTextLine(Contents, CustomMessage('WatchRootsFileMapping'));
    AppendTextLine(Contents, CustomMessage('WatchRootsFileDeepDetect'));
    AppendTextLine(Contents, CustomMessage('WatchRootsFileExample'));
    SaveUTF8TextLines(FilePath, Contents);
  end;
end;

var
  StartupTaskDefaultApplied: Boolean;
  ExistingWatchStateCaptured: Boolean;
  RestartWatchAfterUpgrade: Boolean;
  UpgradePrepared: Boolean;
  InitializeLanguageOnInstall: Boolean;

procedure RestoreWatchAfterUpgrade;
var
  ResultCode: Integer;
begin
  if not RestartWatchAfterUpgrade then
    Exit;

  if not RunInstallerIntegration('StartDaemon', ResultCode) then
    Log('Failed to run the unelevated SunPack Watch restore helper after upgrade.')
  else if ResultCode <> 0 then
    Log(Format('SunPack Watch restore helper exited with code %d.', [ResultCode]))
  else
  begin
    RestartWatchAfterUpgrade := False;
    Log('SunPack Watch was restored after upgrade.');
  end;
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
  if not FileExists(ExistingLauncherPath) then
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
    StartupAction := 'EnableStartup'
  else
    StartupAction := 'DisableStartup';

  if not RunInstallerIntegration(StartupAction, ResultCode) then
    RaiseException(CustomMessage('StartupEnableLaunchFailed'))
  else if ResultCode <> 0 then
    RaiseException(Format(CustomMessage('StartupEnableCommandFailed'), [ResultCode]));
end;

procedure InitializeWizard();
begin
  WizardForm.LicenseAcceptedRadio.Checked := True;
  StartupTaskDefaultApplied := False;
end;

procedure ApplyContextMenuTaskDefault;
var
  PreviousApp, PreviousVersion, Parameters: string;
  Version: Int64;
  ResultCode: Integer;
  ParsedVersion: Boolean;
begin
  if ContextMenuTaskDefaultApplied then
    Exit;
  ContextMenuTaskDefaultApplied := True;
  PreviousVersion := Trim(InstalledVersion);
  if Lowercase(Copy(PreviousVersion, 1, 1)) = 'v' then
    Delete(PreviousVersion, 1, 1);
  PreviousApp := AddBackslash(ExistingApplicationDirectory);
  ParsedVersion := StrToVersion(PreviousVersion, Version);
  if not ParsedVersion then
    ParsedVersion := StrToVersion(PreviousVersion + '.0', Version);
  if ParsedVersion then
    MigrateLegacyContextMenu := ComparePackedVersion(Version, PackVersionComponents(1, 5, 1, 0)) < 0
  else
    MigrateLegacyContextMenu :=
      FileExists(PreviousApp + 'scripts\register_context_menu.ps1') or
      FileExists(PreviousApp + 'scripts\unregister_context_menu.ps1');
  if HasExplicitTaskSelection or ((PreviousVersion = '') and not FileExists(ExistingLauncherPath)) then
    Exit;
  { The menu can be toggled in the GUI after installation, so use its live
    state for the default, using the same desktop user as integration. }
  ExtractTemporaryFile('sunpack-install-integration.ps1');
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
    AddQuotes(ExpandConstant('{tmp}\sunpack-install-integration.ps1')) + ' -Action GetContextMenuState';
  if MigrateLegacyContextMenu then Parameters := Parameters + ' -MigrateContextMenu';
  ResultCode := -1;
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
              Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Failed to launch the desktop user context menu state query.')
  else if ResultCode = 0 then WizardSelectTasks('contextmenu')
  else if ResultCode = 10 then WizardSelectTasks('!contextmenu')
  else Log(Format('Desktop user context menu state query failed with exit code %d.', [ResultCode]));
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpSelectTasks then
  begin
    ApplyStartupTaskDefault;
    ApplyContextMenuTaskDefault;
  end;
end;

function UpgradeConfigurationFields: Boolean;
var
  Parameters, PreviousVersion: string;
  ResultCode: Integer;
begin
  { Prepare and validate retained data before replacing the old application.
    The old advanced file is read-only; [Files] deploys its current template. }
  ExtractTemporaryFile('upgrade_config.ps1');
  ExtractTemporaryFile('sunpack-config-template.json');
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
    AddQuotes(ExpandConstant('{tmp}\upgrade_config.ps1')) +
    ' -UserConfig ' + AddQuotes(ExpandConstant('{commonappdata}\SunPack\sunpack_config.json')) +
    ' -TemplateConfig ' + AddQuotes(ExpandConstant('{tmp}\sunpack-config-template.json')) +
    ' -AdvancedConfig ' + AddQuotes(AddBackslash(ExistingApplicationDirectory) + 'sunpack_advanced_config.json');
  PreviousVersion := InstalledVersion;
  if PreviousVersion <> '' then
    Parameters := Parameters + ' -PreviousVersion ' + AddQuotes(PreviousVersion);
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
                 Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if Result then Result := ResultCode = 0;
  if not Result then Log('SunPack upgrade preparation failed; old application files have not been removed.');
end;

procedure InitializeInstalledLanguage;
var
  Parameters: string;
  ResultCode: Integer;
begin
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
    AddQuotes(ExpandConstant('{tmp}\SunPackInstallScripts\initialize_config_language.ps1')) +
    ' -UserConfig ' + AddQuotes(ExpandConstant('{commonappdata}\SunPack\sunpack_config.json')) +
    ' -AdvancedConfig ' + AddQuotes(ExpandConstant('{app}\sunpack_advanced_config.json')) +
    ' -Language ' + AddQuotes(CustomMessage('ConfigLanguage'));
  if InitializeLanguageOnInstall then Parameters := Parameters + ' -InitializeUserConfig';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
              Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    RaiseException(CustomMessage('ConfigLanguageInitializationFailed'));
end;

procedure CleanupInstallScripts;
var
  TempScripts: string;
begin
  TempScripts := ExpandConstant('{tmp}\SunPackInstallScripts');
  if DirExists(TempScripts) then
    if not DelTree(TempScripts, True, True, True) then
      Log('Unable to remove temporary SunPack installation scripts.');
end;

procedure DeinitializeSetup;
begin
  CleanupInstallScripts;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  ApplyStartupTaskDefault;
  ApplyContextMenuTaskDefault;
  { PrepareToInstall can be retried after Watch has already been stopped. }
  if not ExistingWatchStateCaptured then
  begin
    RestartWatchAfterUpgrade := QueryExistingWatchRunning;
    ExistingWatchStateCaptured := True;
  end;
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
  if not UpgradePrepared then
  begin
    InitializeLanguageOnInstall := not FileExists(ExpandConstant('{commonappdata}\SunPack\sunpack_config.json'));
    if not UpgradeConfigurationFields then
    begin
      Result := CustomMessage('PrepareDataUpgradeFailed');
      Exit;
    end;
    { A full-reset upgrade is a fresh language initialization too. }
    InitializeLanguageOnInstall := InitializeLanguageOnInstall or
      not FileExists(ExpandConstant('{commonappdata}\SunPack\sunpack_config.json'));
    UpgradePrepared := True;
  end;
  if not RemoveMachinePath(ExistingApplicationDirectory) then
  begin
    Result := CustomMessage('TaskAddToPathFailed');
    Exit;
  end;
  if not RemoveDataDirectory(ExistingApplicationDirectory) or
     not RemoveDataDirectory(ExpandConstant('{app}')) then
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
    InitializeInstalledLanguage;
    InstallBrokerService;
    if not RunInstallerIntegration('RegisterToast', ResultCode) then
      RaiseException(CustomMessage('ToastRegisterLaunchFailed'))
    else if ResultCode <> 0 then
      RaiseException(Format(CustomMessage('ToastRegisterCommandFailed'), [ResultCode]));
    ApplySelectedContextMenuState;
    if WizardIsTaskSelected('addtopath') then
    begin
      if not AddMachinePath then
        RaiseException(CustomMessage('TaskAddToPathFailed'));
    end;
    ApplySelectedStartupState;
    RestoreWatchAfterUpgrade;
    CleanupInstallScripts;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopAndDeleteBrokerService;
    RemoveMachinePath(ExpandConstant('{app}'));
    { InitializeUninstall already stopped the GUI. Run before deleting the
      helper, under the desktop user token even with cross-account elevation.
      Upgrades never run this handler or write GUI preferences. }
    if not RunInstallerIntegration('RemoveGuiPreferences', ResultCode) or (ResultCode <> 0) then
      Log(Format('Current-user GUI preference cleanup failed with code %d.', [ResultCode]));
  end;
end;
