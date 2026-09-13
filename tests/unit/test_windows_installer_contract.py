from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_installer_is_machine_wide_but_owns_only_its_user_path_entry():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "PrivilegesRequired=admin" in script
    assert "DefaultDirName={autopf}\\SunPack" in script
    assert "PathAddedByInstaller" in script
    assert "procedure AddUserPath" in script
    assert "procedure RemoveUserPath" in script
    assert "RegQueryDWordValue" in script


def test_installer_registers_and_unregisters_context_menu():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "register_context_menu.ps1" in script
    assert "unregister_context_menu.ps1" in script
    assert "WizardIsTaskSelected('contextmenu')" in script
    assert "CurUninstallStepChanged" in script


def test_installer_optionally_registers_watch_autostart():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert 'Name: "autostart"' in script
    assert "english.TaskAutostart=Start sunpack Watch when Windows starts" in script
    assert "chinesesimplified.TaskAutostart=Windows 启动时运行 sunpack 监控" in script
    assert "Software\\Microsoft\\Windows\\CurrentVersion\\Run" in script
    assert 'ValueName: "SunPackWatchService"' in script
    assert 'ValueData: """{app}\\sunpack.exe"" watch start"' in script
    assert "Tasks: autostart" in script
    assert "uninsdeletevalue" in script


def test_installer_does_not_register_start_menu_entries():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "DefaultGroupName" not in script
    assert "DisableProgramGroupPage" not in script
    assert "[Icons]" not in script
    assert "[Run]" not in script
    assert 'Parameters: "--register-toast"' not in script
    assert 'Parameters: "--unregister-toast"' in script
    assert "[UninstallRun]" in script
    assert 'Name: "{userprograms}\\SunPack\\SunPack Command Prompt.lnk"' in script
    assert 'Name: "{userprograms}\\SunPack\\Uninstall SunPack.lnk"' in script
    assert 'Name: "{userprograms}\\SunPack\\SunPack Watch Notifications.lnk"' in script


def test_installer_owns_a_minimal_demand_start_watch_broker_service():
    installer = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")
    build = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    assert "SunPackWatchBroker" in installer
    assert "sunpack-watch-broker.exe" in installer
    assert "start= demand" in installer
    assert "obj= LocalSystem" in installer
    assert "sidtype " in installer and " unrestricted" in installer
    assert "(A;;LCRP;;;IU)" in installer
    assert "InstallBrokerService;" in installer
    assert installer.count("StopAndDeleteBrokerService;") >= 2
    assert "sunpack_watch_broker\\Cargo.toml" in build
    assert 'Join-Path $distAppRoot "service"' in build


def test_privileged_journal_code_is_compiled_only_into_the_service():
    core = (ROOT / "native" / "sunpack_usn_core" / "Cargo.toml").read_text(encoding="utf-8")
    broker = (ROOT / "native" / "sunpack_watch_broker" / "Cargo.toml").read_text(encoding="utf-8")
    native = (ROOT / "native" / "sunpack_native" / "Cargo.toml").read_text(encoding="utf-8")
    client_source = (ROOT / "native" / "sunpack_usn_core" / "src" / "client.rs").read_text(encoding="utf-8")
    journal_source = (ROOT / "native" / "sunpack_usn_core" / "src" / "journal.rs").read_text(encoding="utf-8")

    assert 'default = ["client", "journal"]' in core
    assert 'default-features = false, features = ["journal"]' in broker
    assert 'default-features = false, features = ["client"]' in native
    assert "OpenSCManagerW" in client_source
    assert "FSCTL_QUERY_USN_JOURNAL" not in client_source
    assert "FSCTL_QUERY_USN_JOURNAL" in journal_source
    assert "OpenSCManagerW" not in journal_source


def test_uninstaller_unconditionally_removes_watch_autostart():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "StartupRegistryKey = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'" in script
    assert "StartupValueName = 'SunPackWatchService'" in script
    assert "procedure RemoveStartupRunValue" in script
    assert "RegDeleteValue(HKCU, StartupRegistryKey, StartupValueName)" in script
    assert "RemoveStartupRunValue;" in script


def test_installer_stops_existing_watch_before_upgrade_and_cleans_owned_files():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "procedure StopExistingProcesses" in script
    assert "watch stop" in script
    assert "function PrepareToInstall" in script
    assert "StopExistingProcesses;" in script
    assert "function ClearInstallDirectory: Boolean" in script
    assert "function StopAndDeleteBrokerService: Boolean" in script
    assert "IsPersistentInstallFile" in script
    assert "FindData: TFindRec" in script
    assert "DirExists(ItemPath)" in script
    assert "TFindData" not in script
    assert "sunpack_watch_roots.txt,builtin_passwords.txt" in script
    assert 'Source: "{#SourceDir}\\sunpack_watch_roots.txt"; DestDir: "{localappdata}\\SunPack"; Flags: onlyifdoesntexist skipifsourcedoesntexist' in script
    assert 'Source: "{#SourceDir}\\builtin_passwords.txt"; DestDir: "{localappdata}\\SunPack"; Flags: onlyifdoesntexist skipifsourcedoesntexist' in script
    assert "RunContextMenuScript(False);" in script
    assert "RemoveStartupRunValue;" in script
    assert "RemoveUserPath;" in script


def test_uninstaller_stops_running_watch_before_removing_files():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "function InitializeUninstall(): Boolean" in script
    assert "function WaitForExistingRuntimesToExit: Boolean" in script
    assert "function StopExistingProcessesAndWait: Boolean" in script
    assert "RemoveStartupRunValue;" in script
    assert "Result := StopExistingProcessesAndWait;" in script
    assert "Watch Broker service could not be stopped" in script
    assert "StopAndDeleteBrokerService" in script
    assert "Get-Process -ErrorAction SilentlyContinue" in script
    assert "RuntimeAppPath := ExpandConstant('{app}\\sunpack-runtime.exe')" in script
    assert "$targets = @(" in script
    assert "CliAppPath: string;" in script
    assert "RuntimeAppPath: string;" in script
    assert "ExpandConstant('{app}\\sunpack.exe')" in script
    assert "$deadline = (Get-Date).AddSeconds(20)" in script
    assert "Start-Sleep -Milliseconds 250" in script


def test_uninstaller_removes_generated_watch_and_cache_state():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "[UninstallDelete]" in script
    assert 'Type: filesandordirs; Name: "{app}\\*"' in script
    assert 'Type: dirifempty; Name: "{app}"' in script
    assert 'Type: filesandordirs; Name: "{localappdata}\\SunPack"' in script


def test_installer_declares_x64_and_arm64_modes():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert 'TargetArch == "arm64"' in script
    assert "ArchitecturesAllowed=arm64" in script
    assert "ArchitecturesAllowed=x64compatible" in script


def test_build_and_release_workflow_publish_installers_only():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "-setup.exe" in build_script
    assert "Get-InnoSetupCompiler" in build_script
    assert "Creating distributable zip archive" not in build_script
    assert "$releaseZipPath" not in build_script
    assert "portable archive" not in workflow
    assert "sunpack-windows-*.zip" not in workflow
    assert "test_windows_installer.ps1" in workflow
    assert "Expected one Windows installer" in workflow
    assert "*-setup.exe" in workflow


def test_local_build_requires_inno_setup():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    assert "[switch]$SkipInstaller" not in build_script
    assert "[switch]$RequireInstaller" not in build_script
    assert "$innoCompiler = Get-InnoSetupCompiler -PreferredPath $InnoCompilerPath" in build_script
    assert "Install JRSoftware.InnoSetup or pass -InnoCompilerPath" in build_script


def test_installer_build_uses_unique_staging_output_before_publishing():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    assert 'Join-Path $buildRoot "inno-staging"' in build_script
    assert '[guid]::NewGuid().ToString("N")' in build_script
    assert '"/DOutputDir=$installerStagingRoot"' in build_script
    assert '"/DOutputBaseFilename=$attemptBaseName"' in build_script
    assert '"/DOutputDir=$releaseRoot"' not in build_script
    assert "Wait-FileReadyForPromotion -LiteralPath $attemptInstallerPath" in build_script
    assert (
        "Move-Item -LiteralPath $attemptInstallerPath "
        "-Destination $releaseInstallerPath -Force"
    ) in build_script
    assert "[Math]::Max(1, $DelaySeconds) * $attempt" in build_script


def test_build_notes_handles_recreated_tags_and_noninteractive_log_output():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "git fetch --force --prune --tags" in workflow
    assert '--exclude="${current_tag}"' in workflow
    assert 'commits="$(git log --format=\'- %s (%h)\' "${range}")"' in workflow
    assert 'if [ -n "${commits}" ]; then' in workflow
    assert "grep -q" not in workflow


def test_build_uses_nuitka_only():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "Packager" not in build_script
    assert "PyInstaller" not in build_script
    assert not (ROOT / "SunPack.spec").exists()
    assert '"-m", "nuitka"' in build_script
    assert '"--standalone"' in build_script
    assert '"--windows-console-mode=$ConsoleMode"' in build_script
    assert '"--lto=yes"' in build_script
    assert '"--pgo-c"' in build_script
    assert '"--pgo-args=$PgoArgs"' in build_script
    assert '-PgoArgs "--help"' in build_script
    assert build_script.count("Invoke-NuitkaStandaloneBuild -PythonPath") == 1
    assert "$nuitkaWatchDist" not in build_script
    assert 'Embed-WindowsApplicationManifest -PythonPath $venvPython' in build_script
    assert '"scripts\\embed_windows_manifest.py"' in build_script
    assert "Invoke-NuitkaStandaloneBuild" in build_script
    assert "sunpack.detection.pipeline.rules.hard_stop" not in build_script
    assert "sunpack.detection.pipeline.rules.confirmation" not in build_script
    assert '"nuitka>=2"' in project
    assert "pyinstaller" not in project.lower()


def test_windows_native_smoke_checks_follow_current_embedded_scan_api():
    smoke_scripts = (
        ROOT / "scripts" / "build_windows.ps1",
        ROOT / "scripts" / "setup_windows_dev.ps1",
        ROOT / "run_acceptance_tests.ps1",
    )

    for path in smoke_scripts:
        script = path.read_text(encoding="utf-8")
        assert "'scan_embedded_archives'" in script, path
        assert "'scan_carrier_archive'" not in script, path
        assert "'scan_directory_entries'" not in script, path


def test_installer_smoke_uses_process_exit_code_for_started_processes():
    script = (ROOT / "scripts" / "test_windows_installer.ps1").read_text(encoding="utf-8")

    assert "Start-Process" in script
    assert "-PassThru" in script
    assert ".WaitForExit(" in script
    assert "$process.ExitCode" in script
    assert "Invoke-UninstallerChecked" in script
    assert "entire descendant tree" in script
    assert "Wait-UninstallCompletion -InstallRoot $installRoot -ServiceName $serviceName" in script
    assert "Command failed with exit code" in script


def test_acceptance_runs_watch_suites_in_current_powershell():
    acceptance = (ROOT / "run_acceptance_tests.ps1").read_text(encoding="utf-8")

    assert '"tests/integration"' in acceptance
    assert '"tests/real"' in acceptance
    assert '"tests/integration", "tests/real"' in acceptance
    assert '"-m", "requires_watch_broker"' not in acceptance
    assert '"-m", "not requires_watch_broker"' not in acceptance
    assert '"-n", "0"' not in acceptance
    assert "-Action Install" in acceptance
    assert "-Action Uninstall" in acceptance
    assert "CompletionReportPath" not in acceptance
    assert "RequiredCompletionSuites" not in acceptance


def test_acceptance_test_steps_run_through_unelevated_runner():
    acceptance = (ROOT / "run_acceptance_tests.ps1").read_text(encoding="utf-8")

    assert '$unelevatedRunner = Join-Path $repoRoot "scripts\\run_unelevated_process.py"' in acceptance
    assert "$runnerArguments += $argsList" in acceptance
    assert "ArgumentList = $runnerArguments" in acceptance
    assert "run_unelevated_process.py" in acceptance


def test_packaged_smoke_tests_shutdown_the_persistent_runtime_before_installer_test():
    build = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    smoke = build.index('Write-Step "Running packaged smoke tests"')
    last_request = build.index(
        'Invoke-Native -FilePath $distExePath -Arguments @("config", "validate", "--json")',
        smoke,
    )
    shutdown = build.index(
        'Invoke-Native -FilePath $distExePath -Arguments @("--persistent-shutdown")',
        last_request,
    )
    wait = build.index("Wait-ExecutableExit -ExecutablePath $distRuntimeExePath", shutdown)

    assert smoke < last_request < shutdown < wait
    assert "Get-CimInstance Win32_Process" in build


def test_elevated_test_failures_are_persisted_and_replayed():
    helper = (ROOT / "scripts" / "test_elevation.ps1").read_text(encoding="utf-8")

    assert "sunpack-elevated-test-" in helper
    assert "*>&1 | Out-File" in helper
    assert "Format-List * -Force" in helper
    assert "Elevated test process failed. Diagnostic log:" in helper
    assert "Get-Content -LiteralPath $diagnosticPath" in helper
    assert "The elevated process did not produce its diagnostic log." in helper


def test_installer_smoke_exercises_generated_uninstall_residue_cleanup():
    script = (ROOT / "scripts" / "test_windows_installer.ps1").read_text(encoding="utf-8")

    assert 'Join-Path $userDataRoot "builtin_passwords.txt"' in script
    assert 'Join-Path $userDataRoot ".sunpack_watch"' in script
    assert 'Join-Path $env:LOCALAPPDATA "SunPack\\cache"' in script
    assert "Upgrade install overwrote the existing builtin password file" in script
    assert "Upgrade install left stale application data behind" in script
    assert "Invoke-UnelevatedChecked" in script
    assert "run_unelevated_process.py" in script
    assert "Upgrade install left stale configuration data behind" in script
    assert "Set-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName" in script
    assert "Uninstaller left the watch state directory behind" in script
    assert "Uninstaller left the local SunPack cache behind" in script


def test_release_packages_copy_only_runtime_tool_files():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts" / "verify_windows_package_arch.ps1").read_text(encoding="utf-8")

    for script in (build_script, verifier):
        assert "function Get-PackagedRuntimeToolNames" in script
        assert '"7z.dll"' in script
        assert '"sunpack_sevenzip.dll"' in script
        assert '"sunpack_sevenzip_worker.exe"' in script
        assert '"sunpack_toast.dll"' in script
        assert "Assert-PackagedRuntimeTools" in script
    assert "Copy-PackagedRuntimeTools -Source $toolsRoot -Destination $distToolsRoot" in build_script
    assert 'Copy-Item -LiteralPath $toolsRoot -Destination $distToolsRoot -Recurse -Force' not in build_script


def test_acceptance_setup_bootstraps_and_checks_real_archive_generators():
    setup_script = (ROOT / "scripts" / "setup_windows_dev.ps1").read_text(encoding="utf-8")
    acceptance_script = (ROOT / "run_acceptance_tests.ps1").read_text(encoding="utf-8")

    assert ".sunpack_test_tools" in setup_script
    assert "winrar-x64-622.exe" in setup_script
    assert "zstd-v1.5.7-win64.zip" in setup_script
    assert "Test-RarGeneratorVersion" in setup_script
    assert "SkipAcceptanceTestTools" in setup_script
    assert "Assert-AcceptanceTestTools" in acceptance_script
    assert "Default.SFX" in acceptance_script
    assert "zstd.exe" in acceptance_script


def test_release_package_uses_native_console_launcher_and_one_shared_gui_runtime():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    assert '$runtimeExeName = "sunpack-runtime.exe"' in build_script
    assert '$watchExeName' not in build_script
    assert "Packaged shared SunPack runtime executable" in build_script
    assert build_script.count("Invoke-NuitkaStandaloneBuild -PythonPath") == 1
    assert 'ConsoleMode "disable"' in build_script
    assert 'Assert-PathMissing -LiteralPath (Join-Path $distAppRoot "sunpack-watch.exe")' in build_script
