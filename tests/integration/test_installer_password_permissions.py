from __future__ import annotations

import json
import re
import subprocess
import uuid
import winreg

from tests.helpers.installer import inno_compiler


def test_installer_resets_pre_130_data_and_preserves_current_data(tmp_path, repo_root):
    # Runtime/ACL tests cannot catch version gating, selective cleanup or install
    # order. Without this harness those failures go undetected; one small build
    # covers that independent boundary, including overlapping state directories.
    compiler = inno_compiler()
    source = (repo_root / "installer/SunPack.iss").read_text(encoding="utf-8-sig")
    registry_key = "Software\\SunPackInstallerTests\\" + uuid.uuid4().hex
    uninstall_key = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}_is1"
    routines = []
    for name in (
        "NormalizePathEntry", "PopPathEntry", "PathContains", "InstallerOwnsMachinePath",
        "PathWithoutEntry", "AddMachinePath", "RemoveMachinePath",
        "PowerShellSingleQuotedString", "VersionBefore", "RequiresDataReset",
        "InstalledVersion", "InstalledDataRequiresReset",
        "RemoveDataDirectory", "ExistingApplicationDirectory", "RemoveInstalledData",
        "ExistingLauncherPath", "CaptureConfigurationForUpgrade", "PrepareToInstall",
    ):
        match = re.search(rf"^(?:function|procedure) {name}\b.*?^end;", source, re.M | re.S)
        assert match is not None, name
        routines.append(match.group().replace("HKLM64", "HKCU").replace("HKLM", "HKCU").replace(uninstall_key, registry_key)
                        .replace(r"{commonappdata}\SunPack", r"{param:Data}"))
    default_files = [line.replace("{#SourceDir}", str(repo_root))
                     .replace(r"{commonappdata}\SunPack", r"{param:Data}")
                     for line in source.splitlines() if line.startswith('Source: "{#SourceDir}\\')
                     and 'DestDir: "{commonappdata}' in line
                     and ('\\sunpack_config.json";' in line or '\\builtin_passwords.json";' in line)]
    assert len(default_files) == 2
    harness = tmp_path / "reset.iss"
    harness.write_text(f"""
[Setup]
AppName=SunPack reset regression
AppVersion=1.3.0
DefaultDirName={{tmp}}\\SunPackResetRegression
PrivilegesRequired=lowest
Uninstallable=no
UsePreviousAppDir=no
DisableDirPage=yes
DisableProgramGroupPage=yes
CloseApplications=no
OutputDir={tmp_path}
OutputBaseFilename=reset
[Files]
{chr(10).join(default_files)}
Source: "{repo_root / 'sunpack_advanced_config.json'}"; DestDir: "{{app}}"; Flags: ignoreversion
[CustomMessages]
PrepareRuntimeRunning=Runtime still running
PrepareBrokerRemoveFailed=Broker still running
PrepareOldFilesRemoveFailed=Cannot remove old files
TaskAddToPathFailed=Cannot update PATH
[Code]
const
  SunPackRegistryKey = '{registry_key}\\integration';
  EnvironmentRegistryKey = '{registry_key}\\environment';
  PathMarkerName = 'PathAddedByInstaller';
var
  StopStage: Integer;
  ExistingWatchStateCaptured, RestartWatchAfterUpgrade: Boolean;
  ConfigBackupCaptured: Boolean;
  InitializeLanguageOnInstall: Boolean;
procedure ApplyStartupTaskDefault;
begin
end;
function QueryExistingWatchRunning: Boolean;
begin
  Result := False;
end;
function StopExistingProcessesAndWait: Boolean;
begin
  StopStage := 1;
  Result := ExpandConstant('{{param:StopFailure|0}}') <> '1';
end;
function StopAndDeleteBrokerService: Boolean;
begin
  if StopStage <> 1 then RaiseException('Broker stopped before runtime');
  StopStage := 2;
  Result := True;
end;
{chr(10).join(routines)}
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if StopStage <> 2 then RaiseException('Installed before runtime/broker stop');
    if ExpandConstant('{{param:AddPath|1}}') = '1' then
      if not AddMachinePath then RaiseException('Cannot add PATH');
    SaveStringToFile(ExpandConstant('{{param:Fixture}}\\completed'), 'ok', False);
  end;
end;
""", encoding="utf-8-sig")
    result = subprocess.run([compiler, "/Qp", str(harness)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    defaults = {name: (repo_root / name).read_bytes()
                for name in ("sunpack_config.json", "builtin_passwords.json")}
    # The malformed-config case proves deletion needs no functioning old runtime
    # or valid schema. The relocated case also resolves state from old defaults.
    cases = (("v1.2.8", True, False, "separate"), ("v1.2.9", True, False, "separate"),
             ("1.3.0", False, False, "separate"), ("1.10.0", False, False, "separate"),
             (None, True, False, "separate"), ("1.2.8", True, True, "separate"),
             ("invalid", True, False, "separate"),
             ("v1.2.8-7-gabcdef0", True, False, "separate"),
             ("1.2.9-7-gabcdef0-dirty", True, False, "separate"),
             ("v1.3.0-7-gabcdef0", False, False, "separate"),
             ("v1.3.1", False, False, "separate"),
             ("1.2.8", True, False, "missing"),
             ("1.2.8", True, False, "same"), ("1.2.8", True, False, "parent"))
    try:
        for index, (version, reset, stop_failure, layout) in enumerate(cases):
            fixture = tmp_path / f"case {index} ' [data]"
            app, data, custom = (fixture / name for name in ("app", "data", "custom ' [watch]"))
            if layout == "same":
                custom = data
            elif layout == "parent":
                data = custom / "data"
            installed = fixture / "previous app" if index in (1, 3) else app
            for directory in {app, data, custom, installed}:
                (directory / "unknown" / "nested").mkdir(parents=True)
                (directory / "unknown" / "nested" / "backup.bak").write_text("old", encoding="utf-8")
            task_files = ["state.snapshot", "state.journal.00000000000000000001.wal",
                          "state.journal.00000000000000000142.wal", "events.jsonl", "state.json",
                          "state.journal.00000000000000000001.jsonl", "events.json"]
            other_files = ["catalog.snapshot.bin", "catalog.wal.bin", "initial_scanned",
                               "state.journal.not-a-sequence.wal"]
            for directory in (data / ".sunpack_watch", custom):
                directory.mkdir(exist_ok=True)
                for name in task_files + other_files:
                    (directory / name).write_text(name, encoding="utf-8")
            # Names are only preserved at the top level of the data directory.
            for name in ("sunpack_watch_roots.txt", "builtin_passwords.json"):
                (data / "unknown" / name).write_text("discard", encoding="utf-8")
            (installed / "bin").mkdir()
            (installed / "bin" / "sunpack.exe").write_text("stub", encoding="utf-8")
            config = {"watch": {"state_dir": str(custom)}, "unknown": "keep current data"}
            (data / "sunpack_config.json").write_text(json.dumps(config), encoding="utf-8")
            roots = "sunpack_watch_roots.txt"
            (data / "builtin_passwords.json").write_text('{"passwords":[{"value":"私有密码"}]}', encoding="utf-8-sig")
            (data / roots).write_text("# 保留注释\nC:\\Downloads | D:\\输出 | true | true | false\n", encoding="utf-8-sig")
            if layout == "missing":
                (data / roots).unlink()
                (data / "builtin_passwords.json").unlink()
            (installed / "sunpack_advanced_config.json").write_text(json.dumps(config), encoding="utf-8")
            if index == 1:
                # Advanced-only custom path and a broken user config are both supported cleanup inputs.
                (data / "sunpack_config.json").write_text("{invalid}", encoding="utf-8")
            originals = {name: (data / name).read_bytes() for name in (*defaults, roots)
                         if (data / name).exists()}
            initial_path = f"C:\\unrelated;{installed};{installed / 'bin'}"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_key + r"\environment") as key:
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, initial_path)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_key + r"\integration") as key:
                winreg.SetValueEx(key, "PathAddedByInstaller", 0, winreg.REG_DWORD, 1)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_key) as key:
                winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(installed))
                if version is None:
                    try:
                        winreg.DeleteValue(key, "DisplayVersion")
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, version)
            log = fixture / "setup.log"
            result = subprocess.run(
                [str(harness.with_suffix(".exe")), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/SP-",
                 "/NORESTART", f"/DIR={app}", f"/Fixture={fixture}", f"/Data={data}",
                 f"/AddPath={int(index != 2)}",
                 f"/StopFailure={int(stop_failure)}", f"/LOG={log}"],
                capture_output=True, text=True,
            )
            if stop_failure:
                assert result.returncode != 0
                assert (app / "unknown/nested/backup.bak").is_file()
                assert custom.is_dir()
                assert not (fixture / "completed").exists()
            else:
                assert result.returncode == 0, log.read_text(encoding="utf-8-sig", errors="replace")
                assert (fixture / "completed").is_file()
                assert not (app / "unknown").exists()
                assert (app / "sunpack_advanced_config.json").read_bytes() == (repo_root / "sunpack_advanced_config.json").read_bytes()
                if installed != app:
                    assert not installed.exists()
                assert custom.exists() is (not reset or layout in ("same", "parent"))
                assert (data / "unknown").exists() is not reset
                if reset:
                    assert not (data / ".sunpack_watch").exists()
                    assert not any((custom / name).exists() for name in task_files + other_files)
                if not reset:
                    for directory in (data / ".sunpack_watch", custom):
                        assert all((directory / name).read_text(encoding="utf-8") == name
                                   for name in task_files + other_files)
            for name in defaults:
                expected = defaults[name] if name not in originals or (
                    name == "sunpack_config.json" and reset and not stop_failure
                ) else originals[name]
                assert (data / name).read_bytes() == expected
            if roots in originals:
                assert (data / roots).read_bytes() == originals[roots]
            else:
                assert not (data / roots).exists()
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key + r"\environment") as key:
                expected_path = initial_path if stop_failure else "C:\\unrelated" + (f";{app / 'bin'}" if index != 2 else "")
                assert winreg.QueryValueEx(key, "Path")[0] == expected_path
    finally:
        for suffix in (r"\environment", r"\integration"):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key + suffix)
            except FileNotFoundError:
                pass
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key)
