from __future__ import annotations

import json
import re
import subprocess
import uuid
import winreg

from tests.helpers.installer import inno_compiler


def test_installer_applies_pre_140_policy_before_replacing_application(tmp_path, repo_root):
    # Runtime/ACL tests cannot catch version gating, selective cleanup or install
    # order. Without this harness those failures go undetected; one small build
    # covers that independent boundary, including use of advanced settings before old app deletion.
    compiler = inno_compiler()
    source = (repo_root / "installer/SunPack.iss").read_text(encoding="utf-8-sig")
    registry_key = "Software\\SunPackInstallerTests\\" + uuid.uuid4().hex
    uninstall_key = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}_is1"
    routines = []
    for name in (
        "NormalizePathEntry", "PopPathEntry", "PathContains", "InstallerOwnsMachinePath",
        "PathWithoutEntry", "AddMachinePath", "RemoveMachinePath",
        "PowerShellSingleQuotedString", "InstalledVersion",
        "RemoveDataDirectory", "ExistingApplicationDirectory",
        "ExistingLauncherPath", "UpgradeConfigurationFields", "PrepareToInstall",
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
    temporary_files = [line.replace("{#SourceDir}", str(repo_root))
                       for line in source.splitlines() if line.startswith('Source: "{#SourceDir}\\')
                       and 'DestDir: "{tmp}' in line
                       and ("upgrade_config.ps1" in line or "sunpack_config.json" in line)]
    assert len(temporary_files) == 2
    harness = tmp_path / "reset.iss"
    harness.write_text(f"""
[Setup]
AppName=SunPack reset regression
AppVersion=1.4.0
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
{chr(10).join(default_files + temporary_files)}
Source: "{repo_root / 'sunpack_advanced_config.json'}"; DestDir: "{{app}}"; Flags: ignoreversion
[CustomMessages]
PrepareRuntimeRunning=Runtime still running
PrepareBrokerRemoveFailed=Broker still running
PrepareOldFilesRemoveFailed=Cannot remove old files
PrepareDataUpgradeFailed=Cannot upgrade configuration
TaskAddToPathFailed=Cannot update PATH
[Code]
const
  SunPackRegistryKey = '{registry_key}\\integration';
  EnvironmentRegistryKey = '{registry_key}\\environment';
  PathMarkerName = 'PathAddedByInstaller';
var
  StopStage: Integer;
  ExistingWatchStateCaptured, RestartWatchAfterUpgrade: Boolean;
  InitializeLanguageOnInstall, UpgradePrepared: Boolean;
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
    if InitializeLanguageOnInstall then
      SaveStringToFile(ExpandConstant('{{param:Fixture}}\\completed'), 'initialize language', False)
    else
      SaveStringToFile(ExpandConstant('{{param:Fixture}}\\completed'), 'ok', False);
  end;
end;
""", encoding="utf-8-sig")
    result = subprocess.run([compiler, "/Qp", str(harness)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr

    fresh = tmp_path / "fresh install"
    fresh.mkdir()
    log = fresh / "setup.log"
    result = subprocess.run([
        str(harness.with_suffix(".exe")), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/SP-", "/NORESTART",
        f"/DIR={fresh / 'app'}", f"/Fixture={fresh}", f"/Data={fresh / 'data'}", "/AddPath=0", f"/LOG={log}",
    ], capture_output=True, text=True)
    assert result.returncode == 0, log.read_text(encoding="utf-8-sig", errors="replace")
    assert (fresh / "completed").read_text() == "initialize language"

    cases = [("v1.2.9", True, False), ("v1.3.0", True, False),
             ("v1.3.5-2-gabcdef0", True, False), ("1.4.0", False, False),
             ("1.10.0", False, False), (None, False, False), ("invalid", False, False),
             ("1.3.5", True, True)]
    try:
        for index, (version, migrate, failure) in enumerate(cases):
            fixture = tmp_path / f"case {index} ' [data]"
            app, data, custom, installed = (fixture / name for name in
                                            ("app", "data", "custom ' [watch]", "previous app"))
            for directory in (app, data, custom, installed):
                directory.mkdir(parents=True)
                (directory / "unrelated.txt").write_bytes(b"user owned")
            (installed / "bin").mkdir()
            (installed / "bin/sunpack.exe").write_bytes(b"stub")
            (custom / "state.snapshot").write_bytes(b"old state")
            (data / ".sunpack_watch").mkdir()
            (data / ".sunpack_watch/state.snapshot").write_bytes(b"old state")
            config = {"cli": {"language": "en"}, "watch": {"tray_enabled": False}}
            (data / "sunpack_config.json").write_text(json.dumps(config), encoding="utf-8")
            (data / "builtin_passwords.json").write_bytes(b'{"passwords": []}\r\n')
            (data / "sunpack_watch_roots.txt").write_bytes(
                b"# keep\r\nC:\\Downloads | D:\\out | true | true | false\r\n")
            (installed / "sunpack_advanced_config.json").write_text(json.dumps({
                "watch": {"state_dir": str(custom), "toast_enabled": False}
            }), encoding="utf-8")
            originals = {str(p.relative_to(fixture)): p.read_bytes()
                         for p in fixture.rglob("*") if p.is_file()}
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
                 f"/StopFailure={int(index == 7)}", f"/LOG={log}"],
                capture_output=True, text=True,
            )
            if failure:
                assert result.returncode != 0
                assert not (fixture / "completed").exists()
                for name, content in originals.items():
                    assert (fixture / name).read_bytes() == content
            else:
                assert result.returncode == 0, log.read_text(encoding="utf-8-sig", errors="replace")
                reset = version in (None, "invalid")
                assert (fixture / "completed").read_text() == ("initialize language" if reset else "ok")
                assert not installed.exists()
                assert not (app / "unrelated.txt").exists()
                assert (app / "sunpack_advanced_config.json").read_bytes() == (
                    repo_root / "sunpack_advanced_config.json").read_bytes()
                if reset:
                    assert {p.name for p in data.iterdir()} == {"sunpack_config.json", "builtin_passwords.json"}
                    for name in ("sunpack_config.json", "builtin_passwords.json"):
                        assert (data / name).read_bytes() == (repo_root / name).read_bytes()
                    assert (custom / "state.snapshot").read_bytes() == b"old state"
                elif migrate:
                    updated = json.loads((data / "sunpack_config.json").read_text(encoding="utf-8-sig"))
                    assert updated["cli"]["language"] == "en"
                    assert updated["watch"]["tray_enabled"] is False
                    # This value comes from the OLD install, proving the script
                    # completed before that application's directory was deleted.
                    assert updated["watch"]["toast_enabled"] is False
                    assert {p.name for p in data.iterdir()} == {
                        "sunpack_config.json", "builtin_passwords.json", "sunpack_watch_roots.txt"}
                    assert not (custom / "state.snapshot").exists()
                    assert (custom / "unrelated.txt").read_bytes() == b"user owned"
                else:
                    for name, content in originals.items():
                        if name.split("\\", 1)[0].split("/", 1)[0] == "data" or name.startswith("custom "):
                            assert (fixture / name).read_bytes() == content
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key + r"\environment") as key:
                expected = initial_path if failure else f"C:\\unrelated;{app / 'bin'}"
                assert winreg.QueryValueEx(key, "Path")[0] == expected
    finally:
        for suffix in (r"\environment", r"\integration"):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key + suffix)
            except FileNotFoundError:
                pass
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key)
