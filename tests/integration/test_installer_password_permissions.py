from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid
import winreg

import pytest


def _ps_string(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _powershell(script: str):
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _inno_compiler():
    candidates = [shutil.which("ISCC.exe")]
    candidates.extend(str(Path(os.environ.get(key, "")) / suffix) for key, suffix in (
        ("ProgramFiles(x86)", "Inno Setup 6/ISCC.exe"),
        ("ProgramFiles", "Inno Setup 6/ISCC.exe"),
        ("LOCALAPPDATA", "Programs/Inno Setup 6/ISCC.exe"),
    ))
    compiler = next((path for path in candidates if path and Path(path).is_file()), None)
    if compiler is None:
        pytest.skip("Inno Setup compiler is not installed")
    return compiler


def test_installer_repairs_existing_and_new_password_data_permissions(tmp_path, repo_root):
    # No runtime password test can detect leftover installer ACEs or blocked atomic writes.
    compiler = _inno_compiler()

    existing = tmp_path / "existing ' [data]"
    fresh = tmp_path / "fresh"
    nested = existing / "nested"
    nested.mkdir(parents=True)
    fresh.mkdir()
    password_file = existing / "builtin_passwords.json"
    password_file.write_text('{"passwords":[],"clipboard_history":[]}', encoding="utf-8")
    backup = nested / "builtin_passwords.txt.bak"
    backup.write_text("preserved", encoding="utf-8")
    original = password_file.read_bytes()
    _powershell(f"""
$ErrorActionPreference = 'Stop'
$data = {_ps_string(existing)}
$acl = [IO.Directory]::GetAccessControl($data)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
[IO.Directory]::SetAccessControl($data, $acl)
$directory = {_ps_string(nested)}
$acl = [IO.Directory]::GetAccessControl($directory)
$acl.SetAccessRuleProtection($true, $true)
[IO.Directory]::SetAccessControl($directory, $acl)
foreach ($path in @({_ps_string(password_file)}, {_ps_string(backup)})) {{
    $acl = [IO.File]::GetAccessControl($path)
    foreach ($sid in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')) {{
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'Modify', 'Allow'))
    }}
    [IO.File]::SetAccessControl($path, $acl)
}}
'true'
""")

    source = (repo_root / "installer/SunPack.iss").read_text(encoding="utf-8-sig")
    routines = []
    for name in ("PowerShellSingleQuotedString", "SecurePasswordDataDirectory"):
        match = re.search(rf"^(?:function|procedure) {name}\b.*?^end;", source, re.M | re.S)
        assert match is not None, name
        routines.append(match.group())
    marker = tmp_path / "completed"
    harness = tmp_path / "permissions.iss"
    harness.write_text(f"""
[Setup]
AppName=SunPack permission regression
AppVersion=1
DefaultDirName={{tmp}}\\SunPackPermissionRegression
PrivilegesRequired=lowest
Uninstallable=no
CreateAppDir=no
OutputDir={tmp_path}
OutputBaseFilename=permissions
[CustomMessages]
DataDirectoryPermissionsFailed=Cannot secure %s
[Code]
{chr(10).join(routines)}
function InitializeSetup: Boolean;
begin
  SecurePasswordDataDirectory({_ps_string(existing)});
  SecurePasswordDataDirectory({_ps_string(fresh)});
  SecurePasswordDataDirectory({_ps_string(existing)});
  SaveStringToFile({_ps_string(marker)}, 'ok', False);
  Result := False;
end;
""", encoding="utf-8-sig")
    result = subprocess.run([compiler, "/Qp", str(harness)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    result = subprocess.run(
        [str(harness.with_suffix(".exe")), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/SP-",
         "/NORESTART", f"/LOG={tmp_path / 'setup.log'}"],
        capture_output=True, text=True, timeout=30,
    )
    assert marker.exists(), (tmp_path / "setup.log").read_text(encoding="utf-8-sig", errors="replace")
    assert password_file.read_bytes() == original
    assert backup.read_text(encoding="utf-8") == "preserved"

    # Verify effective non-elevated IO as well as exact root and inherited child grants.
    for directory in (existing, fresh):
        temp = directory / ".clipboard.tmp"
        temp.write_text('{"passwords":[],"clipboard_history":["updated"]}', encoding="utf-8")
        temp.replace(directory / "builtin_passwords.json")
        assert json.loads((directory / "builtin_passwords.json").read_text(encoding="utf-8"))["clipboard_history"] == ["updated"]
        # Python rename succeeds with Modify, while ReplaceFile without a
        # backup requires DELETE_CHILD here. Exercise the actual GUI writer;
        # ACL shape and runtime-only writes cannot detect this failure.
        import platform
        arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
        binary = repo_root / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"
        assert binary.is_file(), "Build the native GUI with scripts/build_gui.ps1"
        result = subprocess.run([str(binary), "--password-add", str(directory / "builtin_passwords.json"), "GUI saved"],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads((directory / "builtin_passwords.json").read_text(encoding="utf-8")) == {
            "passwords": [{"value": "GUI saved"}], "clipboard_history": ["updated"],
        }
    security = _powershell(f"""
$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$items = foreach ($root in @({_ps_string(existing)}, {_ps_string(fresh)})) {{
    $root
    [IO.Directory]::GetFileSystemEntries($root, '*', [IO.SearchOption]::AllDirectories)
}}
$entries = @($items | ForEach-Object {{
    $acl = if ([IO.Directory]::Exists($_)) {{ [IO.Directory]::GetAccessControl($_) }} else {{ [IO.File]::GetAccessControl($_) }}
    @{{ path = $_; protected = $acl.AreAccessRulesProtected; rules = @(
        $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {{
            @{{ sid = $_.IdentityReference.Value; rights = [int]$_.FileSystemRights;
               inherited = $_.IsInherited; type = [string]$_.AccessControlType;
               inheritance = [int]$_.InheritanceFlags; propagation = [int]$_.PropagationFlags }}
        }}
    ) }}
}})
@{{ sid = $sid; entries = $entries }} | ConvertTo-Json -Depth 6 -Compress
""")
    roots = {str(existing), str(fresh)}
    expected = {security["sid"]: 0x1301BF, "S-1-5-18": 0x1F01FF, "S-1-5-32-544": 0x1F01FF}
    assert len(security["entries"]) == 6
    for entry in security["entries"]:
        is_root = entry["path"] in roots
        assert entry["protected"] is is_root
        assert {rule["sid"]: rule["rights"] for rule in entry["rules"]} == expected
        assert len(entry["rules"]) == 3
        assert all(rule["type"] == "Allow" and rule["inherited"] is not is_root for rule in entry["rules"])
        if is_root:
            assert all(rule["inheritance"] == 3 and rule["propagation"] == 0 for rule in entry["rules"])


def test_installer_resets_pre_120_data_and_preserves_current_data(tmp_path, repo_root):
    # Runtime/ACL tests cannot catch numeric version gating, wholesale cleanup,
    # or installation order. One real installer harness covers that boundary.
    compiler = _inno_compiler()
    source = (repo_root / "installer/SunPack.iss").read_text(encoding="utf-8-sig")
    registry_key = "Software\\SunPackInstallerTests\\" + uuid.uuid4().hex
    uninstall_key = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}_is1"
    routines = []
    for name in (
        "NormalizePathEntry", "PopPathEntry", "PathContains", "InstallerOwnsMachinePath",
        "PathWithoutEntry", "AddMachinePath", "RemoveMachinePath",
        "PowerShellSingleQuotedString", "RequiresDataReset", "InstalledDataRequiresReset",
        "RemoveDataDirectory", "ExistingApplicationDirectory", "RemoveInstalledData",
        "ExistingLauncherPath", "PrepareToInstall",
    ):
        match = re.search(rf"^(?:function|procedure) {name}\b.*?^end;", source, re.M | re.S)
        assert match is not None, name
        routines.append(match.group().replace("HKLM64", "HKCU").replace("HKLM", "HKCU").replace(uninstall_key, registry_key)
                        .replace(r"{commonappdata}\SunPack", r"{param:Fixture}\data"))
    default_files = [line.replace("{#SourceDir}", str(repo_root))
                     .replace(r"{commonappdata}\SunPack", r"{param:Fixture}\data")
                     for line in source.splitlines() if line.startswith('Source: "{#SourceDir}\\')
                     and ('\\sunpack_config.json";' in line or '\\builtin_passwords.json";' in line)]
    assert len(default_files) == 2
    harness = tmp_path / "reset.iss"
    harness.write_text(f"""
[Setup]
AppName=SunPack reset regression
AppVersion=1.2.0
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
    result = subprocess.run([compiler, "/Qp", str(harness)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    defaults = {name: (repo_root / name).read_bytes()
                for name in ("sunpack_config.json", "builtin_passwords.json")}
    # The malformed-config case proves deletion needs no functioning old runtime
    # or valid schema. The relocated case also resolves state from old defaults.
    cases = (("1.1.12", True, False), ("v1.1.99", True, False),
             ("1.2.0", False, False), ("1.10.0", False, False),
             (None, True, False), ("1.1.12", True, True), ("invalid", True, False),
             ("v1.2.2", False, False), ("v1.2.2-7-gabcdef0", False, False),
             ("1.2.2-7-gabcdef0-dirty", False, False), ("v1.1.12-7-gabcdef0", True, False))
    try:
        for index, (version, reset, stop_failure) in enumerate(cases):
            fixture = tmp_path / f"case {index} ' [data]"
            app, data, custom = (fixture / name for name in ("app", "data", "custom ' [watch]"))
            installed = fixture / "previous app" if index in (1, 3) else app
            for directory in {app, data, custom, installed}:
                (directory / "unknown" / "nested").mkdir(parents=True)
                (directory / "unknown" / "nested" / "backup.bak").write_text("old", encoding="utf-8")
            (installed / "bin").mkdir()
            (installed / "bin" / "sunpack.exe").write_text("stub", encoding="utf-8")
            config = {"watch": {"state_dir": str(custom)}, "unknown": "keep current data"}
            (data / "sunpack_config.json").write_text(json.dumps(config), encoding="utf-8")
            (data / "builtin_passwords.json").write_text('{"passwords":[{"value":"private"}]}', encoding="utf-8")
            (data / "sunpack_watch_roots.txt").write_text("private roots", encoding="utf-8")
            (installed / "sunpack_advanced_config.json").write_text(json.dumps(config), encoding="utf-8")
            if index == 1:
                # Advanced-only custom path and a broken user config are both supported cleanup inputs.
                (data / "sunpack_config.json").write_text("{invalid}", encoding="utf-8")
            originals = {name: (data / name).read_bytes() for name in defaults}
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
                 "/NORESTART", f"/DIR={app}", f"/Fixture={fixture}",
                 f"/AddPath={int(index != 2)}",
                 f"/StopFailure={int(stop_failure)}", f"/LOG={log}"],
                capture_output=True, text=True, timeout=30,
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
                assert custom.exists() is not reset
                assert (data / "unknown").exists() is not reset
                assert (data / "sunpack_watch_roots.txt").exists() is not reset
            for name in defaults:
                assert (data / name).read_bytes() == (defaults[name] if reset and not stop_failure else originals[name])
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
