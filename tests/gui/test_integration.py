"""Shipped GUI text and real installer-to-GUI permission contracts."""
import base64
import json
import os
import platform
import re
import subprocess
from pathlib import Path

import pytest

from tests.helpers.installer import inno_compiler


def test_gui_template_texts_exist_in_both_languages():
    # Conditional error actions need not appear in ordinary UI runs. Checking
    # the shipped template/catalog boundary catches missing labels cheaply.
    resources = Path(__file__).resolve().parents[2] / "gui" / "resources"
    catalog = json.loads((resources / "catalog.json").read_text(encoding="utf-8"))["ui"]
    for template in resources.glob("*.uix"):
        for key in set(re.findall(r"\btexts\.([A-Za-z_][A-Za-z0-9_]*)", template.read_text(encoding="utf-8"))):
            assert key in catalog, (template.name, key)
            assert all(catalog[key].get(language) for language in ("zh", "en")), (template.name, key)


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


def test_installer_repairs_existing_and_new_data_permissions(tmp_path, repo_root):
    # This real install hook also catches a skipped ACL repair after [Dirs]/[Files]
    # create the data directory. Runtime tests cannot detect that install order.
    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", repo_root / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    assert binary.is_file(), "Build the native GUI with scripts/build_gui.ps1"
    compiler = inno_compiler()

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
    for name in ("PowerShellSingleQuotedString", "ConfigureDataDirectoryPermissions",
                 "AppendTextLine", "SaveUTF8TextLines", "EnsureLocalizedEditableConfigFiles"):
        match = re.search(rf"^(?:function|procedure) {name}\b.*?^end;", source, re.M | re.S)
        assert match is not None, name
        routines.append(match.group().replace(r"{commonappdata}\SunPack", "{param:Data}"))
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
DisableWelcomePage=yes
DisableFinishedPage=yes
OutputDir={tmp_path}
OutputBaseFilename=permissions
[Dirs]
Name: "{{param:Data}}"
[CustomMessages]
DataDirectoryPermissionsFailed=Cannot secure %s
EditableConfigCreateFailed=Cannot create %s
WatchRootsFileHeader=# Watched folders
WatchRootsFileMapping=# Mapping
WatchRootsFileDeepDetect=# Deep detect
WatchRootsFileExample=# Example
[Code]
{chr(10).join(routines)}
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    EnsureLocalizedEditableConfigFiles;
    SaveStringToFile({_ps_string(marker)}, 'ok', False);
  end;
end;
""", encoding="utf-8-sig")
    result = subprocess.run([compiler, "/Qp", str(harness)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    for directory in (existing, fresh, existing):
        result = subprocess.run(
            [str(harness.with_suffix(".exe")), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/SP-",
             "/NORESTART", f"/Data={directory}", f"/LOG={tmp_path / 'setup.log'}"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0 and marker.exists(), (tmp_path / "setup.log").read_text(encoding="utf-8-sig", errors="replace")
    assert password_file.read_bytes() == original
    assert backup.read_text(encoding="utf-8") == "preserved"

    # Verify effective non-elevated IO as well as exact root and inherited child grants.
    for directory in (existing, fresh):
        roots_file = directory / "sunpack_watch_roots.txt"
        roots_file.write_text("C:\\Downloads\n", encoding="utf-8")
        temp = directory / ".clipboard.tmp"
        temp.write_text('{"passwords":[],"clipboard_history":["updated"]}', encoding="utf-8")
        temp.replace(directory / "builtin_passwords.json")
        assert json.loads((directory / "builtin_passwords.json").read_text(encoding="utf-8"))["clipboard_history"] == ["updated"]
        # Python rename succeeds with Modify, while ReplaceFile without a
        # backup requires DELETE_CHILD here. Exercise the actual GUI writer;
        # ACL shape and runtime-only writes cannot detect this failure.
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
    expected = {"S-1-5-32-545": 0x1301BF, "S-1-5-18": 0x1F01FF, "S-1-5-32-544": 0x1F01FF}
    assert len(security["entries"]) == 8
    for entry in security["entries"]:
        is_root = entry["path"] in roots
        assert entry["protected"] is is_root
        assert {rule["sid"]: rule["rights"] for rule in entry["rules"]} == expected
        assert len(entry["rules"]) == 3
        assert all(rule["type"] == "Allow" and rule["inherited"] is not is_root for rule in entry["rules"])
        if is_root:
            assert all(rule["inheritance"] == 3 and rule["propagation"] == 0 for rule in entry["rules"])


def test_rust_writer_cpp_query_lifecycle(repo_root):
    # The existing Rust decoder cannot detect C++ query/index/filter mistakes.
    # This prebuilt test drives the real writer and invokes --project itself;
    # no Python pipeline, copied store decoder, or build-on-test fallback.
    binary = Path(os.environ.get("SUNPACK_GUI_WRITER_TEST_BINARY", repo_root / "tools" / "gui_projection_writer.exe"))
    if not binary.is_file() and "SUNPACK_GUI_WRITER_TEST_BINARY" not in os.environ:
        pytest.skip("Set SUNPACK_GUI_WRITER_TEST_BINARY to the prebuilt Rust lib test executable")
    assert binary.is_file(), "Build/copy the Rust lib test executable and set SUNPACK_GUI_WRITER_TEST_BINARY"
    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    gui = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", repo_root / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    assert gui.is_file(), "Build the actual C++ GUI reader with scripts/build_gui.ps1"
    environment = {**os.environ, "SUNPACK_GUI_TEST_BINARY": str(gui)}
    result = subprocess.run(
        [str(binary), "--ignored", "--exact", "event_log::gui_contract::rust_writer_cpp_query_lifecycle", "--nocapture"],
        capture_output=True, text=True, encoding="utf-8", env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout, "the real writer/GUI boundary test was not selected"
