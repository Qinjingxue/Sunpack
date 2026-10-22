"""Cross-language file identity and tray launch contracts, absent from C++ tests."""
import base64
import os
import ctypes
from ctypes import wintypes
import platform
import subprocess
import json
import re
from pathlib import Path

import pytest

from tests.helpers.installer import inno_compiler

from sunpack.core.platform.windows.file_mutex import file_mutex, file_mutex_name
from sunpack.runtime.watch.service import watch_roots_mutex_name
from sunpack.runtime.gui import manager


def test_gui_template_texts_exist_in_both_languages():
    # Conditional error actions need not appear in ordinary UI runs. Checking
    # the shipped template/catalog boundary catches missing labels cheaply.
    resources = Path(__file__).resolve().parents[2] / "gui" / "resources"
    catalog = json.loads((resources / "catalog.json").read_text(encoding="utf-8"))["ui"]
    for template in resources.glob("*.uix"):
        for key in set(re.findall(r"\btexts\.([A-Za-z_][A-Za-z0-9_]*)", template.read_text(encoding="utf-8"))):
            assert key in catalog, (template.name, key)
            assert all(catalog[key].get(language) for language in ("zh", "en")), (template.name, key)


def test_native_mutex_matches_runtime_for_windows_paths(tmp_path):
    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", Path(__file__).resolve().parents[2] / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    if not binary.is_file():
        pytest.skip("Build the native GUI with scripts/build_gui.ps1")
    for path in (tmp_path / "builtin_passwords.json", Path("C:/混合İ/../中文/密码.json"), Path(r"\\server\share\密码.json"), "C:/Data/", "C:/", "//server/share/"):
        names = subprocess.check_output([str(binary), "--mutex", str(path)], text=True, encoding="utf-8").splitlines()
        assert names == [file_mutex_name(path), watch_roots_mutex_name(path)]


def test_native_edit_preserves_python_clipboard_update_under_same_mutex(tmp_path, monkeypatch):
    from sunpack.core.passwords.internal import builtin

    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", Path(__file__).resolve().parents[2] / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    if not binary.is_file():
        pytest.skip("Build the native GUI with scripts/build_gui.ps1")
    path = tmp_path / "builtin_passwords.json"
    path.write_text(json.dumps({"passwords": [{"value": "initial"}], "clipboard_history": []}), encoding="utf-8-sig")
    monkeypatch.setattr(builtin, "builtin_password_path", lambda: path)
    # ReplaceFile holds DELETE access. A concurrent reader must share DELETE,
    # even though it only reads. Ordinary Python open deterministically fails here.
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.CreateFileW(str(path), 0x80010000, 7, None, 3, 0, None)
    assert handle != wintypes.HANDLE(-1).value
    try:
        assert builtin.read_builtin_password_file(path).global_passwords == ("initial",)
    finally:
        kernel32.CloseHandle(handle)
    with file_mutex(path):
        process = subprocess.Popen([str(binary), "--password-add", str(path), " GUI # 中文 "], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert builtin.merge_watch_clipboard_passwords(["后台新密码"])
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 0, (stdout, stderr)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document == {"passwords": [{"value": "initial"}, {"value": " GUI # 中文 "}], "clipboard_history": ["后台新密码"]}
    assert builtin.read_builtin_password_file(path).global_passwords == ("initial", " GUI # 中文 ", "后台新密码")
    from sunpack_native import native_resource_snapshot
    assert native_resource_snapshot([str(tmp_path)]) == []


def test_packaged_manager_launch_releases_native_process_handle(tmp_path, monkeypatch):
    executable = tmp_path / "sunpack-runtime.exe"
    (tmp_path / "SunPackGUI.exe").touch()
    monkeypatch.setattr(manager, "current_process_executable", lambda: executable)
    monkeypatch.setattr(manager, "is_packaged_process", lambda: True)
    monkeypatch.setattr(manager, "writable_data_dir", lambda: tmp_path)
    calls = []

    class Process:
        def close(self):
            calls.append("closed")

    def launch(argv, **kwargs):
        calls.append((argv, kwargs))
        return Process()

    monkeypatch.setattr(manager, "launch_unelevated", launch)
    manager.launch_manager()
    assert calls == [([str(tmp_path / "SunPackGUI.exe")], {"cwd": str(tmp_path)}), "closed"]


def test_gui_ranges_keep_runtime_boundaries_exact(tmp_path):
    """C++ GUI -> JSON -> Python -> native scan, without actual enormous files."""
    from datetime import datetime, timezone
    from sunpack.pipeline.discovery.filesystem.filters.modules.size_range import SizeRangeScanFilter
    from sunpack.pipeline.discovery.filesystem.filters.modules.mtime_range import MtimeRangeScanFilter
    from sunpack.core.contracts.filesystem import FileEntry
    from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
    from tests.helpers.config_factory import make_config

    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", Path(__file__).resolve().parents[2] / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    if not binary.is_file():
        pytest.skip("Build the native GUI with scripts/build_gui.ps1")
    modules = json.loads(subprocess.check_output([str(binary), "--ranges"], text=True, encoding="utf-8"))
    size = SizeRangeScanFilter.from_config(modules["size"]).value_range
    assert not size.allows(9007199254740992) and size.allows(9007199254740993)
    time = MtimeRangeScanFilter.from_config(modules["time"]).value_range
    lower = int(datetime(2024, 2, 29, 4, 34, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    upper = int(datetime(2026, 12, 31, 16, 0, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    assert time.allows(lower) and not time.allows(lower - 1)
    assert not time.allows(upper) and time.allows(upper - 1)
    snapshot = DirectoryScanner.snapshot_from_entries(str(tmp_path), [
        FileEntry(path=tmp_path / "large.zip", is_dir=False, size=9007199254740993),
        FileEntry(path=tmp_path / "small.zip", is_dir=False, size=9007199254740992),
    ], config=make_config({"filesystem": {"scan_filters": [modules["size"]]}}))
    assert {Path(path).name for path, *_ in snapshot.iter_columns()} == {"large.zip"}


def test_structured_filter_protocol_rejects_old_and_invalid_fields():
    from sunpack.pipeline.discovery.filesystem.filters.modules.size_range import SizeRangeScanFilter
    from sunpack.pipeline.discovery.filesystem.filters.modules.mtime_range import MtimeRangeScanFilter
    for cls, invalid in (
        (SizeRangeScanFilter, [{"range": "r > 0"}, {"gt": 0}, {"min_bytes": True},
                               {"min_bytes": -1}, {"max_bytes": 1 << 64},
                               {"min_bytes": 2, "max_bytes": 1}, {"min_bytes": 0.5}]),
        (MtimeRangeScanFilter, [{"date": "d > 20240101"}, {"since": "20240101"},
                                {"start_utc": 0}, {"start_utc": "2023-02-29T00:00Z"},
                                {"start_utc": "2024-01-01T00:00:00Z"},
                                {"start_utc": "2024-01-01T00:00Z", "end_utc": "2024-01-01T00:00Z"}]),
    ):
        for config in invalid:
            with pytest.raises(ValueError):
                cls.from_config(config)
        with pytest.raises(ValueError):
            cls.from_config({"match_none": True})
        assert cls.from_config({}).value_range.allows(None)
    point = SizeRangeScanFilter.from_config({"min_bytes": (1 << 64) - 1, "max_bytes": (1 << 64) - 1}).value_range
    assert point.allows((1 << 64) - 1) and not point.allows((1 << 64) - 2)


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


def test_installer_repairs_existing_and_new_password_data_permissions(tmp_path, repo_root):
    # No runtime password test can detect leftover installer ACEs or blocked atomic writes.
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
