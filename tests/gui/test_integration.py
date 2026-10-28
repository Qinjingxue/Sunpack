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


def _state_projection(path, query="", cursor="", root="", status=""):
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", Path(__file__).resolve().parents[2] / ".cache" / "gui-x64" / "Release" / "sunpack_gui_tests.exe"))
    if not binary.is_file():
        pytest.skip("Build the native GUI with scripts/build_gui.ps1")
    return json.loads(subprocess.check_output([str(binary), "--project", str(path), query, cursor, root, status], text=True, encoding="utf-8"))


def test_indexed_history_pages_and_literal_member_search_work_without_a_producer(tmp_path):
    # Projection-only fixtures cannot detect Rust/C++ index/filter disagreement,
    # cursor omissions across UTC runs, or a GUI accidentally writing the store.
    # One closed real producer covers all three without loading all history in UI.
    import time
    from sunpack.runtime.watch.log import WatchLogStore
    path = tmp_path / "events.json"
    store = WatchLogStore(str(path))
    base = time.time() - 2 * 86400
    for index in range(250):
        source = str(tmp_path / ("one" if index < 100 else "two") / f"载体-{index}.fake")
        member = str(tmp_path / f"密钥_{index}%.002")
        timestamp = base + (index // 100) * 86400 + index / 1000
        store.write("pipeline_sources_claimed", owner=str(index), processing=True, ts=timestamp,
                    groups=[{"path": source, "name": "payload.rar", "members": [source, member]}])
        store.write("done", path=member, owner=str(index), ts=timestamp)
    store.flush()
    store.close()
    manifest = path.read_bytes()
    files = {p: p.stat().st_mtime_ns for p in path.with_name(path.name + ".store").iterdir()}
    cursor, ids = "", set()
    while True:
        page = _state_projection(path, cursor=cursor)["tasks"]
        assert 0 < len(page["rows"]) <= 100
        for row in page["rows"]:
            assert row["id"] not in ids
            ids.add(row["id"])
        if not page["hasMore"]:
            break
        cursor = page["next"]
    assert len(ids) == 250
    for query in ("密", "密钥", "100%", "PAYLOAD.RAR"):
        page = _state_projection(path, query=query)["tasks"]
        assert page["rows"]
        if query == "100%":
            assert len(page["rows"]) == 1 and page["rows"][0]["name"] == "载体-100.fake"
    assert not _state_projection(path, query="密匙")["tasks"]["rows"]
    assert len(_state_projection(path, root=str(tmp_path / "one"))["tasks"]["rows"]) == 100
    assert not _state_projection(path, status="taskFailed")["tasks"]["rows"]
    assert path.read_bytes() == manifest
    assert {p: p.stat().st_mtime_ns for p in files} == files


def test_gui_reads_display_state_across_publication_faults_and_close(tmp_path):
    # Pure model fixtures cannot detect disagreements with the real Rust writer.
    # Kernel sharing conflicts and read failures cover publication, fault reporting,
    # retained last-known state, healing, and independent offline replay.
    from sunpack.runtime.watch.log import WatchLogStore
    path = tmp_path / "events.json"
    source = str(tmp_path / "carrier.fake.001")
    log = WatchLogStore(str(path))
    try:
        log.recover()
        log.write("processing_started", path=source)
        log.flush()
        live = _state_projection(path)
        assert live["tasks"]["rows"][0]["status"] == "taskProcessing"
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        # A normal GUI reader allows deletion and must not prevent compaction.
        # MoveFileExW alone fails with error 5 even with this sharing mode.
        held = kernel.CreateFileW(str(path), 0x80000000, 7, None, 3, 0, None)
        assert held != wintypes.HANDLE(-1).value
        try:
            log.write("failed_password", path=source)
            log.write("diagnostic", padding="x" * 4096)
            log.flush()
            published = _state_projection(path)
            assert published["tasks"]["rows"][0]["statusText"] == "等待密码"
            old_bytes, count = ctypes.create_string_buffer(4096), wintypes.DWORD()
            assert kernel.ReadFile(held, old_bytes, len(old_bytes), ctypes.byref(count), None)
            assert json.loads(old_bytes.raw[:count.value])["format"] == 1
        finally:
            kernel.CloseHandle(held)
        held = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0, None)
        assert held != wintypes.HANDLE(-1).value
        before = path.read_bytes()
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            try:
                log.write("failed_password", path=source)
                log.write("diagnostic", padding="x" * 4096)
                publication = executor.submit(log.flush)
                # A reader that denies deletion delays replacement until it
                # releases its handle. The previously published file stays valid.
                assert path.read_bytes() == before
                stale = _state_projection(path)
                assert [(r["id"], r["status"]) for r in stale["tasks"]["rows"]] == [(r["id"], r["status"]) for r in published["tasks"]["rows"]]
            finally:
                kernel.CloseHandle(held)
            publication.result()
        assert not log.error
        log.write("diagnostic", message="disk available again")
        log.flush()
        healed = _state_projection(path)
        assert healed["tasks"]["rows"][0]["statusText"] == "等待密码"
        log.write("done", path=source, output_dirs=["retained-output"])
        log.flush()
        completed = _state_projection(path)
    finally:
        log.close()
    assert _state_projection(path) == completed
    # A failed read/rebuild is swallowed while the manifest is locked. The next
    # submission rebuilds the disposable history without an idle retry loop.
    before = path.read_bytes()
    held = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
    assert held != wintypes.HANDLE(-1).value
    log = WatchLogStore(str(path))
    try:
        log.recover()
        try:
            log.flush()
            assert log.error
        finally:
            kernel.CloseHandle(held)
        assert path.read_bytes() == before
        log.write("diagnostic", message="history readable again")
        log.flush()
        restored = _state_projection(path)["tasks"]["rows"]
        assert restored == []  # Completed history has no WAL-backed state.
    finally:
        log.close()
    assert not list(tmp_path.glob("*.tmp"))


def test_gui_history_survives_process_death_and_wal_recovery(tmp_path):
    # A live writer cannot expose history lost across process lifetimes or
    # the WAL/log gap. Crash a real producer, then recover its current blocker
    # while preserving previous executions and all offline task statuses.
    import sys
    source = tmp_path / "disguised.bin"
    source.write_bytes(b"not inspected by this projection test")
    path = tmp_path / "events.json"
    script = """
import sys
from sunpack.runtime.watch.log import WatchLogStore
from sunpack.runtime.watch.state import WatchStateStore
log = WatchLogStore(sys.argv[1])
state = WatchStateStore(sys.argv[2])
log.recover()
log.write('processing_started', path=sys.argv[3], owner='completed')
log.write('pipeline_sources_claimed', owner='completed', processing=True,
          groups=[{'path':sys.argv[3], 'name':'retained.rar', 'members':[sys.argv[3], sys.argv[3]+'.002']}])
log.write('done', path=sys.argv[3], owner='completed', output_dirs=['previous-output'])
log.write('failed_terminal', path=sys.argv[3] + '.failed', owner='failed')
log.write('processing_started', path=sys.argv[3] + '.inflight', owner='inflight')
log.write('failed_password', path=sys.argv[3] + '.waiting')
log.flush()
# Leave the durable blocker ahead of the published state, then crash without
# publishing a recovery snapshot or running either store's close method.
state.mark(sys.argv[3], 1, 1.0, status='suspended_missing_volume')
print('ready', flush=True)
sys.stdin.readline()
"""
    child = subprocess.Popen([sys.executable, "-c", script, str(path), str(tmp_path / "state.snapshot"), str(source)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        child.kill()
        child.wait(timeout=10)
        dead = _state_projection(path)
        assert {r["status"] for r in dead["tasks"]["rows"]} == {"taskSucceeded", "taskFailed", "taskWaiting", "taskProcessing"}
    finally:
        if child.poll() is None: child.kill(); child.wait(timeout=10)
        child.stdin.close(); child.stdout.close()
    from sunpack.runtime.watch.log import WatchLogStore
    from sunpack.runtime.watch.state import WatchStateStore
    state = WatchStateStore(str(tmp_path / "state.snapshot"))
    # A crash can leave one incomplete append after all committed records.
    manifest = json.loads(path.read_text())
    run = manifest["runs"][-1]
    data = path.with_name(path.name + ".store") / (run["name"] + ".data")
    with data.open("ab") as tail:
        tail.write(b"unpublished incomplete compressed display record")
    log = WatchLogStore(str(path))
    try:
        log.recover(state._native)
        log.flush()
        restored = _state_projection(path)
        assert restored["tasks"]["total"] == 3
        assert {r["status"] for r in restored["tasks"]["rows"]} == {"taskSucceeded", "taskFailed", "taskWaiting"}
        assert next(r for r in restored["tasks"]["rows"] if r["status"] == "taskWaiting")["statusText"] == "等待分卷"
        assert next(r for r in restored["tasks"]["rows"] if r["status"] == "taskSucceeded")["outputs"] == ["previous-output"]
        assert next(r for r in restored["tasks"]["rows"] if r["status"] == "taskSucceeded")["name"] == source.name
        # WAL blockers without a group must get a new identity even when their
        # path currently aliases a completed execution in the same host.
        log.write("processing_started", path=str(source), owner="retried")
        log.write("done", path=str(source), owner="retried", output_dirs=["retry-output"])
        log.recover(state._native)
        log.flush()
        restored = _state_projection(path)
        assert restored["tasks"]["total"] == 4
        assert {tuple(r["outputs"]) for r in restored["tasks"]["rows"] if r["status"] == "taskSucceeded"} == {("previous-output",), ("retry-output",)}
        # Rebuilding again in the same host must preserve the same historical ID.
        log.recover(state._native)
        log.flush()
        assert {r["id"] for r in _state_projection(path)["tasks"]["rows"] if r["status"] != "taskWaiting"} == {r["id"] for r in restored["tasks"]["rows"] if r["status"] != "taskWaiting"}
    finally:
        state.close(); log.close()


def test_native_and_gui_share_member_retirement_and_real_request_lifetimes(tmp_path):
    # Scalar status/GUI-only fixtures miss compaction resurrecting a removed
    # sibling, and a completed request leaving invisible active groups resident.
    from sunpack.runtime.watch.log import WatchLogStore
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
    from sunpack.core.contracts.tasks import ArchiveTask
    from sunpack.pipeline.coordinator.engine import _task_source_group
    log = WatchLogStore(str(tmp_path / "events.json"))
    a, b, c = (str(tmp_path / name) for name in ("carrier.001", "other.bin", "last.part"))
    def compact():
        log.write("diagnostic", message="x" * 4096)
        log.flush()
        return _state_projection(log.path)["tasks"]
    def members():
        from tests.display_history import records as read_records
        records = read_records(log.path)
        return next(g for r in reversed(records) if r["event"] == "pipeline_sources_claimed"
                    for g in r["groups"] if g["path"] == a)["members"]
    try:
        log.recover()
        log.write("processing_started", path=c, owner="request")
        # Real descriptor -> producer -> Rust compaction -> C++ display. This
        # also covers the otherwise invisible one-volume multipart marker.
        descriptor = ArchiveInputDescriptor(entry_path=a, open_mode="native_volumes", volume_style="rar",
            parts=[ArchiveInputPart(InputExtent(p), volume_number=n, canonical_name=f"nested.part{n}.rar")
                   for p, n in ((c, 10), (a, 1), (b, 2))])
        group = _task_source_group(ArchiveTask.from_archive_input(descriptor, discovery_source="test"))
        log.write("pipeline_sources_claimed", owner="request", groups=[group])
        # Absorbing a provisional member must canonicalize its saved status;
        # retiring it before compaction must not resurrect a second card.
        log.write("task_retired", path=c)
        rows = compact()["rows"]
        assert len(rows)==1 and members()==[a,b,c]
        assert rows[0]["parts"]==["carrier.001", "other.bin", "last.part"]
        log.write("suspended_missing_volume", path=a)
        log.write("task_retired", path=c)
        rows = compact()["rows"]
        assert len(rows)==1 and members()==[a,b] and rows[0]["path"]==a
        assert rows[0]["parts"]==["carrier.001", "other.bin"]
        log.write("task_retired", path=a)
        rows = compact()["rows"]
        assert len(rows)==1 and members()==[b] and rows[0]["status"]=="taskWaiting"
        log.write("failed_password", path=a)
        assert compact()["rows"][0]["parts"]==["other.bin"]
        log.write("processing_started", path=a, owner="request")
        log.write("blocker_cleared", path=a, task_path=a)
        assert compact()["total"]==1  # A real running task survives old blocker retirement.
        log.write("failed_password", path=b)
        log.write("blocker_cleared", path=b, task_path=a)
        assert compact()["total"]==0  # Clearing a blocker alone never fabricates a queue.
        log.write("pipeline_sources_claimed", owner="old", processing=True,
                  groups=[{"path": a, "members": [a,b]}])
        log.write("pipeline_sources_claimed", owner="new", processing=True,
                  groups=[{"path": a, "members": [a,b]}])
        log.write("pipeline_sources_released", owner="old", paths=[a,b])
        assert compact()["total"]==1
        log.write("pipeline_sources_released", owner="new", paths=[a,b])
        assert compact()["total"]==0
        log.write("pipeline_sources_claimed", owner="end", processing=True,
                  groups=[{"path": a, "members": [a,b]}])
        log.write("task_retired", path=a, scope="task")
        assert compact()["total"]==0
        log.write("pipeline_sources_claimed", owner="failure", processing=True, groups=[group])
        log.write("failed_terminal", path=a, error="CRC mismatch\n嵌套压缩包损坏", error_kind="damaged")
        rows = compact()["rows"]
        assert rows[0]["parts"]==["carrier.001", "other.bin", "last.part"]
        assert rows[0]["error"]=="CRC mismatch\n嵌套压缩包损坏"
        assert rows[0]["errorType"]=="压缩数据损坏"
    finally:
        log.close()


def test_execution_history_survives_regroup_retry_and_compaction(tmp_path):
    # Existing distinct-path tests cannot detect overwriting same-path history
    # or an old eviction unlinking a live alias. One real writer/GUI scenario
    # covers both, including snapshot replay and the existing byte budget.
    from sunpack.runtime.watch.log import WatchLogStore
    import time
    base = time.time() - 100
    log = WatchLogStore(str(tmp_path / "events.json"))
    a, b = (str(tmp_path / name) for name in ("carrier.fake", "unrelated.bin"))
    group = {"path": a, "name": "payload.rar", "members": [a, b]}

    def rows():
        log.flush()
        result = _state_projection(log.path)["tasks"]["rows"]
        for row in result:
            row.pop("sortSequence")  # Replay-local tie breaker, not identity.
        return result

    def compact():
        # Drain first, then exceed the obsolete-byte threshold in a single
        # writer batch. The next read must come from a rewritten snapshot.
        log.flush()
        for _ in range(32):
            log.write("diagnostic", message="x" * 4096)
        return rows()

    try:
        log.recover()
        log.write("processing_started", path=b, owner="first", ts=base+1)
        log.write("pipeline_sources_claimed", owner="first", processing=True,
                  groups=[group], ts=base+2)
        log.write("done", path=b, owner="first", output_dirs=["old-output"], ts=base+3)
        old, = rows()
        assert old["path"] == a and old["status"] == "taskSucceeded"
        log.write("processing_started", path=b, owner="second", ts=base+4)
        current = rows()
        assert len(current) == 2 and old in current
        retry_id = next(r["id"] for r in current if r["status"] == "taskProcessing")
        log.write("pipeline_sources_claimed", owner="second", processing=True,
                  groups=[{"path": b, "name": "payload.rar", "members": [b]}], ts=base+5)
        log.write("suspended_missing_volume", path=b, ts=base+6)
        log.write("processing_started", path=a, owner="third", ts=base+7)
        log.write("pipeline_sources_claimed", owner="third", processing=True, groups=[group], ts=base+8)
        log.write("pipeline_sources_released", owner="second", paths=[a, b])
        log.write("failed_terminal", owner="second", path=b, ts=base+8)
        log.write("failed_password", path=b, ts=base+9)
        current = rows()
        assert len(current) == 2 and old in current
        waiting, = [r for r in current if r["status"] == "taskWaiting"]
        assert waiting["id"] == retry_id
        assert waiting["statusText"] == "等待密码"
        assert compact() == current
        log.write("processing_started", path=b, owner="fourth", ts=base+10)
        log.write("done", path=a, owner="fourth", output_dirs=["new-output"], ts=base+11)
        current = rows()
        assert len(current) == 2 and old in current
        assert {r["id"] for r in current} == {old["id"], retry_id}
        assert all(r["status"] == "taskSucceeded" for r in current)
        assert compact() == current
        # Evict old executions at the same physical paths. Their cleanup must
        # not remove the aliases of the new waiting task.
        for index in range(80):
            owner = f"burst-{index}"
            log.write("processing_started", path=a, owner=owner)
            log.write("pipeline_sources_claimed", owner=owner, processing=True, groups=[group])
            log.write("done", path=b, owner=owner)
        log.write("processing_started", path=a, owner="active")
        log.write("pipeline_sources_claimed", owner="active", processing=True, groups=[group])
        log.write("failed_password", path=b)
        current = compact()
        assert len(current) == 83
        assert len([r for r in current if r["status"] == "taskWaiting"]) == 1
        assert log.path.stat().st_size < 65536
        log.write("blocker_cleared", path=b, task_path=a)
        retained = compact()
        assert all(r["status"] == "taskSucceeded" for r in retained)
    finally:
        log.close()
    # Reopening must retain exactly the already bounded results, including
    # confirmed names for physical inputs that are no longer present.
    log = WatchLogStore(str(tmp_path / "events.json"))
    try:
        log.recover()
        assert rows() == retained
        assert log.path.stat().st_size < 65536
    finally:
        log.close()


def test_split_arrivals_publish_only_confirmed_cards(tmp_path, monkeypatch):
    # Final snapshots cannot expose a sibling card appearing before discovery.
    # Three tiny real arrivals cover that boundary, stable IDs and growing
    # membership together; per-format extraction is covered elsewhere.
    import asyncio
    import shutil
    from sunpack.pipeline.coordinator.engine import PipelineEngine
    from sunpack.runtime.watch.scheduler import WatchScheduler
    from sunpack.runtime.watch.scanner import watch_candidate_for_path
    from sunpack.runtime.watch.roots import WatchRootEntry
    from tests.helpers.config_factory import make_config

    monkeypatch.setattr("sunpack.runtime.watch.scheduler.validate_ntfs_watch_roots", lambda _roots: None)
    root = tmp_path / "input"
    root.mkdir()
    payload = tmp_path / "payload.txt"
    payload.write_text("split arrival payload\n" * 110, encoding="utf-8")
    subprocess.run([str(Path(__file__).resolve().parents[2] / "tools" / "7z.exe"),
                    "a", "-t7z", "-mx=0", "-v1k", str(tmp_path / "split.7z"), str(payload)],
                   check=True, capture_output=True)
    parts = sorted(tmp_path.glob("split.7z.*"))
    assert len(parts) == 3
    config = make_config({"recursive_extract": "1", "detection": {"enabled": True},
                          "watch": {"clipboard_monitor_enabled": False},
                          "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False}})

    async def scenario():
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(config, [str(root)], pipeline_engine=engine,
                state_path=str(tmp_path / "state.snapshot"), root_entries=[
                    WatchRootEntry(str(root), str(tmp_path / "output"))])
            try:
                watcher.log.recover()
                previous = []
                for index, source in enumerate(parts):
                    arrived = root / source.name
                    shutil.copyfile(source, arrived)
                    watcher.enqueue(str(arrived), force=True, event_type="created")
                    request = await watcher._submit_candidate(watch_candidate_for_path(str(arrived)))
                    assert request is not None
                    # Admission has no confirmed descriptor yet. It must neither
                    # add a provisional card nor change the waiting card.
                    watcher.log.flush()
                    assert _state_projection(watcher.log.path)["tasks"]["rows"] == previous
                    await request.task
                    result = await watcher._finish_active_request(request)
                    assert result.failed == int(index < 2)
                    watcher.log.flush()
                    rows = _state_projection(watcher.log.path)["tasks"]["rows"]
                    assert len(rows) == 1, [(r["id"],r["status"],r["path"]) for r in rows]
                    assert rows[0]["parts"] == [part.name for part in parts[:index + 1]]
                    assert rows[0]["status"] == ("taskWaiting" if index < 2 else "taskSucceeded")
                    if previous:
                        assert rows[0]["id"] == previous[0]["id"]
                    previous = rows
                assert (Path(rows[0]["outputs"][0]) / payload.name).read_text(encoding="utf-8") == payload.read_text(encoding="utf-8")
            finally:
                await watcher.aclose()
    asyncio.run(scenario())


def test_real_recursive_watch_executions_keep_two_outer_rows(tmp_path, monkeypatch):
    # Synthetic events cannot detect the real pipeline dropping depth on a
    # lease/promotion update. Two tiny carrier executions cover all three
    # language boundaries without a format matrix or extra monitor process.
    # Deliver actual source-departure notifications before harvesting results;
    # direct completion alone misses the cleanup/observer race.
    import asyncio
    import io
    import zipfile
    from sunpack.pipeline.coordinator.engine import PipelineEngine
    from sunpack.runtime.watch.scheduler import WatchScheduler
    from sunpack.runtime.watch.scanner import watch_candidate_for_path
    from sunpack.runtime.watch.roots import WatchRootEntry
    from tests.helpers.config_factory import make_config
    # Submit directly without a filesystem observer or USN service.
    monkeypatch.setattr("sunpack.runtime.watch.scheduler.validate_ntfs_watch_roots", lambda _roots: None)

    root = tmp_path / "input"
    root.mkdir()
    source = root / "A.disguised"
    config = make_config({
        "recursive_extract": "3", "detection": {"enabled": True},
        "watch": {"clipboard_monitor_enabled": False},
        "post_extract": {"archive_cleanup_mode": "d"},
    })

    def archive(name, payload):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as package:
            package.writestr(name, payload)
        return stream.getvalue()

    async def scenario():
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(config, [str(root)], pipeline_engine=engine,
                state_path=str(tmp_path / "state.snapshot"), root_entries=[
                    WatchRootEntry(str(root), str(tmp_path / "output"), deep_detect=True)])
            try:
                watcher.log.recover()
                first_id = None
                payload = archive("B.other", archive("C.blob", archive("payload.txt", "same-payload")))
                for index in range(2):
                    source.write_bytes(b"carrier-prefix" + payload + b"carrier-tail")
                    watcher.enqueue(str(source), force=True, event_type="created")
                    request = await watcher._submit_candidate(watch_candidate_for_path(str(source)))
                    assert request is not None
                    await request.task
                    assert not source.exists()  # Real pipeline cleanup already ran.
                    watcher.notify_path_departed(str(source) if index == 0 else str(root), recursive=index == 1)
                    result = await watcher._finish_active_request(request)
                    assert result.failed == 0 and result.succeeded == 3
                    watcher.log.flush()
                    rows = _state_projection(watcher.log.path)["tasks"]["rows"]
                    assert len(rows) == index + 1
                    assert all(row["path"] == str(source) and row["name"] == source.name
                               and row["status"] == "taskSucceeded" for row in rows)
                    if first_id is None:
                        first_id = rows[0]["id"]
                    else:
                        assert len({row["id"] for row in rows}) == 2
                        assert first_id in {row["id"] for row in rows}
                        assert len({tuple(row["outputs"]) for row in rows}) == 2
                offline = rows
            finally:
                await watcher.aclose()
            assert _state_projection(tmp_path / "events.json")["tasks"]["rows"] == offline
    asyncio.run(scenario())
