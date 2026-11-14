import os
import json
import subprocess
import time
import zipfile
from pathlib import Path

import pytest
import psutil

from tests.helpers.native_fixture import native_fixture


pytestmark = pytest.mark.requires_watch_broker


def test_rootless_watch_restores_foreground_process_priority(package, tmp_path):
    package.configure(runtime={"process_mode": "normal"})
    package.json("watch", "start", "--no-tray")
    source = tmp_path / "archive.zip"
    _zip(source, "payload.txt", b"payload")
    assert package.json("scan", source)["summary"]["archive_count"] == 1

    state = next(package.data.glob("runtime-*.state"))
    owner = psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))
    assert owner.nice() == psutil.NORMAL_PRIORITY_CLASS


def _zip(path, name, content):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, content)


def _wait_for_output(output, name, expected):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        paths = list(output.rglob(name))
        try:
            if len(paths) == 1 and paths[0].read_bytes() == expected:
                return
        except OSError:
            pass  # The worker can still hold the output open while writing.
        time.sleep(0.05)
    pytest.fail(f"Watch did not produce {name} in {output}")


def test_watch_rearms_the_root_object_after_rename_and_recreation(package, tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    package.json("watch", "add", watched, "-R", "-o", output)
    package.json("watch", "start", "--no-tray")
    events = package.data / ".sunpack_watch" / "events.json"

    def wait_for_rebuild(previous):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                history = native_fixture("display_events", path=str(events))["history"]
            except subprocess.CalledProcessError:
                pass  # The display store may still be publishing its manifest.
            else:
                count = sum(
                    row["event"] == "catalog_rebuilt" and Path(row.get("root", "")) == watched
                    for row in history
                )
                if count > previous:
                    return count
            time.sleep(0.05)
        pytest.fail("Watch did not rebuild the configured root after its directory changed")

    rebuilt = wait_for_rebuild(0)
    # The old directory remains alive, so an old handle can remain healthy
    # even though the configured path now denotes a different object.
    replacement = tmp_path / "replacement"
    nested = replacement / "nested"
    nested.mkdir(parents=True)
    _zip(nested / "first.zip", "first.txt", b"replacement root")
    watched.rename(tmp_path / "old-root")
    replacement.rename(watched)
    nested = watched / "nested"
    # Runtime directory arrival must enumerate archives already present in
    # the new object, unlike startup's missing-catalog conservative baseline.
    wait_for_rebuild(rebuilt)
    _wait_for_output(output, "first.txt", b"replacement root")

    # A later change below an already existing subdirectory cannot be rescued
    # by a nonrecursive parent sentinel. The root itself must be reattached.
    _zip(nested / "later.zip", "later.txt", b"reattached subscription")
    _wait_for_output(output, "later.txt", b"reattached subscription")
    assert package.json("watch", "stop")["summary"]["stopped"]


def test_watch_output_home_expansion_in_add_and_roots_file(package, tmp_path):
    home = tmp_path / "profile"
    home.mkdir()
    package.env["USERPROFILE"] = str(home)
    added = tmp_path / "added"
    loaded = tmp_path / "loaded"
    added.mkdir()
    loaded.mkdir()
    _zip(added / "first.zip", "first.txt", b"added output")
    _zip(loaded / "second.zip", "second.txt", b"roots file output")
    package.json("watch", "add", added, "-o", "~/added-output")
    roots = package.data / "sunpack_watch_roots.txt"
    assert str(home / "added-output") in roots.read_text(encoding="utf-8")
    with roots.open("a", encoding="utf-8") as stream:
        stream.write(f"{loaded} | ~\\loaded-output | false | false | false\n")
    package.json("watch", "start", "--once", "--no-tray")
    assert [p.read_bytes() for p in (home / "added-output").rglob("first.txt")] == [b"added output"]
    assert [p.read_bytes() for p in (home / "loaded-output").rglob("second.txt")] == [b"roots file output"]
    assert not (added / "~").exists()
    assert not (loaded / "~").exists()


def test_cold_watch_once_collects_the_clipboard_before_dispatch(package, tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    payload = tmp_path / "secret.txt"
    payload.write_bytes(b"one-shot clipboard password")
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mhe=on", "-pclipboard-only-key",
         str(watched / "secret.7z"), str(payload)],
        check=True, capture_output=True,
    )
    package.configure(watch={"clipboard_monitor_enabled": True, "clipboard_builtin_max_entries": 2})
    # Keep the STA owner alive while Watch reads the real clipboard, then
    # restore all formats captured before the test changed it.
    script = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$previous = [System.Windows.Forms.Clipboard]::GetDataObject()
$saved = New-Object System.Windows.Forms.DataObject
if ($null -ne $previous) {
    foreach ($format in $previous.GetFormats($false)) {
        $saved.SetData($format, $false, $previous.GetData($format, $false))
    }
}
try {
    [System.Windows.Forms.Clipboard]::SetText("discarded`nretained`nclipboard-only-key")
    # With no roots, even once must not import the current clipboard.
    & $env:SUNPACK_CLIPBOARD_TEST_LAUNCHER watch start --once --no-tray --json
    if ($LASTEXITCODE -ne 0) { throw "empty-root once failed" }
    $passwords = Get-Content -Raw $env:SUNPACK_CLIPBOARD_TEST_PASSWORDS | ConvertFrom-Json
    if (@($passwords.clipboard_history).Count -gt 0 -and $null -ne $passwords.clipboard_history) {
        throw "empty-root once imported clipboard passwords"
    }
    & $env:SUNPACK_CLIPBOARD_TEST_LAUNCHER watch add $env:SUNPACK_CLIPBOARD_TEST_ROOT -o $env:SUNPACK_CLIPBOARD_TEST_OUTPUT --json
    if ($LASTEXITCODE -ne 0) { throw "watch add failed" }
    & $env:SUNPACK_CLIPBOARD_TEST_LAUNCHER watch start --once --no-tray --json
    $result = $LASTEXITCODE
} finally {
    if ($saved.GetFormats($false).Count -gt 0) {
        [System.Windows.Forms.Clipboard]::SetDataObject($saved, $true)
    } else {
        [System.Windows.Forms.Clipboard]::Clear()
    }
}
exit $result
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-STA", "-Command", script],
        cwd=package.data,
        env={**package.env, "SUNPACK_CLIPBOARD_TEST_LAUNCHER": str(package.launcher),
             "SUNPACK_CLIPBOARD_TEST_ROOT": str(watched),
             "SUNPACK_CLIPBOARD_TEST_OUTPUT": str(output),
             "SUNPACK_CLIPBOARD_TEST_PASSWORDS": str(package.data / "builtin_passwords.json")},
        text=True, encoding="utf-8", capture_output=True, timeout=60,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert [p.read_bytes() for p in output.rglob(payload.name)] == [payload.read_bytes()]
    document = json.loads((package.data / "builtin_passwords.json").read_text(encoding="utf-8"))
    assert document["clipboard_history"] == ["retained", "clipboard-only-key"]


def test_once_drains_admitted_work_without_waiting_for_a_busy_pending_file(package, tmp_path):
    import ctypes
    from ctypes import wintypes

    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    busy = watched / "busy.zip"
    _zip(busy, "busy.txt", b"recover after unlock")
    _zip(watched / "ready.zip", "ready.txt", b"drain this round")
    package.json("watch", "add", watched, "-o", output)

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    # Share metadata reads so Watch can durably observe the candidate, while
    # our WRITE access conflicts with its exclusive readiness boundary.
    handle = kernel.CreateFileW(str(busy), 0x40000000, 7, None, 3, 0x80, None)
    assert handle != wintypes.HANDLE(-1).value, ctypes.get_last_error()
    try:
        package.json("watch", "start", "--once", "--no-tray", timeout=30)
        assert [path.read_bytes() for path in output.rglob("ready.txt")] == [b"drain this round"]
        assert not list(output.rglob("busy.txt"))
        assert not package.json("watch", "status")["summary"]["running"]
        # Close/reopen stores, not merely the scheduler: deferred work must be
        # in the journal, rather than surviving only in a resident pending map.
        assert package.run("--persistent-shutdown").returncode == 0
    finally:
        assert kernel.CloseHandle(handle), ctypes.get_last_error()
    package.json("watch", "start", "--once", "--no-tray")
    assert [path.read_bytes() for path in output.rglob("busy.txt")] == [b"recover after unlock"]
    assert [path.read_bytes() for path in output.rglob("ready.txt")] == [b"drain this round"]


def test_watch_observes_edits_to_config_symlink_target(package, tmp_path):
    config = package.data / "sunpack_config.json"
    real_config = tmp_path / "watch-settings.json"
    config.replace(real_config)
    try:
        config.symlink_to(real_config)
    except OSError as error:
        if error.winerror != 1314:
            raise
        pytest.skip("Creating file symlinks requires Windows Developer Mode or SeCreateSymbolicLinkPrivilege")

    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    package.json("watch", "add", watched, "-o", output)
    package.json("watch", "start", "--no-tray")

    first = watched / "keep.zip"
    _zip(first, "kept.txt", b"keep the first source")
    _wait_for_output(output, "kept.txt", b"keep the first source")
    assert first.is_file()

    payload = json.loads(real_config.read_text(encoding="utf-8"))
    payload["post_extract"]["archive_cleanup_mode"] = "d"
    replacement = real_config.with_suffix(".tmp")
    replacement.write_text(json.dumps(payload), encoding="utf-8")
    replacement.replace(real_config)
    # Use the real reload signal so an explicit config command cannot mask a
    # missing subscription on the link's destination.
    events = package.data / ".sunpack_watch" / "events.json"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            history = native_fixture("display_events", path=str(events))["history"]
        except subprocess.CalledProcessError:
            pass  # The display store may still be publishing its manifest.
        else:
            if any(row["event"] == "service_reloaded" for row in history):
                break
        time.sleep(0.05)
    else:
        pytest.fail("Watch did not reload after editing the config symlink target")
    second = watched / "delete.zip"
    _zip(second, "deleted.txt", b"delete the second source")
    _wait_for_output(output, "deleted.txt", b"delete the second source")
    package.json("watch", "stop")
    assert not second.exists()


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("layout", ["outside-alias", "inside-alias", "direct"])
def test_settled_outputs_ignore_old_writes_but_admit_changes_after_restart(
    package, tmp_path, origin, layout,
):
    """Output baselines survive restart; additions and edits remain ordinary inputs."""
    watched = tmp_path / "watched"
    real = watched / "physical"
    real.mkdir(parents=True)
    if layout == "direct":
        alias = real
    else:
        alias = (watched if layout == "inside-alias" else tmp_path) / "junction"
        subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(real)],
            check=True, capture_output=True,
        )
    inner = tmp_path / "inner.zip"
    _zip(inner, "generated.txt", b"must stay inside the nested archive")
    source = tmp_path / "outer.zip"
    _zip(source, inner.name, inner.read_bytes())
    package.configure(recursive_extract=1, post_extract={"flatten_single_directory": False})
    package.json("watch", "add", watched, "-R", "-o", alias / "results")
    try:
        package.json("watch", "start", "--no-tray")
        if origin == "foreground":
            package.json("extract", "-r", "1", "-o", alias / "results", source)
        else:
            source.replace(watched / source.name)
        _wait_for_output(real, inner.name, inner.read_bytes())
        # A real admission round and drain, not a sleep-based negative check.
        package.json("watch", "start", "--once", "--no-tray")
        assert package.json("watch", "stop")["summary"]["stopped"]
        assert not list(real.rglob("generated.txt"))
        assert package.run("--persistent-shutdown").returncode == 0
        package.json("watch", "start", "--once", "--no-tray")
        assert not list(real.rglob("generated.txt"))
        history = native_fixture("display_events", path=str(package.data / ".sunpack_watch" / "events.json"))["history"]
        assert not [row for row in history if row["event"] in {"candidate_active", "pipeline_request_started"}
                    and Path(row.get("path", "")).name == inner.name], history
        nested, = real.rglob(inner.name)
        output = nested.parent
        package.json("watch", "start", "--no-tray")
        incoming = tmp_path / "external.zip"
        _zip(incoming, "external.txt", b"new input at the old output path")
        incoming.replace(output / incoming.name)
        _wait_for_output(real, "external.txt", b"new input at the old output path")
        replacement = tmp_path / "replacement.zip"
        _zip(replacement, "changed.txt", b"changed nested archive is now an input")
        replacement.replace(nested)
        _wait_for_output(real, "changed.txt", b"changed nested archive is now an input")
        package.json("watch", "start", "--once", "--no-tray")
        assert package.json("watch", "stop")["summary"]["stopped"]
        assert not list(real.rglob("generated.txt"))
    finally:
        package.run("watch", "stop")
        if alias != real:
            alias.rmdir()


def test_watch_retries_unobserved_candidate_after_acl_only_recovery(package, tmp_path):
    # No data/rename event occurs after permission is restored. Validate real
    # metadata-visible but identity-unreadable candidate and an idle, empty queue
    # before the SECURITY-only repair. A raw SYNCHRONIZE deny is necessary:
    # FileSystemAccessRule strips SYNCHRONIZE from Deny rules, and denying
    # parent enumeration would fail is_file before reaching the observation.
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    source = watched / "restricted.zip"
    _zip(source, "restored.txt", b"ACL-only arrival recovery")
    idle_probe = tmp_path / "idle-probe.zip"
    _zip(idle_probe, "probe.txt", b"idle reader barrier")
    acl_script = tmp_path / "candidate-acl.ps1"
    acl_script.write_text(r"""
param([string]$Path, [string]$Saved, [switch]$Restore)
$ErrorActionPreference = 'Stop'
$acl = Get-Acl -LiteralPath $Path
if ($Restore) {
    $acl.SetSecurityDescriptorSddlForm([IO.File]::ReadAllText($Saved), [Security.AccessControl.AccessControlSections]::Access)
} else {
    [IO.File]::WriteAllText($Saved, $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access))
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($acl.Sddl)
    $ace = New-Object Security.AccessControl.CommonAce([Security.AccessControl.AceFlags]::None, [Security.AccessControl.AceQualifier]::AccessDenied, 0x100000, $sid, $false, $null)
    $raw.DiscretionaryAcl.InsertAce(0, $ace)
    $acl.SetSecurityDescriptorSddlForm($raw.GetSddlForm([Security.AccessControl.AccessControlSections]::Access), [Security.AccessControl.AccessControlSections]::Access)
}
Set-Acl -LiteralPath $Path -AclObject $acl
if ($Restore) {
    $actual = (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    if ($actual -ne [IO.File]::ReadAllText($Saved)) { throw "Original DACL was not restored" }
}
""", encoding="utf-8")
    saved = tmp_path / "original-acl.txt"

    def acl(path, restore=False):
        command = ["powershell.exe", "-NoProfile", "-File", str(acl_script),
                   "-Path", str(path), "-Saved", str(saved)]
        if restore:
            command.append("-Restore")
        # Windows PowerShell must resolve its own modules, not inherit the
        # incompatible PowerShell 7 module path from the test runner.
        environment = {name: value for name, value in os.environ.items()
                       if name.lower() != "psmodulepath"}
        result = subprocess.run(command, capture_output=True, text=True, env=environment)
        assert result.returncode == 0, (result.stdout, result.stderr)

    package.configure(watch={"runtime_cache_cleanup_idle_seconds": 0.25})
    package.json("watch", "add", watched, "-R", "-o", output)
    events = package.data / ".sunpack_watch" / "events.json"
    current = source
    try:
        acl(source)
        package.json("watch", "start", "--no-tray")
        assert current.is_file() and current.stat().st_size > 0
        # Assert that this machine/token really reaches the required failure:
        # FILE_READ_ATTRIBUTES alone may remain available through parent list.
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                      ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        kernel.CreateFileW.restype = ctypes.c_void_p
        handle = kernel.CreateFileW(str(current), 0x80, 7, None, 3, 0, None)
        error = ctypes.get_last_error()
        if handle != ctypes.c_void_p(-1).value:
            kernel.CloseHandle(ctypes.c_void_p(handle))
            pytest.fail("ACL fixture did not deny FILE_READ_ATTRIBUTES")
        assert error == 5, error
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                history = native_fixture("display_events", path=str(events))["history"]
                if any(item.get("event") == "candidate_ignored"
                       and item.get("reason") == "observation_error"
                       and Path(item.get("path", "")) == current for item in history):
                    break
            except (OSError, subprocess.CalledProcessError):
                pass
            time.sleep(0.01)
        else:
            pytest.fail("Watch did not observe the identity denial during its initial scan")
        assert package.json("watch", "status")["summary"]["pending"] == 0
        package.json("scan", idle_probe)
        # Reader-cache release is an observable idle-maintenance barrier. An
        # exclusive open cannot succeed while the runtime retains its reader.
        deadline = time.monotonic() + 30
        saw_cached_reader = False
        while time.monotonic() < deadline:
            handle = kernel.CreateFileW(str(idle_probe), 0x80000000, 0, None, 3, 0, None)
            if handle != ctypes.c_void_p(-1).value:
                kernel.CloseHandle(ctypes.c_void_p(handle))
                break
            assert ctypes.get_last_error() in (32, 33)
            saw_cached_reader = True
            time.sleep(0.01)
        else:
            pytest.fail("Watch idle maintenance did not release the foreground reader")
        assert saw_cached_reader, "idle barrier did not observe a retained reader"
        assert not list(output.rglob("restored.txt"))
        acl(current, restore=True)
        _wait_for_output(output, "restored.txt", b"ACL-only arrival recovery")
        assert len(list(output.rglob("restored.txt"))) == 1
    finally:
        if saved.exists():
            acl(current, restore=True)
        package.json("watch", "stop")


def test_password_blocked_split_group_retires_departed_non_head_member(package, tmp_path):
    import random

    watched = tmp_path / "watched"
    watched.mkdir()
    payload = tmp_path / "payload.bin"
    payload.write_bytes(random.Random(105).randbytes(8192))
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", "-v1k", "-mhe=on",
         "-pdeparted-member-only", str(watched / "locked.7z"), str(payload)],
        check=True, capture_output=True,
    )
    parts = sorted(watched.glob("locked.7z.*"))
    assert len(parts) >= 3
    package.json("watch", "add", watched, "-o", tmp_path / "out")
    package.json("watch", "start", "--no-tray")
    events = package.data / ".sunpack_watch" / "events.json"

    def wait_members(expected):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                rows = native_fixture("display_events", path=str(events))["live"]
            except subprocess.CalledProcessError:
                pass
            else:
                blocked = [row for row in rows if row.get("event") == "failed_password"
                           and Path(row.get("path", "")) == parts[0]]
                if len(blocked) == 1 and {
                    Path(member) for member in blocked[0].get("group", {}).get("members", [])
                } == expected:
                    return
            time.sleep(0.05)
        pytest.fail("Password blocker did not publish the current physical member set")

    try:
        wait_members(set(parts))
        # No write to the head or password change accompanies this departure.
        parts[-1].replace(tmp_path / parts[-1].name)
        wait_members(set(parts[:-1]))
    finally:
        package.json("watch", "stop")
