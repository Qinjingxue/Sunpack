import json
import subprocess
import time
import zipfile
from pathlib import Path

import pytest

from tests.helpers.native_fixture import native_fixture


pytestmark = pytest.mark.requires_watch_broker


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
    watched.rename(tmp_path / "old-root")
    nested = watched / "nested"
    nested.mkdir(parents=True)
    # Let the parent sentinel rebuild the replacement root's empty baseline.
    # Files present before this point are intentionally not treated as arrivals.
    wait_for_rebuild(rebuilt)
    _zip(nested / "first.zip", "first.txt", b"replacement root")
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


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("layout", ["outside-alias", "inside-alias", "direct"])
def test_owned_outputs_are_excluded_after_restart_but_admit_replacement(
    package, tmp_path, origin, layout,
):
    """Real extraction covers both registration routes and physical admission.

    Lexical lifecycle tests miss outputs created outside a scope through a
    junction. One nested archive also catches re-entry after WAL reopen, while
    replacing the directory proves exclusion is identity-based, not permanent.
    """
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
        nested, = real.rglob(inner.name)
        output = nested.parent
        # Keep the old directory alive so an ID cannot be immediately reused.
        output.rename(tmp_path / "previous-output")
        output.mkdir()
        package.json("watch", "start", "--no-tray")
        incoming = tmp_path / "external.zip"
        _zip(incoming, "external.txt", b"new input at the old output path")
        incoming.replace(output / incoming.name)
        _wait_for_output(real, "external.txt", b"new input at the old output path")
        package.json("watch", "start", "--once", "--no-tray")
        assert package.json("watch", "stop")["summary"]["stopped"]
        assert not list(real.rglob("generated.txt"))
    finally:
        package.run("watch", "stop")
        if alias != real:
            alias.rmdir()
