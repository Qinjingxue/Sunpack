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
    package.json("watch", "add", watched, "-o", output)
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
        env={**package.env, "SUNPACK_CLIPBOARD_TEST_LAUNCHER": str(package.launcher)},
        text=True, encoding="utf-8", capture_output=True, timeout=60,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert [p.read_bytes() for p in output.rglob(payload.name)] == [payload.read_bytes()]
    document = json.loads((package.data / "builtin_passwords.json").read_text(encoding="utf-8"))
    assert document["clipboard_history"] == ["retained", "clipboard-only-key"]
