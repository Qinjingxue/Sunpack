"""Watch recovery with a disposable catalog that cannot persist its snapshot."""
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


def _wait(predicate, message):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (OSError, subprocess.CalledProcessError):
            pass
        time.sleep(0.05)
    pytest.fail(message)


def test_runtime_rebuild_keeps_arrivals_after_catalog_persistence_fails(package, tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    output = tmp_path / "out"
    _zip(watched / "baseline.zip", "baseline.txt", b"startup baseline")
    roots = package.data / "sunpack_watch_roots.txt"
    # A previously-scanned root starts without a trusted persisted catalog.
    # Its old files establish a baseline; only arrivals after startup run.
    roots.write_text(f"{watched} | {output} | false | true | true | true\n", encoding="utf-8")
    state = package.data / ".sunpack_watch"
    state.mkdir()
    # Real snapshot creation failure, not a product test hook. The initial
    # inventory remains resident while the disposable persistent store closes.
    (state / "catalog.snapshot.bin.tmp").mkdir()
    package.json("daemon", "start", "-nt")
    events = state / "events.json"
    _wait(
        lambda: any(row.get("event") == "catalog_persistence_failed"
                    for row in native_fixture("display_events", path=str(events))["history"]),
        "catalog snapshot failure was not reported",
    )
    arrival = tmp_path / "arrival"
    arrival.mkdir()
    _zip(arrival / "new.zip", "new.txt", b"runtime arrival")
    # A directory arrival has no direct-file compensation. It must be emitted
    # by the full in-memory catalog refresh when the saved cursor is unavailable.
    arrival.rename(watched / "arrived")
    _wait(lambda: any(p.read_bytes() == b"runtime arrival" for p in output.rglob("new.txt")),
          "runtime rebuild swallowed the directory arrival")
    assert package.json("daemon", "stop")["summary"]["running"] is False
    assert not list(output.rglob("baseline.txt"))
    assert len(list(output.rglob("new.txt"))) == 1


def test_relative_roots_file_input_uses_runtime_working_directory(package, tmp_path):
    # The native launcher starts its server in the install directory, not
    # the client's invocation directory or the ProgramData roots-file folder.
    cwd = tmp_path / "client-cwd"
    cwd.mkdir()
    watched = package.launcher.parent.parent / "relative-input"
    watched.mkdir()
    output = tmp_path / "output"
    _zip(watched / "input.zip", "input.txt", b"process cwd")
    paused = tmp_path / "paused"
    paused.mkdir()
    _zip(paused / "paused.zip", "paused.txt", b"reactivated")
    roots = package.data / "sunpack_watch_roots.txt"
    roots.write_text(f"relative-input | {output} | false | false | false | true\n"
                     f"{paused} | {output} | false | false | false | false\n", encoding="utf-8")
    with package.watch_session(cwd=cwd):
        package.await_watch_event("done", path="input.zip")
        assert package.json("watch", "list")["summary"]["count"] == 1
        assert not list(output.rglob("paused.txt"))
        # The first scan's marker write must retain the disabled row. Re-enable
        # it through the same atomic file replacement performed by the GUI.
        lines = roots.read_text(encoding="utf-8").splitlines()
        assert lines[1].endswith(" | false")
        lines[1] = lines[1].rsplit("|", 1)[0] + "| true"
        pending = roots.with_suffix(".tmp")
        pending.write_text("\n".join(lines) + "\n", encoding="utf-8")
        pending.replace(roots)
        package.json("watch", "reload")
        package.await_watch_event("done", path="paused.zip")
    assert [p.read_bytes() for p in output.rglob("input.txt")] == [b"process cwd"]
    assert [p.read_bytes() for p in output.rglob("paused.txt")] == [b"reactivated"]
