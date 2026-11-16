"""Real Watch pause boundaries, without weakening ordinary crash/offline recovery."""

import zipfile
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import psutil
import pytest

from tests.helpers.package import wait_for

pytestmark = pytest.mark.requires_watch_broker


def _archive(root, name, member=None):
    with zipfile.ZipFile(root / f"{name}.zip", "w") as archive:
        member = member or name
        archive.writestr(f"{member}.txt", member.encode())


def _status(package, enabled):
    status = package.json("watch", "status")["summary"]
    assert status["running"] and status["enabled"] is enabled, status
    assert not status["last_error"], status
    return status


def _owner(package):
    state = next(package.data.glob("runtime-*.state"))
    return psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3]))


def _output(output, name):
    def ready():
        paths = list(output.rglob(f"{name}.txt"))
        try:
            return len(paths) == 1 and paths[0].read_bytes() == name.encode()
        except OSError:
            return False
    wait_for(ready, f"Watch extraction of {name}")


def _start(package, root, output):
    root.mkdir()
    package.json("watch", "add", root, "-o", output)
    package.json("daemon", "start", "--no-tray")
    package.await_watch_admission()
    _status(package, True)


def _drain(package):
    assert package.json("daemon", "stop")["summary"]["running"] is False


def _shutdown(package, mode):
    if mode == "clean":
        _drain(package)
    else:
        # Only the PID published by this isolated fixture's runtime endpoint.
        owner = _owner(package)
        assert owner.exe().lower() == str(package.launcher.parent.parent / "sunpack-runtime.exe").lower()
        owner.kill()
        owner.wait(timeout=30)


def test_disable_keeps_daemon_and_enable_skips_only_paused_arrivals(package, tmp_path):
    root, output = tmp_path / "watched", tmp_path / "out"
    _start(package, root, output)
    for name in ("original_modify", "original_rename", "original_delete"):
        _archive(root, name)
        _output(output, name)
        package.await_watch_event("done", path=f"{name}.zip")
    owner = _owner(package)
    package.json("watch", "disable")
    _status(package, False)
    assert owner.is_running() and _owner(package) == owner
    _archive(root, "paused")
    _archive(root, "original_modify", "paused_modified")
    (root / "original_rename.zip").rename(root / "renamed_while_paused.zip")
    (root / "original_delete.zip").unlink()
    package.json("watch", "enable")
    _status(package, True)
    assert _owner(package) == owner
    _archive(root, "active")
    _output(output, "active")
    # An ignored paused arrival is a baseline, not a permanent suppression.
    _archive(root, "paused", "edited_after_resume")
    _output(output, "edited_after_resume")
    _drain(package)
    assert sorted(p.name for p in output.rglob("*.txt")) == sorted(
        f"{name}.txt" for name in ("original_modify", "original_rename", "original_delete",
                                    "active", "edited_after_resume")
    )
    assert not list(output.rglob("paused.txt"))
    assert (root / "paused.zip").is_file()


@pytest.mark.parametrize("shutdown", ["clean", "crash"])
def test_disabled_intent_survives_daemon_restart_and_skips_entire_interval(package, tmp_path, shutdown):
    root, output = tmp_path / "watched", tmp_path / "out"
    _start(package, root, output)
    package.json("watch", "disable")
    _archive(root, "paused_online")
    _shutdown(package, shutdown)
    _archive(root, "paused_offline")
    package.json("daemon", "start", "--no-tray")
    _status(package, False)
    _archive(root, "paused_restarted")
    package.json("watch", "enable")
    _status(package, True)
    _archive(root, "resumed")
    _output(output, "resumed")
    _drain(package)
    assert sorted(p.name for p in output.rglob("*.txt")) == ["resumed.txt"]


@pytest.mark.parametrize("shutdown", ["clean", "crash"])
def test_enabled_daemon_restart_still_recovers_offline_arrivals(package, tmp_path, shutdown):
    root, output = tmp_path / "watched", tmp_path / "out"
    _start(package, root, output)
    # Establish a proven persisted catalog before taking the daemon offline.
    _archive(root, "before")
    _output(output, "before")
    package.await_watch_event("done", path="before.zip")
    _shutdown(package, shutdown)
    _archive(root, "offline")
    package.json("daemon", "start", "--no-tray")
    _status(package, True)
    _output(output, "offline")
    _drain(package)
    assert sorted(p.name for p in output.rglob("*.txt")) == ["before.txt", "offline.txt"]


def test_enable_racing_arrivals_keeps_acknowledged_future_changes(package, tmp_path):
    root, output = tmp_path / "watched", tmp_path / "out"
    _start(package, root, output)
    package.json("watch", "disable")
    began, enabled = Event(), Event()

    def produce():
        _archive(root, "racing_0")
        began.set()
        for index in range(1, 32):
            _archive(root, f"racing_{index}")
        assert enabled.wait(60), "enable did not acknowledge"
        # Classification of the racing writes is intentionally unspecified.
        # Changes after the acknowledged boundary must never be swallowed.
        _archive(root, "post_ack")
        _archive(root, "racing_0", "changed_after_ack")

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(produce)
        assert began.wait(60), "producer did not start"
        try:
            package.json("watch", "enable")
        finally:
            enabled.set()
        pending.result(timeout=60)
    _output(output, "post_ack")
    _output(output, "changed_after_ack")
    _drain(package)
