"""Real Watch pause boundaries, without weakening ordinary crash/offline recovery."""

import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from threading import Event

import psutil
import pytest

from tests.helpers.marker_utils import open_shared_file, replace_shared_file
from tests.helpers.native_fixture import native_fixture
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
    package.json("daemon", "start", "-nt")
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


def test_directory_resume_skips_paused_files_and_parent_respects_disabled_scope(package, tmp_path):
    parent = tmp_path / "watched"
    child = parent / "child"
    child.mkdir(parents=True)
    parent_out, child_out = tmp_path / "parent-out", tmp_path / "child-out"
    roots = package.data / "sunpack_watch_roots.txt"

    def save_child(enabled, scanned=True, *, parent_enabled=True, reload=True):
        pending = roots.with_suffix(".tmp")
        pending.write_text(
            f"{parent} | {parent_out} | false | true | true | {str(parent_enabled).lower()}\n"
            f"{child} | {child_out} | false | {str(scanned).lower()} | true | {str(enabled).lower()}\n",
            encoding="utf-8",
        )
        replace_shared_file(pending, roots)
        if reload:
            package.json("watch", "reload")
            _status(package, True)

    _archive(child, "original")
    save_child(True, scanned=False, reload=False)
    with package.watch_session():
        _output(child_out, "original")
        package.await_watch_event("done", path="original.zip")
        save_child(False)
        _archive(child, "paused")
        _archive(parent, "parent_active")
        _output(parent_out, "parent_active")
        save_child(True)
        _archive(child, "live")
        _output(child_out, "live")
        save_child(False, parent_enabled=False)

    _archive(child, "paused_offline")
    save_child(True, reload=False)
    with package.watch_session():
        _archive(child, "after_restart")
        _output(child_out, "after_restart")
        _archive(child, "paused", "edited_after_resume")
        _output(child_out, "edited_after_resume")

    assert sorted(path.name for path in parent_out.rglob("*.txt")) == ["parent_active.txt"]
    assert sorted(path.name for path in child_out.rglob("*.txt")) == [
        "after_restart.txt", "edited_after_resume.txt", "live.txt", "original.txt",
    ]
    display = native_fixture("display_events", path=str(package.data / ".sunpack_watch" / "events.json"))
    assert sum(row["event"] == "done" and Path(row.get("path", "")).name == "original.zip"
               for row in display["history"]) == 1


@pytest.mark.parametrize("unavailable", ["missing", "sharing_violation"])
def test_roots_reload_keeps_active_policy_until_config_is_readable(package, tmp_path, unavailable):
    watched, added = tmp_path / "watched", tmp_path / "added"
    output, added_output = tmp_path / "out", tmp_path / "added-out"
    watched.mkdir()
    added.mkdir()
    package.json("watch", "add", watched, "-o", output)
    roots = package.data / "sunpack_watch_roots.txt"

    with package.watch_session():
        _archive(watched, "before")
        done = package.await_watch_event("done", path="before.zip")
        next_policy = roots.read_text(encoding="utf-8") + (
            f"{added} | {added_output} | false | true | false | true\n"
        )
        with ExitStack() as restore:
            if unavailable == "missing":
                pending = roots.with_suffix(".tmp")
                pending.write_text(next_policy, encoding="utf-8")
                roots.unlink()
                restore.callback(replace_shared_file, pending, roots)
            else:
                writer = restore.enter_context(open_shared_file(roots, "w", share=0, encoding="utf-8"))
                writer.write(next_policy)
                writer.flush()
            assert package.json("watch", "reload")["summary"]["reloaded"] is False
            _archive(watched, "during")
            _output(output, "during")

        # A returning file or a released writer must apply the new policy
        # without a second explicit reload.
        package.await_watch_event("service_reloaded", after=done["ts"])
        _archive(added, "after")
        _output(added_output, "after")

    assert sorted(path.name for path in output.rglob("*.txt")) == ["before.txt", "during.txt"]


@pytest.mark.parametrize("shutdown", ["clean", "crash"])
def test_disabled_intent_survives_daemon_restart_and_skips_entire_interval(package, tmp_path, shutdown):
    root, output = tmp_path / "watched", tmp_path / "out"
    _start(package, root, output)
    package.json("watch", "disable")
    _archive(root, "paused_online")
    _shutdown(package, shutdown)
    _archive(root, "paused_offline")
    package.json("daemon", "start", "-nt")
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
    package.json("daemon", "start", "-nt")
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
