from __future__ import annotations

import json
import time
import ctypes
import asyncio
from ctypes import wintypes
from types import SimpleNamespace

from tests.display_history import records as _records
from concurrent.futures import ThreadPoolExecutor

import sunpack.runtime.watch.log as log_module
from sunpack.runtime.watch.log import WatchLogStore
from sunpack.runtime.watch.state import WatchStateStore


def test_shared_display_history_keeps_results_on_disk_and_releases_live_groups(tmp_path):
    # Covers concurrent owners, complete history and live-family routing together.
    # Recovery tests cannot detect premature history eviction under a busy writer.
    path = tmp_path / "events.json"
    store = WatchLogStore(str(path))
    other = WatchLogStore(str(path))
    a, b = str(tmp_path / "carrier.fake"), str(tmp_path / "unrelated.002")
    store.recover()
    other.write("pipeline_sources_claimed", groups=[{"path": a, "name": "nested.rar", "members": [a, b]}])
    store.write("suspended_missing_volume", path=b)
    def produce(index):
        writer = store if index % 2 else other
        writer.write("processing_started", path=str(tmp_path / f"active-{index}.bin"))
        for n in range(12):
            writer.write("done", path=str(tmp_path / f"finished-{index}-{n}"))
            writer.write("scheduler_tick", padding="x" * 120)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(produce, range(40)))
    store.flush()
    rows = _records(path)
    assert len([r for r in rows if r["event"] == "done"]) == 480
    assert len([r for r in rows if r["event"] == "processing_started"]) == 40
    assert {a, b} == set(next(r["groups"][0]["members"] for r in rows if r["event"] == "pipeline_sources_claimed"))
    # Retire a large temporary live set while unrelated live families survive.
    # This also exercises sparse-slot compaction without a separate micro-test.
    for index in range(320):
        store.write("processing_started", path=str(tmp_path / f"temporary-{index}"))
    store.flush()
    for index in range(320):
        store.write("task_retired", path=str(tmp_path / f"temporary-{index}"), scope="task")
    store.flush()
    rows = _records(path)
    assert len([r for r in rows if r["event"] == "processing_started"]) == 40
    assert any(r["event"] == "suspended_missing_volume" for r in rows)
    store.close()
    other.write("done", path=b)
    other.flush()
    other.close()
    reopened = WatchLogStore(str(path))
    reopened.recover()
    reopened.flush()
    rows = _records(path)
    assert len([r for r in rows if r["event"] == "done"]) == 481
    assert not any(r["event"] == "processing_started" for r in rows)
    reopened.close()
    assert not list(tmp_path.rglob("*.wal*"))


def test_recovery_rebuilds_from_wal_with_groups_and_silent_blocker_retirement(tmp_path):
    # Replaying the JSONL cannot expose the WAL/event commit gap. Reopen the
    # actual state store: replace stale live state without losing results.
    path = tmp_path / "events.json"
    a, b = str(tmp_path / "opaque.001"), str(tmp_path / "opaque.002")
    (tmp_path / "opaque.001").write_bytes(b"0123456789")
    (tmp_path / "opaque.002").write_bytes(b"0123456789")
    departed = tmp_path / "opaque.003"
    departed.write_bytes(b"0123456789")
    store = WatchLogStore(str(path))
    state = WatchStateStore(str(tmp_path / "state.snapshot"))
    state._native.attach_events(store._native)
    store.recover()
    group = {"path": a, "members": [a, b, str(departed)], "name": "inside.rar"}
    store.write("pipeline_sources_claimed", groups=[group])
    assert state.mark(a, 10, 1.0, status="suspended_missing_volume", failure_payload={}, source_group=group)
    store.write("done", path=a)  # A completed execution is independent history.
    state.close()
    departed.unlink()  # Simulate a deletion before its JSONL notification.
    state = WatchStateStore(str(tmp_path / "state.snapshot"))
    state._native.attach_events(store._native)
    store.recover(state._native)
    store.flush()
    rows = _records(path)
    assert any(r["event"] == "done" for r in rows)
    assert not any(r["event"] == "processing_started" for r in rows)
    restored_group = [r for r in rows if r["event"] == "pipeline_sources_claimed"][-1]["groups"][0]
    assert restored_group["path"] == a and restored_group["name"] == group["name"]
    assert set(restored_group["members"]) == {a, b}
    assert any(r["event"] == "suspended_missing_volume" for r in rows)
    assert state.mark(b, 10, 1.0, status="failed_password", failure_payload={}, source_group=group)
    state.clear_entries([a])
    store.flush()
    statuses = [r for r in _records(path) if r["event"] in {"failed_password", "blocker_cleared"}]
    assert statuses[-1]["event"] == "failed_password" and statuses[-1]["path"] in {a, b}
    state.clear_entries([b])
    store.write("diagnostic", message="x" * 4096)
    store.flush()
    assert not any(r["event"] in {"task_queued", "processing_started", "failed_password", "suspended_missing_volume"} for r in _records(path) if r["event"] != "blocker_cleared")
    state.close()
    store.close()



def test_diagnostic_history_is_not_capacity_evicted_and_payloads_are_bounded(tmp_path):
    # The task-mode test misses diagnostics-only restart handling and oversized
    # Python payload conversion. This one scenario adds those distinct failures.
    path = tmp_path / "runtime.state.events.json"
    for index in range(4):
        store = WatchLogStore(str(path))
        for n in range(500):
            store.write("host_event", index=index * 500 + n, padding="x" * 100)
        store.flush()
        store.close()
    store = WatchLogStore(str(path))
    store.write("huge_error", error="错" * 2_000_000, nested=["y" * 10000] * 1000)
    store.flush()
    store.close()
    rows = _records(path)
    assert len(rows) == 2001
    assert rows[-1]["event"] == "huge_error" and rows[-1]["truncated"]
    assert len(json.dumps(rows[-1], ensure_ascii=False).encode()) < 32768


def test_utc_deadline_reclaims_disk_without_a_new_write_and_reloads_retention(tmp_path):
    # Other scenarios always submit new work. This catches a missing timer and
    # boundary-prefix reclamation; one real OS notification replaces polling.
    path = tmp_path / "events.json"
    store = WatchLogStore(str(path))
    expires = time.time() - 7 * 86400 + 2.0
    store.write("done", path="expired-carrier.001", ts=expires)
    store.write("pipeline_sources_claimed", processing=True, ts=expires,
                groups=[{"path":"waiting.fake", "members":["waiting.fake", "opaque.002"]}])
    store.write("suspended_missing_volume", path="opaque.002", ts=expires)
    store.write("done", path="retained-nested.bin", ts=expires + 60)
    store.flush()
    before = json.loads(path.read_text())
    run = before["runs"][0]
    folder = path.with_name(path.name + ".store")
    old_data = folder / (run["name"] + ".data")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.FindFirstChangeNotificationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
    kernel.FindFirstChangeNotificationW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.FindCloseChangeNotification.argtypes = [wintypes.HANDLE]
    change = kernel.FindFirstChangeNotificationW(str(tmp_path), False, 0x11)
    assert change != wintypes.HANDLE(-1).value
    try:
        assert kernel.WaitForSingleObject(change, 5000) == 0
        store.flush()
    finally:
        kernel.FindCloseChangeNotification(change)
    assert [r["path"] for r in _records(path) if r["event"] == "done"] == ["retained-nested.bin"]
    assert not any(r["event"] == "suspended_missing_volume" for r in _records(path))
    # The first record was the oldest run's prefix; its old compressed bytes
    # must be zeroed, or the whole old run removed, rather than just hidden.
    if old_data.exists():
        assert old_data.read_bytes().startswith(b"\0")
    shorter = WatchLogStore(str(path), retention_days=1)
    shorter.flush()
    assert not [r for r in _records(path) if r["event"] == "done"]
    shorter.close()
    store.close()


def test_blocker_group_is_durable_without_an_event_log(tmp_path):
    # A log-attached WAL cannot expose a reverse dependency on the projection.
    # Persist confirmed pipeline metadata with no logger and recover it later.
    path = str(tmp_path / "disguised.001")
    (tmp_path / "disguised.001").touch()
    state = WatchStateStore(str(tmp_path / "state.snapshot"))
    group = {"path": path, "name": "archive.rar", "members": [path]}
    try:
        assert state.mark(path, 0, 1.0, status="failed_password", source_group=group)
    finally:
        state.close()
    state = WatchStateStore(str(tmp_path / "state.snapshot"))
    log = WatchLogStore(str(tmp_path / "events.json"))
    try:
        log.recover(state._native)
        log.flush()
        rows = _records(log.path)
        assert next(r for r in rows if r["event"] == "pipeline_sources_claimed")["groups"][0]["members"] == [path]
        assert any(r["event"] == "failed_password" for r in rows)
        assert not any(r["event"] == "task_queued" for r in rows)
    finally:
        state.close()
        log.close()

def test_throttle_expiry_preserves_live_limits_and_releases_bounded_history(tmp_path, monkeypatch):
    # Rotation tests cannot catch early unthrottling or retained expired paths.
    # Cover both limits and expiry cheaply without producing thousands of logs.
    now = [100.0]
    monkeypatch.setattr(log_module.time, "monotonic", lambda: now[0])
    store = WatchLogStore(str(tmp_path / "events.json"))
    written = []
    monkeypatch.setattr(store, "write", lambda event, **payload: written.append(event))
    store.write_throttled("ignored", throttle_key="source", interval_seconds=300)
    store.write_throttled("error", throttle_key="source", interval_seconds=30)
    now[0] = 130.0
    store.clear_expired_history()
    assert store.next_history_expiry == 400.0
    store.write_throttled("ignored", throttle_key="source", interval_seconds=300)
    assert written == ["ignored", "error"]
    now[0] = 400.0
    store.clear_expired_history()
    assert not store._last_throttled_write
    assert store.next_history_expiry is None
    store.write_throttled("ignored", throttle_key="source", interval_seconds=300)
    assert written == ["ignored", "error", "ignored"]
    for index in range(2100):
        store.write_throttled("ignored", throttle_key=str(index), interval_seconds=300)
    assert len(store._last_throttled_write) == 2048
    now[0] = 700.0
    store.clear_expired_history()
    assert not store._last_throttled_write
    assert store.next_history_expiry is None


def test_log_corruption_rebuilds_through_cli_and_writer_and_retries_after_failure(tmp_path, monkeypatch):
    # Ordinary recovery preserves the log, so it cannot catch broken deletion,
    # CLI routing or a writer stuck after failed recovery. One WAL-backed coarse
    # scenario uniquely covers these contracts with a few small disk writes.
    from sunpack.runtime.cli.cli import build_cli_parser
    from sunpack.runtime.cli.cli_context import CliContext
    from sunpack.runtime.cli.commands import watch
    from sunpack.runtime.cli.runtime_host import RuntimeHost
    from sunpack.runtime.cli import runtime_state
    from tests.helpers.config_factory import make_config

    path = tmp_path / "events.json"
    source = tmp_path / "carrier.fake.002"
    source.touch()
    group = {"path": str(source), "name": "nested.rar", "members": [str(source)]}
    state_path = str(tmp_path / "state.snapshot")
    state = WatchStateStore(state_path)
    state.mark(str(source), 0, 1.0, status="suspended_missing_volume", source_group=group)
    state.close()  # Rebuild must actually load the WAL, with watch stopped.
    assert list(tmp_path.glob("*.wal"))
    log = WatchLogStore(str(path))
    log.write("done", path="old-completed-history")
    log.close()
    path.write_text("broken manifest", encoding="utf-8")
    folder = path.with_name(path.name + ".store")
    (folder / "broken.index").write_bytes(b"bad")

    config = make_config({"watch": {"state_dir": str(tmp_path)}})
    host = RuntimeHost()
    monkeypatch.setattr(runtime_state, "require_runtime_host", lambda: host)
    monkeypatch.setattr(watch, "load_request_config", lambda _: config)
    ctx = CliContext(language="en", cwd=str(tmp_path))
    args = build_cli_parser(ctx).parse_args(["watch", "rebuild-log"])

    async def command():
        code, result = await watch.handle(args, ctx)
        assert code == 0 and not result.errors

    def restored():
        rows = _records(path)
        assert not any(row["event"] == "done" and row["path"] == "old-completed-history" for row in rows)
        assert any(row["event"] == "suspended_missing_volume" for row in rows)
        restored_group = next(row for row in rows if row["event"] == "pipeline_sources_claimed")["groups"][0]
        assert {key: restored_group[key] for key in group} == group

    asyncio.run(command())
    restored()
    assert not (folder / "broken.index").exists()

    state = WatchStateStore(state_path)
    log = WatchLogStore(str(path))
    state._native.attach_events(log._native)
    host._watch_service = SimpleNamespace(log=log)
    try:
        # Force both publication and rebuild to fail, without a retry timer.
        log.flush()
        path.unlink()
        path.mkdir()
        log.write("done", path="lost-during-storage-failure")
        log.flush()  # Failed recovery must not escape to the business caller.
        assert log.error
        asyncio.run(command())  # The explicit CLI also swallows failed rebuilds.
        path.rmdir()
        log.write("done", path="after-storage-repair")
        log.flush()
        assert log.error is None
        restored()
        assert any(row.get("path") == "after-storage-repair" for row in _records(path))
        # GUI-reported damage can be invisible to an already-open Rust writer.
        path.write_text("[]", encoding="utf-8")
        asyncio.run(command())
        restored()
    finally:
        host._watch_service = None
        state.close()
        log.close()
