from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import sunpack.runtime.watch.log as log_module
from sunpack.runtime.watch.log import WatchLogStore
from sunpack.runtime.watch.state import WatchStateStore


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_shared_async_log_compacts_history_without_losing_active_groups(tmp_path):
    # Old rollover tests cannot catch lost live tasks or disagreeing producers.
    # One concurrent burst covers grouping, history budgets and both log modes.
    path = tmp_path / "events.jsonl"
    store = WatchLogStore(str(path), max_bytes=4096)
    other = WatchLogStore(str(path), max_bytes=4096)
    store.recover()
    a, b = str(tmp_path / "carrier.fake"), str(tmp_path / "unrelated.002")
    other.write("pipeline_sources_claimed", groups=[{"path": a, "name": "nested.rar", "members": [a, b]}])
    store.write("suspended_missing_volume", path=b)
    def produce(index):
        owner = store if index % 2 else other
        owner.write("processing_started", path=str(tmp_path / f"long-{index}.bin"))
        for n in range(12):
            owner.write("done", path=str(tmp_path / f"finished-{index}-{n}"))
            owner.write("scheduler_tick", padding="x" * 120)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(produce, range(40)))
    # Force one more compaction after the concurrent burst has drained.
    for n in range(80):
        store.write("scheduler_tick", padding="x" * 120)
    for _ in range(16):
        store.write("scheduler_tick", padding="x" * 4096)
    store.flush()
    rows = _records(path)
    assert len({r["path"] for r in rows if r["event"] == "processing_started"}) == 40
    groups = [g for r in rows if r["event"] == "pipeline_sources_claimed" for g in r["groups"]]
    assert {a, b} == set(groups[0]["members"])
    assert any(r["event"] == "suspended_missing_volume" and r["path"] in {a, b} for r in rows)
    assert path.stat().st_size < 40 * 500 + 16000
    assert not list(tmp_path.glob("events.jsonl.*"))
    store.close()  # A second owner must remain usable.
    other.write("done", path=b)
    other.flush()
    assert _records(path)[-1]["event"] == "done"
    other.write("processing_started", path=b)
    other.write("no_tasks_found", path=b, retire_group=True)
    for _ in range(16):
        other.write("scheduler_tick", padding="x" * 4096)
    other.flush()
    # Retiring a fresh empty request must preserve the previous execution.
    assert any(r["event"] == "done" and r["path"] in {a, b} for r in _records(path))
    assert not any(r["event"] == "processing_started" and r["path"] == b for r in _records(path))
    other.close()
    diagnostic = WatchLogStore(str(tmp_path / "runtime-test.state.events.jsonl"), max_bytes=2048)
    for n in range(100): diagnostic.write("host_event", index=n, padding="x" * 120)
    diagnostic.flush()
    assert diagnostic.path.stat().st_size < 8192
    assert _records(diagnostic.path)[-1]["index"] == 99
    diagnostic.close()
    diagnostic = WatchLogStore(str(tmp_path / "runtime-test.state.events.jsonl"), max_bytes=2048)
    diagnostic.write("host_restarted")
    diagnostic.flush()
    assert any(r.get("index") == 99 for r in _records(diagnostic.path))
    diagnostic.close()


def test_recovery_rebuilds_from_wal_with_groups_and_silent_blocker_retirement(tmp_path):
    # Replaying the JSONL cannot expose the WAL/event commit gap. Reopen the
    # actual state store: replace stale live state without losing results.
    path = tmp_path / "events.jsonl"
    a, b = str(tmp_path / "opaque.001"), str(tmp_path / "opaque.002")
    (tmp_path / "opaque.001").write_bytes(b"0123456789")
    (tmp_path / "opaque.002").write_bytes(b"0123456789")
    departed = tmp_path / "opaque.003"
    departed.write_bytes(b"0123456789")
    store = WatchLogStore(str(path), max_bytes=8192)
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



def test_diagnostic_restarts_and_large_payloads_stay_bounded(tmp_path):
    # One-run rotation cannot find a size reset between lifetimes or an event
    # name accidentally turning a diagnostic log into unlimited active state.
    path = tmp_path / "runtime.state.events.jsonl"
    for index in range(40):
        store = WatchLogStore(str(path), max_bytes=8192)
        try:
            store.write("processing_started", path=f"diagnostic-{index}", message="x" * 1024)
            store.flush()
        finally:
            store.close()
        assert path.stat().st_size < 20000
    store = WatchLogStore(str(path), max_bytes=128 * 1024)
    try:
        for index in range(3000):
            store.write("processing_started", path=f"diagnostic-only-{index}", message="x" * 100)
        store.flush()
        assert path.stat().st_size < 256 * 1024
        store.write("huge_error", error="错" * 2_000_000, nested=["y" * 10000] * 1000)
        store.flush()
        row = _records(path)[-1]
        assert row["event"] == "huge_error" and row["truncated"]
        assert len(json.dumps(row, ensure_ascii=False).encode("utf-8")) < 32768
    finally:
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
    log = WatchLogStore(str(tmp_path / "events.jsonl"))
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
    store = WatchLogStore(str(tmp_path / "events.jsonl"))
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
