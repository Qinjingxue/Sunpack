from __future__ import annotations

import json
import weakref

import sunpack.runtime.watch.log as log_module

from sunpack.runtime.watch.log import (
    DEFAULT_EVENTS_MAX_BYTES,
    WatchLogStore,
    append_jsonl_record,
)


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_watch_log_defaults_to_one_megabyte():
    assert DEFAULT_EVENTS_MAX_BYTES == 1 * 1024 * 1024


def test_watch_log_resets_at_limit_without_creating_backups(tmp_path):
    path = tmp_path / "events.jsonl"
    store = WatchLogStore(str(path), max_bytes=160)

    for index in range(20):
        store.write("test_event", index=index, message="payload")

    assert path.exists()
    assert path.stat().st_size <= 160
    assert not list(tmp_path.glob("events.jsonl.*"))
    assert all(record["event"] == "test_event" for record in _records(path))
    assert _records(path)[-1]["index"] == 19
    another_owner = WatchLogStore(str(path))
    assert another_owner._path_lock is store._path_lock
    lock = weakref.ref(store._path_lock)
    del store
    assert lock() is another_owner._path_lock
    del another_owner
    assert lock() is None


def test_watch_log_rollover_discards_old_records(tmp_path):
    path = tmp_path / "events.jsonl"
    first = {"event": "first", "message": "a" * 32}
    second = {"event": "second", "message": "b" * 32}

    append_jsonl_record(path, first, max_bytes=80)
    append_jsonl_record(path, second, max_bytes=80)

    assert _records(path) == [second]
    assert not list(tmp_path.glob("events.jsonl.*"))


def test_watch_log_keeps_an_oversized_record_intact(tmp_path):
    path = tmp_path / "events.jsonl"
    store = WatchLogStore(str(path), max_bytes=64)

    store.write("large_event", message="x" * 256)

    records = _records(path)
    assert len(records) == 1
    assert records[0]["event"] == "large_event"
    assert records[0]["message"] == "x" * 256


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
