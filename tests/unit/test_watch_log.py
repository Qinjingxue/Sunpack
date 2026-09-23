from __future__ import annotations

import json

from sunpack.watch.log import (
    DEFAULT_EVENTS_MAX_BYTES,
    WatchLogStore,
)


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_watch_log_defaults_to_one_megabyte():
    assert DEFAULT_EVENTS_MAX_BYTES == 1 * 1024 * 1024


def test_watch_log_rotates_before_append_and_bounds_backups(tmp_path):
    path = tmp_path / "events.jsonl"
    store = WatchLogStore(str(path), max_bytes=160, backup_count=2)

    for index in range(20):
        store.write("test_event", index=index, message="payload")

    rotated = [path, path.with_name("events.jsonl.1"), path.with_name("events.jsonl.2")]
    assert path.exists()
    assert path.with_name("events.jsonl.1").exists()
    assert path.with_name("events.jsonl.2").exists()
    assert not path.with_name("events.jsonl.3").exists()
    assert all(item.stat().st_size <= 160 for item in rotated)
    assert all(record["event"] == "test_event" for item in rotated for record in _records(item))
    assert _records(path)[-1]["index"] == 19


def test_watch_log_keeps_an_oversized_record_intact(tmp_path):
    path = tmp_path / "events.jsonl"
    store = WatchLogStore(str(path), max_bytes=64)

    store.write("large_event", message="x" * 256)

    records = _records(path)
    assert len(records) == 1
    assert records[0]["event"] == "large_event"
    assert records[0]["message"] == "x" * 256
