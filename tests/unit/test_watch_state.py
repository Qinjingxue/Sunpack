import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

import sunpack.filesystem.watcher.journal_commit as watch_journal_module
import sunpack.filesystem.watcher.state as watch_state_module
from sunpack.filesystem.watcher.group_models import WatchGroupState
from sunpack.filesystem.watcher.state import (
    WatchStateJournalError,
    WatchStateStore,
)


def _group_state(tmp_path, name, paths, *, head_path=None, status="done"):
    normalized = [str(path.resolve()) for path in paths]
    selected_head = (paths[0] if head_path is None and paths else head_path)
    return WatchGroupState(
        group_id=f"group-{name}",
        directory=str(tmp_path.resolve()),
        logical_name=name,
        split_family="7z",
        head_path=str(Path(selected_head).resolve()) if selected_head else "",
        input_paths=normalized,
        owned_paths=normalized,
        status=status,
    )


def _candidate(path: Path, index: int = 1):
    return SimpleNamespace(
        path=str(path.resolve()),
        size=1000 + index,
        mtime=1720000000.0 + index,
        file_id=f"file-{index}",
        change_usn=index,
    )


def test_checkpoint_uses_unique_atomic_snapshot_writer(tmp_path, monkeypatch):
    state_path = tmp_path / "state.json"
    state = WatchStateStore(str(state_path))
    state.queue_active(_candidate(tmp_path / "queued.7z"), durable=True)
    temporary_paths = []
    real_replace = watch_state_module.os.replace

    def record_replace(source, destination):
        temporary_paths.append(Path(source))
        real_replace(source, destination)

    monkeypatch.setattr(watch_state_module.os, "replace", record_replace)
    state.save()

    assert len(temporary_paths) == 1
    assert temporary_paths[0].parent == tmp_path
    assert temporary_paths[0].name.endswith(".tmp")
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["version"] == watch_state_module.STATE_VERSION
    assert payload["checkpoint_seq"] == state.applied_seq
    assert not list(tmp_path.glob(".state.json.*.tmp"))


def test_incremental_update_appends_segment_without_replacing_snapshot(tmp_path, monkeypatch):
    state_path = tmp_path / "state.json"
    state = WatchStateStore(str(state_path))
    state.save()
    snapshot_before = state_path.read_text(encoding="utf-8")
    replacements = []
    real_replace = watch_state_module.os.replace

    def record_replace(source, destination):
        replacements.append((source, destination))
        real_replace(source, destination)

    monkeypatch.setattr(watch_state_module.os, "replace", record_replace)
    state.queue_active(_candidate(tmp_path / "queued.7z"), durable=True)

    assert not replacements
    assert state_path.read_text(encoding="utf-8") == snapshot_before
    assert state.journal_path.read_text(encoding="utf-8").endswith("\n")
    [reloaded] = WatchStateStore(str(state_path)).pending_work_items()
    assert reloaded.path == str((tmp_path / "queued.7z").resolve())


def test_failed_journal_append_faults_store(tmp_path, monkeypatch):
    state = WatchStateStore(str(tmp_path / "state.json"))
    state.save()

    def fail_open(*_args, **_kwargs):
        raise OSError("journal unavailable")

    monkeypatch.setattr(watch_journal_module, "open_service_file", fail_open)

    with pytest.raises(OSError, match="journal unavailable"):
        state.queue_active(_candidate(tmp_path / "queued.7z"), durable=True)
    with pytest.raises(RuntimeError, match="persistence is unavailable"):
        state.queue_active(_candidate(tmp_path / "second.7z"), durable=True)


def test_truncated_segment_tail_is_ignored_and_recovered(tmp_path):
    state_path = tmp_path / "state.json"
    first = _candidate(tmp_path / "first.7z", 1)
    state = WatchStateStore(str(state_path))
    state.queue_active(first, durable=True)
    damaged_segment = state.journal_path
    with open(damaged_segment, "ab") as handle:
        handle.write(b'{"version":17,"seq":2,"operations":[')

    recovered = WatchStateStore(str(state_path))
    assert [item.path for item in recovered.pending_work_items()] == [first.path]
    assert recovered.applied_seq == 1


def test_corrupt_complete_journal_record_is_reported(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    state.queue_active(_candidate(tmp_path / "queued.7z"), durable=True)
    with open(state.journal_path, "ab") as handle:
        handle.write(b"{not-json}\n")

    with pytest.raises(WatchStateJournalError, match="corrupt watch state journal"):
        WatchStateStore(str(state.path))


def test_duplicate_sequence_is_rejected(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "failed.7z"
    state = WatchStateStore(str(state_path))
    state.mark(
        str(archive),
        10,
        20.0,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    journal = state.journal_path.read_bytes()
    with open(state.journal_path, "ab") as handle:
        handle.write(journal)

    with pytest.raises(WatchStateJournalError, match="non-contiguous watch state sequence"):
        WatchStateStore(str(state_path))


def test_failed_snapshot_publish_keeps_sealed_journal_recoverable(tmp_path, monkeypatch):
    state_path = tmp_path / "state.json"
    candidate = _candidate(tmp_path / "queued.7z")
    state = WatchStateStore(str(state_path))
    state.queue_active(candidate, durable=True)
    real_replace = watch_state_module.os.replace
    failed = False

    def fail_snapshot_replace(source, destination):
        nonlocal failed
        if Path(destination) == state.path and not failed:
            failed = True
            raise OSError("failed snapshot replace")
        real_replace(source, destination)

    monkeypatch.setattr(watch_state_module.os, "replace", fail_snapshot_replace)
    with pytest.raises(OSError, match="failed snapshot replace"):
        state.save()
    monkeypatch.setattr(watch_state_module.os, "replace", real_replace)

    [recovered] = WatchStateStore(str(state_path)).pending_work_items()
    assert recovered.path == candidate.path


def test_checkpoint_does_not_block_state_progress(tmp_path, monkeypatch):
    state = WatchStateStore(
        str(tmp_path / "state.json"),
        compact_records=1,
        compact_bytes=1024 * 1024 * 1024,
    )
    entered = Event()
    release = Event()
    real_write = state._write_snapshot_view

    def slow_snapshot(view):
        entered.set()
        assert release.wait(5)
        real_write(view)

    monkeypatch.setattr(state, "_write_snapshot_view", slow_snapshot)
    first = _candidate(tmp_path / "first.7z", 1)
    second = _candidate(tmp_path / "second.7z", 2)
    state.queue_active(first, durable=True)
    assert entered.wait(2)

    started = time.perf_counter()
    state.queue_active(second, durable=True)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0

    release.set()
    state.save()
    recovered = WatchStateStore(str(state.path))
    assert {item.path for item in recovered.pending_work_items()} == {
        first.path,
        second.path,
    }


def test_hard_limit_never_runs_snapshot_on_mutation_thread(tmp_path, monkeypatch):
    state = WatchStateStore(
        str(tmp_path / "state.json"),
        compact_records=1_000_000,
        compact_bytes=1,
        hard_compact_bytes=1,
    )
    checkpoint_thread_ids = []
    caller_thread_id = watch_state_module.threading.get_ident()
    real_write = state._write_snapshot_view

    def record_snapshot_thread(view):
        checkpoint_thread_ids.append(watch_state_module.threading.get_ident())
        real_write(view)

    monkeypatch.setattr(state, "_write_snapshot_view", record_snapshot_thread)
    state.queue_active(_candidate(tmp_path / "queued.7z"), durable=True)
    state.save()

    assert checkpoint_thread_ids
    assert all(thread_id != caller_thread_id for thread_id in checkpoint_thread_ids)
    assert WatchStateStore(str(state.path)).pending_work_items()


def test_previous_state_schema_is_discarded_without_migration(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps({"version": 16, "pending_work": {"legacy": {"path": "legacy"}}}),
        encoding="utf-8",
    )
    legacy_journal = state_path.with_name("state.journal.jsonl")
    legacy_journal.write_text('{"version":16,"operations":[]}\n', encoding="utf-8")

    state = WatchStateStore(str(state_path))

    assert not state.pending_work_items()
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["version"] == watch_state_module.STATE_VERSION
    assert payload["checkpoint_seq"] == 0
    assert not legacy_journal.exists()


def test_concurrent_updates_share_one_ordered_sequence(tmp_path):
    state_path = tmp_path / "state.json"
    state = WatchStateStore(str(state_path))
    candidates = [_candidate(tmp_path / f"queued-{index}.7z", index) for index in range(100)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(state.queue_active, candidates))
    state.flush()

    reloaded = WatchStateStore(str(state_path))
    assert reloaded.applied_seq == 100
    assert {item.path for item in reloaded.pending_work_items()} == {
        candidate.path for candidate in candidates
    }


def test_independent_state_stores_append_without_losing_transactions(tmp_path):
    state_path = tmp_path / "state.json"
    stores = [WatchStateStore(str(state_path)), WatchStateStore(str(state_path))]
    candidates = [
        _candidate(tmp_path / "first.7z", 1),
        _candidate(tmp_path / "second.7z", 2),
    ]

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(lambda pair: pair[0].queue_active(pair[1]), zip(stores, candidates)))
    stores[0].flush()

    assert {item.path for item in WatchStateStore(str(state_path)).pending_work_items()} == {
        candidate.path for candidate in candidates
    }


def test_completed_work_is_not_retained_as_processed_history(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))

    state.record_attempt(str(archive), stat.st_size, stat.st_mtime, "device:inode")
    assert state.pending_work
    state.complete_work([str(archive)])
    state.save()

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert not WatchStateStore(str(state_path)).pending_work_items()
    assert "snapshots" not in payload
    assert "pending_work" in payload


def test_pending_work_survives_restart_until_completed(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))
    state.record_attempt(str(archive), stat.st_size, stat.st_mtime, "device:inode")
    state.flush()

    reloaded = WatchStateStore(str(state_path))
    assert [item.path for item in reloaded.pending_work_items()] == [str(archive.resolve())]

    reloaded.complete_work([str(archive)])
    reloaded.flush()
    assert not WatchStateStore(str(state_path)).pending_work_items()


def test_only_retry_blocking_failures_are_kept_as_entries(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state.mark(
        str(archive),
        stat.st_size,
        stat.st_mtime,
        status="failed_password",
        failure_payload={"kind": "wrong_password", "blockers": ["password"]},
    )
    assert state.latest_entry_for_path(str(archive)).status == "failed_password"

    state.mark(str(archive), stat.st_size, stat.st_mtime, status="done")
    assert state.latest_entry_for_path(str(archive)) is None


def test_metadata_observation_advances_retry_entry_without_changing_failure(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    state = WatchStateStore(str(state_path))
    state.mark(
        str(archive),
        archive.stat().st_size,
        100.0,
        file_id="file",
        change_usn=10,
        status="failed_password",
        error="password",
        failure_payload={"kind": "wrong_password", "blockers": ["password"]},
    )
    candidate = type("Candidate", (), {
        "path": str(archive),
        "size": archive.stat().st_size,
        "mtime": 50.0,
        "file_id": "file",
        "change_usn": 11,
    })()

    assert state.advance_entry_observation(candidate)
    state.flush()

    entry = WatchStateStore(str(state_path)).latest_entry_for_path(str(archive))
    assert entry is not None
    assert entry.mtime == 50.0
    assert entry.change_usn == 11
    assert entry.status == "failed_password"
    assert entry.last_error == "password"
    assert entry.attempt_count == 1


def test_active_work_persists_force_cause_for_restart(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"active")
    state = WatchStateStore(str(state_path))
    candidate = type("Candidate", (), {
        "path": str(archive),
        "size": archive.stat().st_size,
        "mtime": archive.stat().st_mtime,
    })()
    state.queue_active(candidate, force=True)
    state.flush()

    [pending] = WatchStateStore(str(state_path)).pending_work_items()
    assert pending.path == str(archive.resolve())
    assert pending.force is True


def test_prune_missing_records_removes_stale_entries_and_groups(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    present = tmp_path / "present.zip"
    partial_present = tmp_path / "partial.7z.001"
    missing = tmp_path / "missing.zip"
    present.write_bytes(b"present")
    partial_present.write_bytes(b"partial")

    state.mark(
        str(present),
        present.stat().st_size,
        present.stat().st_mtime,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    state.mark(
        str(missing),
        1,
        1.0,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    state.groups["present"] = _group_state(tmp_path, "present", [present])
    state.groups["missing"] = _group_state(tmp_path, "missing", [missing])
    state.groups["partial"] = _group_state(tmp_path, "partial", [partial_present, missing])

    removed_entries, removed_groups = state.prune_missing_records()

    assert (removed_entries, removed_groups) == (1, 2)
    assert state.latest_entry_for_path(str(present)) is not None
    assert state.latest_entry_for_path(str(missing)) is None
    assert set(state.groups) == {"present"}


def test_prune_missing_records_keeps_group_with_missing_expected_volume(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    first = tmp_path / "split.7z.001"
    third = tmp_path / "split.7z.003"
    first.write_bytes(b"first")
    third.write_bytes(b"third")
    group = _group_state(tmp_path, "split", [first, third], status="waiting")
    group.missing_indices = [2]
    state.groups[group.group_id] = group
    missing_head_member = tmp_path / "head-missing.7z.002"
    missing_head_member.write_bytes(b"member")
    missing_head_group = _group_state(
        tmp_path,
        "head-missing",
        [missing_head_member],
        head_path="",
        status="waiting",
    )
    missing_head_group.missing_indices = [1]
    state.groups[missing_head_group.group_id] = missing_head_group

    removed_entries, removed_groups = state.prune_missing_records()

    assert (removed_entries, removed_groups) == (0, 0)
    assert state.group_state(group.group_id) is not None
    assert state.group_state(missing_head_group.group_id) is not None


def test_prune_missing_records_retains_records_when_presence_is_unknown(tmp_path, monkeypatch):
    state = WatchStateStore(str(tmp_path / "state.json"))
    archive = tmp_path / "protected.zip"
    archive.write_bytes(b"archive")
    state.mark(
        str(archive),
        archive.stat().st_size,
        archive.stat().st_mtime,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    original_stat = watch_state_module.os.stat

    def blocked_stat(path, *args, **kwargs):
        if str(path).casefold() == str(archive).casefold():
            raise PermissionError("temporary access failure")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(watch_state_module.os, "stat", blocked_stat)

    assert state.prune_missing_records() == (0, 0)
    assert state.latest_entry_for_path(str(archive)) is not None


def test_native_checkpoint_round_trips_nested_unicode_payload(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "雪-special.zip"
    state = WatchStateStore(str(state_path))
    state.mark(
        str(archive),
        123,
        45.5,
        file_id="id-雪",
        change_usn=99,
        status="failed_password",
        error="bad\n\"password\\雪",
        failure_payload={
            "kind": "password",
            "blockers": ["password"],
            "nested": {
                "unicode": "雪☃",
                "escaped": "line1\nline2\t\\\"",
                "values": [True, False, None, 1, -2, 3.25],
                "tuple": ("a", "b"),
            },
        },
    )
    state.watch_cursors = {
        "volume:雪": {"journal_id": 2**63 + 17, "next_usn": 2**63 + 19}
    }
    state.groups["group-雪"] = WatchGroupState(
        group_id="group-雪",
        directory=str(tmp_path),
        logical_name="archive-雪",
        split_family="7z",
        head_path=str(archive),
        input_paths=[str(archive)],
        owned_paths=[str(archive)],
        status="suspended",
        blockers=["missing_volume"],
        failure_payload={"message": "缺少分卷", "indices": [2, 3]},
        updated_at=12.0,
    )
    state.save()

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    entry = next(iter(payload["entries"].values()))
    assert payload["version"] == watch_state_module.STATE_VERSION
    assert payload["watch_cursors"]["volume:雪"]["journal_id"] == 2**63 + 17
    assert entry["last_error"] == "bad\n\"password\\雪"
    assert entry["failure_payload"]["nested"]["unicode"] == "雪☃"
    assert entry["failure_payload"]["nested"]["tuple"] == ["a", "b"]
    assert payload["groups"]["group-雪"]["failure_payload"]["message"] == "缺少分卷"

    reloaded = WatchStateStore(str(state_path))
    assert reloaded.latest_entry_for_path(str(archive)).failure_payload["nested"]["escaped"] == "line1\nline2\t\\\""
    assert reloaded.watch_cursor("volume:雪")["next_usn"] == 2**63 + 19
