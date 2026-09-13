import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from types import SimpleNamespace

import pytest

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


def test_independent_state_stores_use_unique_atomic_writers(tmp_path, monkeypatch):
    state_path = tmp_path / "state.json"
    stores = [WatchStateStore(str(state_path)), WatchStateStore(str(state_path))]
    replace_lock = Lock()
    temporary_paths = []
    active_replaces = 0
    max_active_replaces = 0
    real_replace = watch_state_module.os.replace

    def synchronized_replace(source, destination):
        nonlocal active_replaces, max_active_replaces
        with replace_lock:
            temporary_paths.append(source)
            active_replaces += 1
            max_active_replaces = max(max_active_replaces, active_replaces)
        time.sleep(0.01)
        try:
            real_replace(source, destination)
        finally:
            with replace_lock:
                active_replaces -= 1

    monkeypatch.setattr(watch_state_module.os, "replace", synchronized_replace)

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        list(executor.map(lambda store: store.save(), stores))

    assert len(set(temporary_paths)) == len(stores) * 2
    assert all(path.parent == tmp_path and path.name.endswith(".tmp") for path in temporary_paths)
    assert max_active_replaces == 1
    assert json.loads(state_path.read_text(encoding="utf-8"))["version"] > 0
    assert not list(tmp_path.glob(".state.json.*.tmp"))
    assert not list(tmp_path.glob(".state.journal.jsonl.*.tmp"))


def test_incremental_update_appends_journal_without_replacing_snapshot(tmp_path, monkeypatch):
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
    state.queue_active(_candidate(tmp_path / "queued.7z"))

    assert not replacements
    assert state_path.read_text(encoding="utf-8") == snapshot_before
    assert state.journal_path.read_text(encoding="utf-8").endswith("\n")
    [reloaded] = WatchStateStore(str(state_path)).pending_work_items()
    assert reloaded.path == str((tmp_path / "queued.7z").resolve())


def test_failed_journal_append_does_not_change_memory(tmp_path, monkeypatch):
    state = WatchStateStore(str(tmp_path / "state.json"))
    state.save()

    def fail_open(*_args, **_kwargs):
        raise OSError("journal unavailable")

    monkeypatch.setattr(watch_state_module, "open_service_file", fail_open)

    with pytest.raises(OSError, match="journal unavailable"):
        state.queue_active(_candidate(tmp_path / "queued.7z"))
    assert not state.pending_work_items()


def test_truncated_journal_tail_is_ignored_and_recovered(tmp_path):
    state_path = tmp_path / "state.json"
    first = _candidate(tmp_path / "first.7z", 1)
    second = _candidate(tmp_path / "second.7z", 2)
    state = WatchStateStore(str(state_path))
    state.queue_active(first)
    with open(state.journal_path, "ab") as handle:
        handle.write(b'{"version":14,"operations":[')

    recovered = WatchStateStore(str(state_path))
    assert [item.path for item in recovered.pending_work_items()] == [first.path]
    assert recovered.journal_path.read_bytes().endswith(b"\n")

    recovered.queue_active(second)
    assert {item.path for item in WatchStateStore(str(state_path)).pending_work_items()} == {
        first.path,
        second.path,
    }


def test_corrupt_complete_journal_record_is_reported(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    state.queue_active(_candidate(tmp_path / "queued.7z"))
    with open(state.journal_path, "ab") as handle:
        handle.write(b"{not-json}\n")

    with pytest.raises(WatchStateJournalError, match="corrupt watch state journal"):
        WatchStateStore(str(state.path))


def test_duplicate_journal_replay_is_idempotent(tmp_path):
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

    entry = WatchStateStore(str(state_path)).latest_entry_for_path(str(archive))
    assert entry is not None
    assert entry.attempt_count == 1


@pytest.mark.parametrize("failed_target", ["snapshot", "journal"])
def test_compaction_crash_windows_recover_all_state(tmp_path, monkeypatch, failed_target):
    state_path = tmp_path / "state.json"
    candidate = _candidate(tmp_path / "queued.7z")
    state = WatchStateStore(str(state_path))
    state.queue_active(candidate)
    real_replace = watch_state_module.os.replace
    failed = False

    def fail_one_replace(source, destination):
        nonlocal failed
        target = Path(destination)
        should_fail = (
            target == state.path
            if failed_target == "snapshot"
            else target == state.journal_path
        )
        if should_fail and not failed:
            failed = True
            raise OSError(f"failed {failed_target} replace")
        real_replace(source, destination)

    monkeypatch.setattr(watch_state_module.os, "replace", fail_one_replace)
    with pytest.raises(OSError, match=f"failed {failed_target} replace"):
        state.save()
    monkeypatch.setattr(watch_state_module.os, "replace", real_replace)

    [recovered] = WatchStateStore(str(state_path)).pending_work_items()
    assert recovered.path == candidate.path


def test_soft_threshold_compacts_only_when_requested(tmp_path):
    state = WatchStateStore(
        str(tmp_path / "state.json"),
        compact_records=1,
        compact_bytes=1024 * 1024,
        hard_compact_bytes=2 * 1024 * 1024,
    )
    state.queue_active(_candidate(tmp_path / "queued.7z"))

    assert state.compaction_due
    assert state.journal_path.stat().st_size > 0
    assert state.compact_if_needed()
    assert state.journal_path.stat().st_size == 0
    assert not state.compaction_due
    assert WatchStateStore(str(state.path)).pending_work_items()


def test_hard_journal_limit_compacts_synchronously(tmp_path):
    state = WatchStateStore(
        str(tmp_path / "state.json"),
        compact_records=1_000_000,
        compact_bytes=1,
        hard_compact_bytes=1,
    )
    state.queue_active(_candidate(tmp_path / "queued.7z"))

    assert state.journal_path.stat().st_size == 0
    assert not state.compaction_due
    assert WatchStateStore(str(state.path)).pending_work_items()


def test_incompatible_journal_is_discarded_without_migration(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    state.save()
    state.journal_path.write_text(
        json.dumps({"version": 13, "operations": [{"op": "delete"}]}) + "\n",
        encoding="utf-8",
    )

    reloaded = WatchStateStore(str(state.path))

    assert not reloaded.pending_work_items()
    assert reloaded.journal_path.stat().st_size == 0
    assert json.loads(reloaded.path.read_text(encoding="utf-8"))["version"] == watch_state_module.STATE_VERSION


def test_concurrent_updates_share_one_ordered_journal(tmp_path):
    state_path = tmp_path / "state.json"
    state = WatchStateStore(str(state_path))
    candidates = [_candidate(tmp_path / f"queued-{index}.7z", index) for index in range(100)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(state.queue_active, candidates))

    reloaded = WatchStateStore(str(state_path))
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

    reloaded = WatchStateStore(str(state_path))
    assert [item.path for item in reloaded.pending_work_items()] == [str(archive.resolve())]

    reloaded.complete_work([str(archive)])
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

    entry = WatchStateStore(str(state_path)).latest_entry_for_path(str(archive))
    assert entry is not None
    assert entry.mtime == 50.0
    assert entry.change_usn == 11
    assert entry.status == "failed_password"
    assert entry.last_error == "password"
    assert entry.attempt_count == 1


def test_previous_state_schema_is_intentionally_not_loaded(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"version": 5, "entries": {"legacy": {"status": "done"}}}), encoding="utf-8")

    state = WatchStateStore(str(state_path))

    assert not state.pending_work
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["version"] == watch_state_module.STATE_VERSION
    assert "snapshots" not in payload


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
