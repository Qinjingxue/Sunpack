import os
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from tests.helpers.binary_wal import header, frame, frames
import sunpack.runtime.watch.state as watch_state_module
from sunpack.runtime.watch.state import (
    WatchStateJournalError,
    WatchStateStore,
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
    state_path = tmp_path / "state.snapshot"
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
    from sunpack_native import NativeWatchState
    assert NativeWatchState().load_snapshot(str(state_path)) == state.applied_seq
    assert not list(tmp_path.glob(".state.snapshot.*.tmp"))


def test_incremental_update_appends_segment_without_replacing_snapshot(tmp_path, monkeypatch):
    state_path = tmp_path / "state.snapshot"
    state = WatchStateStore(str(state_path))
    state.save()
    snapshot_before = state_path.read_bytes()
    replacements = []
    real_replace = watch_state_module.os.replace

    def record_replace(source, destination):
        replacements.append((source, destination))
        real_replace(source, destination)

    monkeypatch.setattr(watch_state_module.os, "replace", record_replace)
    state.queue_active(_candidate(tmp_path / "queued.7z"), durable=True)

    assert not replacements
    assert state_path.read_bytes() == snapshot_before
    [transaction] = frames(state.journal_path)
    assert transaction[0] == state.applied_seq
    [reloaded] = WatchStateStore(str(state_path)).pending_work_items()
    assert reloaded.path == str((tmp_path / "queued.7z").resolve())


def test_failed_journal_append_faults_store(tmp_path):
    from sunpack_native import watch_journal_request_flush
    from sunpack.runtime.watch.journal_commit import journal_stats

    state = WatchStateStore(str(tmp_path / "state.snapshot"))
    state.save()
    # Force native OpenOptions(file) to fail without relying on Python internals.
    journal_path = state.journal_path
    journal_path.mkdir()

    with pytest.raises(RuntimeError, match="native Watch journal append failed"):
        state.queue_active(_candidate(tmp_path / "queued.7z"), durable=True)
    with pytest.raises(RuntimeError, match="persistence is unavailable"):
        state.queue_active(_candidate(tmp_path / "second.7z"), durable=True)
    ticket = watch_journal_request_flush(state._writer_stream, state.applied_seq)
    with pytest.raises(RuntimeError, match="native Watch journal append failed"):
        state.close()
    assert not journal_stats(state._writer_stream)["registered"]

    # Normal-owner tests cannot cover error retirement: old tickets must keep
    # the error while a new store can write to the same path successfully.
    journal_path.rmdir()
    reopened = WatchStateStore(str(state.path))
    reopened.queue_active(_candidate(tmp_path / "reopened.7z"), durable=True)
    with pytest.raises(RuntimeError, match="native Watch journal append failed"):
        ticket.wait()
    reopened.close()


def test_truncated_segment_tail_is_ignored_and_recovered(tmp_path):
    state_path = tmp_path / "state.snapshot"
    first = _candidate(tmp_path / "first.7z", 1)
    state = WatchStateStore(str(state_path))
    state.queue_active(first, durable=True)
    damaged_segment = state.journal_path
    with open(damaged_segment, "ab") as handle:
        handle.write(frame(2, b"\x91\x92\x00")[:-1])

    recovered = WatchStateStore(str(state_path))
    assert [item.path for item in recovered.pending_work_items()] == [first.path]
    assert recovered.applied_seq == 1


def test_repeated_store_reopen_reuses_one_wal_segment(tmp_path):
    state_path = tmp_path / "state.snapshot"
    segments = set()
    for index in range(16):
        store = WatchStateStore(str(state_path))
        store.queue_active(_candidate(tmp_path / f"queued-{index}.7z", index + 1), durable=True)
        segments.add(store.journal_path)
        store.close()

    assert len(segments) == 1
    assert len(list(tmp_path.glob("state.journal.*.wal"))) == 1
    recovered = WatchStateStore(str(state_path))
    assert recovered.applied_seq == 16
    assert recovered.pending_work_count == 16
    recovered.close()


def test_checkpoint_rotation_still_starts_a_new_wal_segment(tmp_path):
    state_path = tmp_path / "state.snapshot"
    first = WatchStateStore(str(state_path))
    first.queue_active(_candidate(tmp_path / "first.7z"), durable=True)
    original_segment = first.journal_path
    first.save()
    first.close()

    second = WatchStateStore(str(state_path))
    assert second.journal_path != original_segment
    second.queue_active(_candidate(tmp_path / "second.7z", 2), durable=True)
    rotated_segment = second.journal_path
    second.close()

    reopened = WatchStateStore(str(state_path))
    assert reopened.journal_path == rotated_segment
    assert reopened.applied_seq == 2
    reopened.close()


@pytest.mark.parametrize("retry_at", ["idle", "startup"])
def test_covered_wal_retirement_retries_without_rewriting_snapshot(tmp_path, monkeypatch, retry_at):
    # Normal checkpoint tests never fail unlink: this catches lost retry state,
    # needless snapshot rewrites, and deletion of a concurrently appended WAL.
    # Three durable records keep this independent failure coverage inexpensive.
    state_path = tmp_path / "state.snapshot"
    state = WatchStateStore(str(state_path))
    candidates = [_candidate(tmp_path / f"{index}.bin", index + 1) for index in range(3)]
    state.queue_active(candidates[0], durable=True)
    covered = state.journal_path
    real_unlink = Path.unlink
    allow_removal = False
    append_during_retirement = False

    def unlink(path, *args, **kwargs):
        nonlocal append_during_retirement
        if path == covered:
            if not allow_removal:
                raise PermissionError("simulated sharing violation")
            if append_during_retirement:
                append_during_retirement = False
                state.queue_active(candidates[2], durable=True)
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unlink)
    state.save()
    with state._checkpoint_condition:
        assert state._checkpoint_condition.wait_for(lambda: not state._checkpoint_running, timeout=2)
    assert covered.exists()
    state.queue_active(candidates[1], durable=True)
    active = state.journal_path
    snapshot = state_path.read_bytes()
    assert not state.compaction_due
    allow_removal = True
    if retry_at == "idle":
        append_during_retirement = True
        assert state.compact_if_needed()
        with state._checkpoint_condition:
            assert state._checkpoint_condition.wait_for(lambda: not state._checkpoint_running, timeout=2)
        state.close()
    else:
        state.close()
    recovered = WatchStateStore(str(state_path))
    try:
        assert not covered.exists()
        assert active.exists()
        assert state_path.read_bytes() == snapshot
        expected = candidates if retry_at == "idle" else candidates[:2]
        assert {item.path for item in recovered.pending_work_items()} == {item.path for item in expected}
        assert not recovered.compact_if_needed()
    finally:
        recovered.close()


def test_startup_retirement_preserves_sealed_segment_with_uncovered_suffix(tmp_path, monkeypatch):
    # A filename's starting USN cannot prove its whole segment is redundant.
    # Existing recovery tests lack a segment straddling the snapshot boundary.
    # One three-record recovery fixture covers that data-loss risk cheaply.
    state_path = tmp_path / "state.snapshot"
    state = WatchStateStore(str(state_path))
    candidates = [_candidate(tmp_path / f"{index}.bin", index + 1) for index in range(3)]
    state.queue_active(candidates[0], durable=True)
    older = state.journal_path
    real_unlink = Path.unlink
    with monkeypatch.context() as patch:
        def blocked_unlink(path, *args, **kwargs):
            if path == older:
                raise PermissionError("simulated sharing violation")
            return real_unlink(path, *args, **kwargs)
        patch.setattr(Path, "unlink", blocked_unlink)
        state.save()
        state.queue_active(candidates[1], durable=True)
        state.queue_active(candidates[2], durable=True)
        newer = state.journal_path
        state.close()
    (_, _, second), (_, _, third) = frames(newer)
    older.write_bytes(older.read_bytes() + second)
    newest = state._segment_path(3)
    newest.write_bytes(header() + third)
    newer.unlink()
    recovered = WatchStateStore(str(state_path))
    try:
        assert older.exists() and newest.exists()
        assert {item.path for item in recovered.pending_work_items()} == {item.path for item in candidates}
        assert not recovered.compact_if_needed()
    finally:
        recovered.close()


@pytest.mark.parametrize("has_valid_record", [False, True])
def test_reopen_repairs_torn_tail_before_appending(tmp_path, has_valid_record):
    state_path = tmp_path / "state.snapshot"
    first = WatchStateStore(str(state_path))
    if has_valid_record:
        first.queue_active(_candidate(tmp_path / "first.7z"), durable=True)
    segment = first.journal_path
    first.close()
    with open(segment, "ab") as handle:
        handle.write(frame(999, b"\x91\x92\x00")[:-1] if has_valid_record else header()[:7])

    reopened = WatchStateStore(str(state_path))
    assert reopened.journal_path == segment
    reopened.queue_active(_candidate(tmp_path / "second.7z", 2), durable=True)
    reopened.close()

    assert [seq for seq, _, _ in frames(segment)] == ([1, 2] if has_valid_record else [1])
    assert len(list(tmp_path.glob("state.journal.*.wal"))) == 1
    recovered = WatchStateStore(str(state_path))
    assert recovered.applied_seq == (2 if has_valid_record else 1)
    assert {item.path for item in recovered.pending_work_items()} == {
        str((tmp_path / name).resolve())
        for name in (("first.7z", "second.7z") if has_valid_record else ("second.7z",))
    }
    recovered.close()


def test_corrupt_complete_journal_record_is_reported(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.snapshot"))
    state.queue_active(_candidate(tmp_path / "queued.7z"), durable=True)
    with open(state.journal_path, "ab") as handle:
        handle.write(frame(2, b"\x91")[:-1] + b"\x90")

    with pytest.raises(WatchStateJournalError, match="corrupt watch state journal"):
        WatchStateStore(str(state.path))


def test_snapshot_missing_required_field_is_rejected(tmp_path):
    from sunpack.runtime.watch.journal_commit import journal_stats

    state_path = tmp_path / "state.snapshot"
    state_path.write_bytes(header(3))

    with pytest.raises(WatchStateJournalError, match="corrupt watch state snapshot") as error:
        WatchStateStore(str(state_path))
    # Retaining the startup exception/traceback must not retain native ownership.
    assert error.value.__traceback__ is not None
    assert not journal_stats(watch_state_module._state_path_key(state_path))["registered"]


def test_journal_operation_with_unexpected_field_is_rejected(tmp_path):
    state_path = tmp_path / "state.snapshot"
    state = WatchStateStore(str(state_path))
    state.save()
    # Valid envelope + invalid typed opcode, so CRC validation alone cannot pass it.
    state.journal_path.write_bytes(header() + frame(1, b"\x91\x92\xcc\xff\xa1x"))

    with pytest.raises(WatchStateJournalError, match="invalid watch state operation"):
        WatchStateStore(str(state_path))


def test_duplicate_sequence_is_rejected(tmp_path):
    state_path = tmp_path / "state.snapshot"
    archive = tmp_path / "failed.7z"
    archive.touch()
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
        handle.write(journal[16:])

    with pytest.raises(WatchStateJournalError, match="non-contiguous watch state sequence"):
        WatchStateStore(str(state_path))


def test_failed_snapshot_publish_keeps_sealed_journal_recoverable(tmp_path, monkeypatch):
    state_path = tmp_path / "state.snapshot"
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
        str(tmp_path / "state.snapshot"),
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


def test_close_waits_for_existing_checkpoint_before_releasing_stream(tmp_path, monkeypatch):
    from sunpack.runtime.watch.journal_commit import journal_stats

    state = WatchStateStore(str(tmp_path / "state.snapshot"), compact_records=1)
    entered, release = Event(), Event()
    real_write = state._write_snapshot_view

    def paused_snapshot(view):
        entered.set()
        assert release.wait(5)
        real_write(view)

    monkeypatch.setattr(state, "_write_snapshot_view", paused_snapshot)
    candidate = _candidate(tmp_path / "queued.7z")
    state.queue_active(candidate, durable=False)
    assert entered.wait(2)
    with ThreadPoolExecutor(max_workers=1) as executor:
        closing = executor.submit(state.close)
        try:
            with pytest.raises(FutureTimeoutError):
                closing.result(timeout=0.05)
            assert journal_stats(state._writer_stream)["registered"]
        finally:
            release.set()
        closing.result(timeout=2)
    assert not journal_stats(state._writer_stream)["registered"]
    with pytest.raises(RuntimeError, match="closed"):
        state.queue_active(_candidate(tmp_path / "late.7z"))
    recovered = WatchStateStore(str(state.path))
    assert recovered.pending_work_for_path(candidate.path) is not None
    recovered.close()


def test_hard_limit_never_runs_snapshot_on_mutation_thread(tmp_path, monkeypatch):
    state = WatchStateStore(
        str(tmp_path / "state.snapshot"),
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


@pytest.mark.parametrize("reload_during_checkpoint", [False, True])
def test_state_handoff_preserves_newer_checkpoint(tmp_path, monkeypatch, reload_during_checkpoint):
    state_path = tmp_path / "state.snapshot"
    first = _candidate(tmp_path / "first.7z", 1)
    second = _candidate(tmp_path / "second.7z", 2)
    old = WatchStateStore(str(state_path))
    old.queue_active(first, durable=True)
    successor = None if reload_during_checkpoint else WatchStateStore(str(state_path))
    entered, release, handoff = Event(), Event(), Event()
    # Patching the instance restores a bound method on undo, keeping the store
    # and its path coordinator alive after pytest removes/reuses the directory.
    real_write = WatchStateStore._write_snapshot_view

    def paused_snapshot(store, view):
        if store is old:
            entered.set()
            assert release.wait(5)
        real_write(store, view)

    def replace_store():
        handoff.set()
        current = successor or WatchStateStore(str(state_path))
        current.queue_active(second, durable=True)
        current.save()
        return current.applied_seq

    monkeypatch.setattr(WatchStateStore, "_write_snapshot_view", paused_snapshot)
    old.compact_if_needed(force=True)
    assert entered.wait(2)
    with ThreadPoolExecutor(max_workers=1) as executor:
        replacement = executor.submit(replace_store)
        try:
            assert handoff.wait(2)
            # Handoff must not finish while the prior publisher still owns
            # the snapshot and the journal segments it is about to retire.
            with pytest.raises(FutureTimeoutError):
                replacement.result(timeout=0.05)
        finally:
            release.set()
            with old._checkpoint_condition:
                assert old._checkpoint_condition.wait_for(lambda: not old._checkpoint_running, timeout=2)
        latest_seq = replacement.result(timeout=2)

    recovered = WatchStateStore(str(state_path))
    assert recovered.applied_seq == latest_seq
    assert {item.path for item in recovered.pending_work_items()} == {first.path, second.path}



def test_concurrent_updates_share_one_ordered_sequence(tmp_path):
    state_path = tmp_path / "state.snapshot"
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
    state_path = tmp_path / "state.snapshot"
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
    state_path = tmp_path / "state.snapshot"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))

    state.record_attempt(str(archive), stat.st_size, stat.st_mtime, "device:inode")
    assert state.pending_work
    state.complete_work([str(archive)])
    state.save()

    restored = WatchStateStore(str(state_path))
    assert not restored.pending_work_items()
    assert restored.entry_count == 0


def test_pending_work_survives_restart_until_completed(tmp_path):
    state_path = tmp_path / "state.snapshot"
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
    state = WatchStateStore(str(tmp_path / "state.snapshot"))
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
    state_path = tmp_path / "state.snapshot"
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
    state_path = tmp_path / "state.snapshot"
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


def test_prune_missing_records_scopes_stale_entries_without_removing_recovery(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.snapshot"))
    directory = tmp_path / "group"
    directory.mkdir()
    present = directory / "present.zip"
    missing = directory / "missing.zip"
    committed = directory / "committed.zip"
    unrelated = tmp_path / "unrelated.zip"
    present.write_bytes(b"present")
    missing.touch()
    committed.touch()
    unrelated.touch()

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
    state.mark(str(unrelated), 1, 1.0, status="failed_password")
    state.queue_active(_candidate(missing), durable_owner=True, persist=True, durable=True)
    state.record_task_output_started(str(missing), str(missing), str(tmp_path / "partial-output"))
    state.mark(str(committed), 1, 1.0, status="suspended_missing_volume")
    state.queue_active(_candidate(committed), durable_owner=True, persist=True, durable=True)
    output = str(tmp_path / "committed-output")
    state.record_task_output_started(str(committed), str(committed), output)
    state.record_task_output_finished(str(committed), str(committed), output, keep_output=True)

    missing.unlink()
    committed.unlink()
    unrelated.unlink()
    removed_entries = state.prune_missing_records(str(directory), recursive=True)

    assert removed_entries == 2
    assert state.latest_entry_for_path(str(present)) is not None
    assert state.latest_entry_for_path(str(missing)) is None
    assert state.latest_entry_for_path(str(unrelated)) is not None
    assert not state.forget_path(str(directory), recursive=True, missing_only=True)
    assert state.pending_work_for_path(str(missing)).active_outputs
    assert state.pending_work_for_path(str(committed)).committed_roots == [output]
    assert state.prune_missing_records() == 1


def test_prune_missing_records_retains_records_when_presence_is_unknown(tmp_path, monkeypatch):
    state = WatchStateStore(str(tmp_path / "state.snapshot"))
    archive = tmp_path / "protected.zip"
    archive.write_bytes(b"archive")
    state.mark(
        str(archive),
        archive.stat().st_size,
        archive.stat().st_mtime,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    archive.unlink()
    monkeypatch.setattr(watch_state_module, "_recorded_file_presence", lambda _path: None)

    assert state.prune_missing_records() == 0
    assert state.latest_entry_for_path(str(archive)) is not None
    assert state.mark(str(archive), 1, 1.0, status="failed_password")


def test_pruning_shares_root_checks_but_revalidates_each_batch_before_deleting(tmp_path, monkeypatch):
    """Single-entry outage tests miss repeated IO and loss during a batch.

    Removing this leaves both faults uncovered. One small batch verifies offline
    skipping, mid-batch outage, and a later successful cleanup without timing waits.
    """
    from sunpack.core.contracts.discovery_scope import DiscoveryScope
    root, hidden = tmp_path / "input", tmp_path / "offline"
    root.mkdir()
    state = WatchStateStore(str(tmp_path / "state.snapshot"), scopes=(DiscoveryScope(str(root)),))
    for index in range(64):
        source = root / f"part.{index:03d}"
        source.touch()
        state.mark(str(source), 0, 1.0, status="suspended_missing_volume")
        source.unlink()
    presence, isdir = watch_state_module._recorded_file_presence, os.path.isdir
    checked_files, checked_roots = [], []
    interrupt = False

    def file_presence(path):
        nonlocal interrupt
        checked_files.append(path)
        if interrupt:
            interrupt = False
            root.rename(hidden)
        return presence(path)

    def root_available(path):
        if path == str(root):
            checked_roots.append(path)
        return isdir(path)

    monkeypatch.setattr(watch_state_module, "_recorded_file_presence", file_presence)
    monkeypatch.setattr(os.path, "isdir", root_available)
    try:
        root.rename(hidden)
        assert state.prune_missing_records() == 0
        assert not checked_files and len(checked_roots) == 1
        hidden.rename(root)
        checked_roots.clear()
        interrupt = True
        assert state.prune_missing_records() == 0
        assert state.entry_count == 64 and len(checked_roots) == 2
        hidden.rename(root)
        checked_roots.clear()
        assert state.prune_missing_records() == 64
        assert len(checked_roots) == 2
    finally:
        state.close()


def test_scope_retirement_persists_without_losing_pending_output_recovery(tmp_path):
    # Missing-file pruning cannot retire still-present inputs removed from
    # configuration, and must not erase the recovery queue or its output blockers.
    from sunpack.core.contracts.discovery_scope import DiscoveryScope
    from sunpack_native import resolve_output_volume_key

    retained, removed = tmp_path / "retained", tmp_path / "removed"
    retained.mkdir()
    removed.mkdir()
    output = tmp_path / "partial-output"
    output.mkdir()
    kept = retained / "kept.bin"
    abandoned = removed / "abandoned.001"
    owner = removed / "recover.bin"
    nested = output / "nested.bin"
    for path in (kept, abandoned, owner, nested):
        path.touch()
    state_path = tmp_path / "state.snapshot"
    state = WatchStateStore(str(state_path))
    volume = resolve_output_volume_key(str(retained)).lower()
    for path in (kept, abandoned, owner, nested):
        state.mark(str(path), 1, 1.0, status="suspended_missing_volume")
    state.queue_active(_candidate(owner), durable_owner=True, durable=True)
    state.record_task_output_started(str(owner), str(owner), str(output))
    state.merge_watch_cursors({volume: {"journal_id": 1, "next_usn": 2},
        "unused-volume": {"journal_id": 3, "next_usn": 4}})
    try:
        unavailable = DiscoveryScope(r"\\?\Volume{00000000-0000-0000-0000-000000000000}\input")
        state.retain_scopes([DiscoveryScope(str(retained)), unavailable])
        assert set(state.watch_cursor_snapshot()) == {volume, "unused-volume"}
        state.retain_scopes([DiscoveryScope(str(retained))])
        assert {entry.path for entry in state.entry_items()} == set(map(str, (kept, owner, nested)))
        assert set(state.watch_cursor_snapshot()) == {volume}
        seq = state.applied_seq
        state.retain_scopes([DiscoveryScope(str(retained))])
        assert state.applied_seq == seq
        assert not state_path.exists()
    finally:
        state.close()
    state = WatchStateStore(str(state_path))
    try:
        assert state.latest_entry_for_path(str(abandoned)) is None
        assert state.pending_work_for_path(str(owner)).active_outputs == {str(owner): str(output)}
        state.retain_scopes(())
        assert {entry.path for entry in state.entry_items()} == {str(owner), str(nested)}
        assert set(state.watch_cursor_snapshot()) == {volume}
        state.complete_work([str(owner)], durable=True)
        state.retain_scopes(())
        assert state.entry_count == state.pending_work_count == 0
        assert not state.watch_cursor_snapshot()
    finally:
        state.close()
    state = WatchStateStore(str(state_path))
    try:
        assert state.entry_count == state.pending_work_count == 0
        assert not state.watch_cursor_snapshot()
    finally:
        state.close()


def test_output_commit_preserves_identity_during_child_promotion_and_after_flatten(tmp_path):
    # Real nested tests do not force this overlap or check crash-recovery identity.
    # One tiny lifecycle covers both the blocked metadata read and the required
    # identity refresh after flattening; removing it loses that independent coverage.
    from sunpack.core.support.resource_lifecycle import promotion_barrier
    from sunpack_native import flatten_single_branch_directories, watch_path_identity

    source = tmp_path / "outer.zip"
    source.touch()
    output = tmp_path / "output"
    wrapper = output / "wrapper"
    wrapper.mkdir(parents=True)
    child = wrapper / "payload.bin"
    child.write_bytes(b"payload")
    state_path = tmp_path / "state.snapshot"
    state = WatchStateStore(str(state_path))
    try:
        state.queue_active(_candidate(source), durable_owner=True, durable=True)
        assert state.record_task_output_started(str(source), str(source), str(output))
        identity = state.pending_work_for_path(str(source)).output_identities[str(output)]
        with promotion_barrier([child], quiesce=False):
            assert state.record_task_output_finished(
                str(source), str(source), str(output), keep_output=True,
            )
        assert state.pending_work_for_path(str(source)).output_identities[str(output)] == identity

        flattened = flatten_single_branch_directories(str(output))
        assert not flattened["errors"] and flattened["source_dir"]
        assert state.record_task_output_finished(
            str(source), str(source), str(output), keep_output=True,
        )
        volume, file_id, _ = watch_path_identity(str(output))
        refreshed = f"{volume}|{file_id}"
        assert refreshed != identity
        assert state.pending_work_for_path(str(source)).output_identities == {str(output): refreshed}
    finally:
        state.close()
    state = WatchStateStore(str(state_path))
    try:
        pending = state.pending_work_for_path(str(source))
        assert pending.committed_roots == [str(output)]
        assert pending.output_identities == {str(output): refreshed}
        assert not pending.active_outputs
    finally:
        state.close()


def test_native_checkpoint_round_trips_nested_unicode_payload(tmp_path):
    state_path = tmp_path / "state.snapshot"
    archive = tmp_path / "雪-special.zip"
    archive.touch()
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
    state.merge_watch_cursors({
        "volume:雪": {"journal_id": 2**63 + 17, "next_usn": 2**63 + 19}
    })
    state.save()

    from sunpack_native import NativeWatchState
    restored = NativeWatchState()
    restored.load_snapshot(str(state_path))
    entry = restored.entry(str(archive))
    assert restored.watch_cursors()["volume:雪"]["journal_id"] == 2**63 + 17
    assert entry["last_error"] == "bad\n\"password\\雪"
    assert entry["failure_payload"]["nested"]["unicode"] == "雪☃"
    assert entry["failure_payload"]["nested"]["tuple"] == ["a", "b"]

    reloaded = WatchStateStore(str(state_path))
    assert reloaded.latest_entry_for_path(str(archive)).failure_payload["nested"]["escaped"] == "line1\nline2\t\\\""
    assert reloaded.watch_cursor("volume:雪")["next_usn"] == 2**63 + 19
