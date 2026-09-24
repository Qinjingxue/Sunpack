from __future__ import annotations

from types import SimpleNamespace

from sunpack.runtime.watch.scanner import WatchCandidate
from sunpack.runtime.watch.state import WatchStateStore


def _candidate(path, *, size=10, mtime=1.0):
    return WatchCandidate(path=str(path), size=size, mtime=mtime, file_id="id", change_usn=3)


def test_pending_output_recovery_state_round_trips(tmp_path):
    state_path = tmp_path / "state.json"
    source = tmp_path / "outer.zip"
    source.write_bytes(b"x")
    inner = tmp_path / "out" / "inner.zip"
    output = tmp_path / "out" / "inner"
    staging = tmp_path / "out" / ".sunpack-partial-test"
    state = WatchStateStore(str(state_path))
    state.queue_active(
        _candidate(source),
        password_scope_dir=str(tmp_path),
        durable_owner=True,
        persist=True,
        durable=True,
    )
    assert state.record_task_output_started(str(source), str(inner), str(output))

    [live] = state.pending_work_items()
    assert live.active_outputs[str(inner.resolve())] == str(output.resolve())

    # START is diagnostic only. A restart intentionally forgets it because
    # deterministic staging can be rediscovered without a second fsync.
    [before_commit] = WatchStateStore(str(state_path)).pending_work_items()
    assert before_commit.active_outputs == {}
    assert before_commit.password_scope_dir == str(tmp_path.resolve())

    assert state.record_task_output_committed(
        str(source),
        str(inner),
        str(output),
        staging_dir=str(staging),
        staging_file_id="staging-id",
    )
    [committed] = WatchStateStore(str(state_path)).pending_work_items()
    assert committed.active_outputs == {}
    assert committed.committed_roots == [str(output.resolve())]
    assert committed.completed_sources == [str(inner.resolve())]
    [publication] = committed.publications.values()
    assert publication == {
        "task_path": str(inner.resolve()),
        "staging_dir": str(staging.resolve()),
        "staging_file_id": "staging-id",
        "output_dir": str(output.resolve()),
    }


def test_rebase_pending_work_atomically_moves_recovery_anchor(tmp_path):
    state_path = tmp_path / "state.json"
    outer = tmp_path / "outer.zip"
    first = tmp_path / "out" / "first.zip"
    second = tmp_path / "out" / "second.zip"
    for path in (outer, first, second):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
    state = WatchStateStore(str(state_path))
    state.queue_active(_candidate(outer), password_scope_dir=str(tmp_path))
    state.rebase_pending_work(
        str(outer),
        [_candidate(first), _candidate(second)],
        password_scope_dir=str(tmp_path),
    )

    recovered = WatchStateStore(str(state_path)).pending_work_items()
    assert {item.path for item in recovered} == {str(first.resolve()), str(second.resolve())}
    assert all(item.internal_recovery for item in recovered)
    assert all(item.password_scope_dir == str(tmp_path.resolve()) for item in recovered)
    assert all(not item.active_outputs and not item.committed_roots for item in recovered)


def test_live_enqueue_keeps_owner_memory_only(tmp_path):
    import threading
    import sunpack.runtime.watch.scheduler as scheduler_module

    source = tmp_path / "queued.zip"
    source.write_bytes(b"payload")
    candidate = _candidate(source, size=7)
    calls = []
    scheduler = object.__new__(scheduler_module.WatchScheduler)
    scheduler._lock = threading.Lock()
    scheduler._pending = {}
    scheduler._active_states = {}
    scheduler._latest_observations = {}
    scheduler._quiet_trackers = {}
    scheduler.cold_start_seconds = 0.0
    scheduler._quiet_policy = SimpleNamespace()
    scheduler.state = SimpleNamespace(
        latest_entry_for_path=lambda _path: None,
        queue_active=lambda *_args, **kwargs: calls.append(kwargs),
    )
    scheduler.config = {}
    scheduler.log = SimpleNamespace(
        write=lambda *_args, **_kwargs: None,
        write_throttled=lambda *_args, **_kwargs: None,
    )
    scheduler._wake_callback = None
    scheduler.metadata_files = set()
    scheduler.metadata_dir = ""
    scheduler.watch_roots = [str(tmp_path)]
    scheduler._observe_candidate_activity = lambda *_args, **_kwargs: 0.0
    monkeypatch_target = scheduler_module._candidate_for_event_path
    scheduler_module._candidate_for_event_path = lambda *_args, **_kwargs: candidate
    try:
        scheduler.enqueue(str(source), force=True, event_type="modified")
    finally:
        scheduler_module._candidate_for_event_path = monkeypatch_target

    assert len(calls) == 1
    assert calls[0]["durable_owner"] is False
    assert calls[0]["persist"] is False
    assert calls[0]["durable"] is False
    assert candidate.path in scheduler._pending


def test_noncritical_attempt_refresh_does_not_force_an_extra_fsync(tmp_path, monkeypatch):
    import sunpack.runtime.watch.state as state_module

    state = WatchStateStore(str(tmp_path / "state.json"))
    source = tmp_path / "queued.zip"
    source.write_bytes(b"x")
    state.queue_active(_candidate(source))
    calls = []
    monkeypatch.setattr(state_module.os, "fsync", lambda fd: calls.append(fd))
    state.record_attempt(str(source), 10, 2.0, "id", 4)
    assert calls == []


def test_startup_blocker_reconciliation_is_targeted(tmp_path, monkeypatch):
    import sunpack.runtime.watch.scheduler as scheduler_module

    scheduler = object.__new__(scheduler_module.WatchScheduler)
    password_archive = tmp_path / "password.zip"
    missing_archive = tmp_path / "missing.7z.001"
    password_archive.write_bytes(b"x")
    missing_archive.write_bytes(b"x")
    scope = tmp_path / "scope"
    scope.mkdir()
    password_entry = SimpleNamespace(
        path=str(password_archive),
        status="failed_password",
        password_scope_dir=str(scope),
        failure_payload={"password_scope_signature": "old"},
    )
    missing_entry = SimpleNamespace(
        path=str(missing_archive),
        status="suspended_missing_volume",
        password_scope_dir=str(tmp_path),
        failure_payload={},
    )
    scheduler.state = SimpleNamespace(
        entry_items=lambda: [password_entry, missing_entry],
    )
    scheduler.config = {}
    calls = []
    scheduler.enqueue = lambda path, **kwargs: calls.append((path, kwargs))
    monkeypatch.setattr(scheduler_module, "_directory_password_signature", lambda *_args: "new")

    scheduler._reconcile_persisted_blockers()

    assert [call[0] for call in calls] == [
        str(password_archive),
        str(missing_archive),
    ]
    assert calls[0][1]["event_type"] == "startup_password_reconcile"
    assert calls[1][1]["event_type"] == "startup_missing_volume_reconcile"


def test_departed_inflight_owner_does_not_delete_durable_pending(tmp_path):
    import threading
    import sunpack.runtime.watch.scheduler as scheduler_module

    source = tmp_path / "outer.zip"
    source.write_bytes(b"x")
    state = WatchStateStore(str(tmp_path / "state.json"))
    state.queue_active(_candidate(source))

    scheduler = object.__new__(scheduler_module.WatchScheduler)
    scheduler._lock = threading.Lock()
    scheduler._pending = {}
    scheduler._active_states = {}
    scheduler._quiet_trackers = {}
    scheduler._latest_observations = {}
    scheduler._inflight_requests = [SimpleNamespace(candidate=_candidate(source))]
    scheduler.state = state
    scheduler.log = SimpleNamespace(write=lambda *_args, **_kwargs: None)
    scheduler._wake_callback = None

    scheduler.notify_path_departed(str(source))

    assert state.pending_work_for_path(str(source)) is not None


def test_departed_unowned_path_is_still_forgotten(tmp_path):
    import threading
    import sunpack.runtime.watch.scheduler as scheduler_module

    source = tmp_path / "gone.zip"
    source.write_bytes(b"x")
    state = WatchStateStore(str(tmp_path / "state.json"))
    state.queue_active(_candidate(source))

    scheduler = object.__new__(scheduler_module.WatchScheduler)
    scheduler._lock = threading.Lock()
    scheduler._pending = {}
    scheduler._active_states = {}
    scheduler._quiet_trackers = {}
    scheduler._latest_observations = {}
    scheduler._inflight_requests = []
    scheduler.state = state
    scheduler.log = SimpleNamespace(write=lambda *_args, **_kwargs: None)
    scheduler._wake_callback = None

    scheduler.notify_path_departed(str(source))

    assert state.pending_work_for_path(str(source)) is None


def test_critical_semantic_event_propagates_callback_failure():
    import pytest
    from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner

    runner = SevenZipRunner({})
    runner.progress_callback = lambda *_args: (_ for _ in ()).throw(RuntimeError("state write failed"))
    task = SimpleNamespace()

    with pytest.raises(RuntimeError, match="state write failed"):
        runner.emit_semantic_event(task, "task_output_started", critical=True, output_dir="out")

    # Ordinary progress semantics remain best-effort.
    runner.emit_semantic_event(task, "ui_progress", critical=False)


def test_committed_roots_collapse_nested_outputs(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    outer = tmp_path / "outer.zip"
    outer.write_bytes(b"x")
    state.queue_active(_candidate(outer))
    root = tmp_path / "out" / "outer"
    child_source = root / "child.zip"
    child_output = root / "child"

    state.record_task_output_started(str(outer), str(outer), str(root))
    state.record_task_output_committed(str(outer), str(outer), str(root))
    state.record_task_output_started(str(outer), str(child_source), str(child_output))
    state.record_task_output_committed(str(outer), str(child_source), str(child_output))

    [pending] = state.pending_work_items()
    assert pending.committed_roots == [str(root.resolve())]
    assert pending.completed_sources == [str(child_source.resolve())]


def test_enqueue_does_not_publish_memory_work_when_durable_queue_fails(tmp_path):
    import threading
    import pytest
    import sunpack.runtime.watch.scheduler as scheduler_module

    source = tmp_path / "archive.zip"
    source.write_bytes(b"payload")
    candidate = _candidate(source, size=7)
    scheduler = object.__new__(scheduler_module.WatchScheduler)
    scheduler._lock = threading.Lock()
    scheduler._pending = {}
    scheduler._active_states = {}
    scheduler._latest_observations = {}
    scheduler._quiet_trackers = {}
    scheduler.cold_start_seconds = 0.0
    scheduler._quiet_policy = SimpleNamespace()

    def fail_queue(*_args, **kwargs):
        assert kwargs["durable_owner"] is True
        assert kwargs["persist"] is True
        assert kwargs["durable"] is True
        raise OSError("disk failed")

    scheduler.state = SimpleNamespace(
        latest_entry_for_path=lambda _path: None,
        queue_active=fail_queue,
    )
    scheduler.config = {}
    scheduler.log = SimpleNamespace(
        write=lambda *_args, **_kwargs: None,
        write_throttled=lambda *_args, **_kwargs: None,
    )
    scheduler._wake_callback = None
    scheduler.metadata_files = set()
    scheduler.metadata_dir = ""
    scheduler.watch_roots = [str(tmp_path)]
    scheduler._observe_candidate_activity = lambda *_args, **_kwargs: 0.0
    monkeypatch_target = scheduler_module._candidate_for_event_path
    scheduler_module._candidate_for_event_path = lambda *_args, **_kwargs: candidate
    try:
        with pytest.raises(OSError, match="disk failed"):
            scheduler.enqueue(
                str(source),
                force=True,
                event_type="recovery",
                _crash_recovery=True,
                _recovery_scope_dir=str(tmp_path),
            )
    finally:
        scheduler_module._candidate_for_event_path = monkeypatch_target

    assert scheduler._pending == {}
    assert scheduler._active_states == {}


def test_persisted_blocker_wins_over_stale_pending_recovery(tmp_path):
    import sunpack.runtime.watch.scheduler as scheduler_module

    state = WatchStateStore(str(tmp_path / "state.json"))
    archive = tmp_path / "inner.zip"
    archive.write_bytes(b"x")
    state.mark(
        str(archive),
        1,
        archive.stat().st_mtime,
        status="failed_password",
        failure_payload={"kind": "wrong_password", "blockers": ["password"]},
    )

    assert scheduler_module._persisted_blocker_owns_retry(state, str(archive)) is True
    state.mark(
        str(archive),
        1,
        archive.stat().st_mtime,
        status="done",
    )
    assert scheduler_module._persisted_blocker_owns_retry(state, str(archive)) is False



def test_committed_publication_recovers_namespace_rollback_after_source_cleanup(tmp_path):
    """Durable publication intent makes the rename safely replayable after power loss."""
    import sunpack.runtime.watch.scheduler as scheduler_module
    from sunpack.pipeline.coordinator.watch_staging import publish_staging_output

    state_path = tmp_path / "state.json"
    source = tmp_path / "outer.zip"
    source.write_bytes(b"source")
    staging = tmp_path / ".sunpack-partial-power-loss"
    final = tmp_path / "published"
    staging.mkdir()
    (staging / "payload.bin").write_bytes(b"verified-output")

    state = WatchStateStore(str(state_path))
    state.queue_active(
        _candidate(source, size=len(b"source")),
        durable_owner=True,
        persist=True,
        durable=True,
    )
    assert state.record_task_output_committed(
        str(source),
        str(source),
        str(final),
        staging_dir=str(staging),
        staging_file_id="",
    )

    # Normal success publishes with a same-volume atomic rename. Emulate the
    # only power-loss state WRITE_THROUGH previously tried to prevent: the call
    # returned, source cleanup ran, but NTFS namespace persistence rolls back to
    # the durable staging name after reboot.
    publish_staging_output(str(staging), str(final))
    final.rename(staging)
    source.unlink()

    restarted = WatchStateStore(str(state_path))
    [pending] = restarted.pending_work_items()
    scheduler = object.__new__(scheduler_module.WatchScheduler)
    scheduler.state = restarted
    scheduler.config = {}
    scheduler.log = SimpleNamespace(write=lambda *_args, **_kwargs: None)
    scheduler._startup_suppress_paths = set()

    assert scheduler._recover_committed_publications(pending) is True
    assert final.is_dir()
    assert not staging.exists()
    assert (final / "payload.bin").read_bytes() == b"verified-output"
