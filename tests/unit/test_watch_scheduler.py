from __future__ import annotations

import asyncio

import json
import os
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import sunpack.filesystem.watcher.scheduler as scheduler_module
import sunpack.passwords.internal.builtin as builtin_module
import sunpack.passwords.internal.clipboard_monitor as clipboard_monitor_module
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse
from sunpack.contracts.results import OutcomeKind, TargetRunResult
from sunpack.filesystem.watcher.group_models import WatchGroupState
from sunpack.filesystem.watcher.scheduler import WatchScheduler as RuntimeWatchScheduler
from sunpack.filesystem.watcher.scanner import WatchCandidate
from sunpack.filesystem.watcher.state import WatchStateStore
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.support.path_keys import path_key
from tests.helpers.fake_pipeline_engine import FakePipelineEngine


def WatchScheduler(*args, pipeline_engine=None, **kwargs):
    if pipeline_engine is None:
        pipeline_engine = FakePipelineEngine(
            lambda _config: SimpleNamespace(
                recent_passwords=[],
                context=SimpleNamespace(flatten_candidates=set()),
                run_targets=lambda _paths: SimpleNamespace(
                    success_count=0,
                    partial_success_count=0,
                    failed_tasks=[],
                    failures=[],
                    processed_keys=[],
                    recovered_outputs=[],
                    target_results=[],
                ),
            )
        )
    return RuntimeWatchScheduler(*args, pipeline_engine=pipeline_engine, **kwargs)


def test_usn_data_reason_detects_same_size_in_place_content_change():
    previous = WatchCandidate("sample.zip", 100, 10.0, "file", 100)
    current = WatchCandidate(
        "sample.zip",
        100,
        10.0,
        "file",
        101,
        change_reasons=scheduler_module.USN_REASON_DATA_OVERWRITE,
        change_reasons_without_close=scheduler_module.USN_REASON_DATA_OVERWRITE,
        change_reasons_known=True,
    )

    assert scheduler_module._candidate_content_changed(previous, current)
    assert (
        scheduler_module._candidate_change_kind(previous, current)
        == scheduler_module._CandidateChangeKind.CONTENT_CHANGED
    )


def test_usn_metadata_reason_does_not_count_as_content_change():
    previous = WatchCandidate("sample.zip", 100, 100.0, "file", 100)
    current = WatchCandidate(
        "sample.zip",
        100,
        50.0,
        "file",
        101,
        change_reasons=0x00008000,
        change_reasons_known=True,
    )

    assert not scheduler_module._candidate_content_changed(previous, current)
    assert (
        scheduler_module._candidate_change_kind(previous, current)
        == scheduler_module._CandidateChangeKind.METADATA_ONLY
    )


def test_usn_close_accumulated_data_reason_does_not_restart_content_quiet_window():
    previous = WatchCandidate("sample.zip", 100, 10.0, "file", 100)
    current = WatchCandidate(
        "sample.zip",
        100,
        10.0,
        "file",
        101,
        change_reasons=0x80000000 | scheduler_module.USN_REASON_DATA_OVERWRITE,
        change_reasons_without_close=0,
        change_reasons_known=True,
    )

    assert not scheduler_module._candidate_content_changed(previous, current)
    assert (
        scheduler_module._candidate_change_kind(previous, current)
        == scheduler_module._CandidateChangeKind.METADATA_ONLY
    )


def test_unavailable_journal_treats_large_backward_mtime_restore_as_metadata_only():
    previous = WatchCandidate("sample.zip", 100, 100.0, "file", 100)
    current = WatchCandidate("sample.zip", 100, 50.0, "file", 101)

    assert not scheduler_module._candidate_content_changed(previous, current)


def test_unavailable_journal_keeps_same_stat_usn_change_conservative():
    previous = WatchCandidate("sample.zip", 100, 100.0, "file", 100)
    current = WatchCandidate("sample.zip", 100, 100.0, "file", 101)

    assert scheduler_module._candidate_content_changed(previous, current)


def test_identical_observation_is_unchanged():
    candidate = WatchCandidate("sample.zip", 100, 100.0, "file", 100)

    assert (
        scheduler_module._candidate_change_kind(candidate, candidate)
        == scheduler_module._CandidateChangeKind.UNCHANGED
    )


_TEST_LOOP = asyncio.new_event_loop()

def _await(awaitable):
    return _TEST_LOOP.run_until_complete(awaitable)


class FakeObserver:
    started_count = 0
    stopped_count = 0
    join_timeouts = []

    def __init__(self):
        self.scheduled = []
        self.started = False
        self.stopped = False

    def schedule(self, handler, path, recursive=True):
        self.scheduled.append((handler, path, recursive))

    def start(self):
        self.started = True
        type(self).started_count += 1

    def stop(self):
        self.stopped = True
        type(self).stopped_count += 1

    def join(self, timeout=None):
        type(self).join_timeouts.append(timeout)
        return None


def test_watch_scheduler_prunes_missing_state_before_start(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watch_root = tmp_path / "watch"
    watch_root.mkdir()
    state_path = tmp_path / ".sunpack_watch" / "state.json"
    stale_path = tmp_path / "gone.zip"

    persisted = WatchStateStore(str(state_path))
    persisted.mark(
        str(stale_path),
        1,
        1.0,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    persisted.groups["gone"] = WatchGroupState(
        group_id="gone",
        directory=str(tmp_path),
        logical_name="gone",
        split_family="7z",
        head_path=str(stale_path),
        input_paths=[str(stale_path)],
        owned_paths=[str(stale_path)],
    )
    persisted.save()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=".",
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=False,
    )

    watcher._start_blocking()
    try:
        assert not watcher.state.entries
        assert not watcher.state.groups
        reloaded = WatchStateStore(str(state_path))
        assert not reloaded.entries
        assert not reloaded.groups
    finally:
        watcher._stop_blocking()


class FakeSummary:
    success_count = 1
    failed_tasks = []
    failures = []


class WatchClock:
    def __init__(self, value: float):
        self.value = value

    def install(self, monkeypatch):
        monkeypatch.setattr(scheduler_module.time, "time", lambda: self.value)

    def advance(self, seconds: float):
        self.value += seconds


class WatchEvents:
    def __init__(self, watcher, clock: WatchClock):
        self.watcher = watcher
        self.clock = clock

    def emit(self, path: Path | str, *, event_type: str = "created", after: float = 0.0):
        self.clock.advance(after)
        self.watcher.enqueue(str(path), event_type=event_type)

    def run_after(self, seconds: float, *, processed: int):
        self.clock.advance(seconds)
        result = _await(self.watcher.run_once())
        assert result.processed == processed
        return result


class WatchState:
    @staticmethod
    def assert_pending(watcher, count: int):
        assert watcher.pending_count == count

    @staticmethod
    def assert_processed(result, count: int):
        assert result.processed == count

    @staticmethod
    def assert_quiet_seconds(watcher, path: Path | str, *, minimum: float, maximum: float | None = None):
        quiet_seconds = watcher._active_states[str(path)].quiet_seconds
        assert quiet_seconds >= minimum
        if maximum is not None:
            assert quiet_seconds <= maximum
        return quiet_seconds


class CapturingNotificationSink:
    def __init__(self):
        self.events = []

    def submitted(self, request_id, source_path):
        self.events.append(("submitted", request_id, source_path))

    def progress(self, request_id, task, event):
        self.events.append(("progress", request_id, task, event))

    def succeeded(self, request_id, output_dirs):
        self.events.append(("succeeded", request_id, output_dirs))

    def failed(self, request_id, errors, failure_payloads):
        self.events.append(("failed", request_id, errors, failure_payloads))

    def suppressed(self, request_id):
        self.events.append(("suppressed", request_id))

    def aborted(self, request_id):
        self.events.append(("aborted", request_id))


def _summary_pipeline_engine():
    return FakePipelineEngine(
        lambda _config: SimpleNamespace(
            context=SimpleNamespace(flatten_candidates=set(), recovered_outputs=[]),
            recent_passwords=[],
            run_targets=lambda _paths: FakeSummary(),
        )
    )


def _write_zip(path: Path):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("inside.txt", "ok")


def _nested_failure_summary(path: Path, failure: FailureInfo):
    return SimpleNamespace(
        success_count=1,
        partial_success_count=0,
        failed_tasks=[f"{path.parent / 'nested-inner.7z.001'}: {failure.message}"],
        failures=[failure],
        processed_keys=[str(path)],
        recovered_outputs=[],
        target_results=[TargetRunResult(str(path), OutcomeKind.COMPLETE_SUCCESS)],
    )


class _DeferredHandle:
    def __init__(self, path: str):
        self.path = path
        self.future = _TEST_LOOP.create_future()

    def done(self):
        return self.future.done()

    def complete_no_tasks(self):
        summary = SimpleNamespace(
            success_count=0,
            partial_success_count=0,
            failed_tasks=[],
            failures=[],
            processed_keys=[],
            target_results=[],
            recovered_outputs=[],
        )
        self.future.set_result(PipelineResponse(
            request_id=self.path,
            summary=summary,
            artifacts=PipelineArtifacts(),
            recent_passwords=(),
        ))


class _DeferredPipelineEngine:
    def __init__(self):
        self.handles = []
        self.work_broker = FakePipelineEngine(lambda _config: None).work_broker

    def update_password_sources(self, *, user_passwords, builtin_passwords):
        return None

    @property
    def recent_passwords(self):
        return []

    async def run(
        self,
        targets,
        *,
        direct=False,
        request_config=None,
        output_committer=None,
        progress_callback=None,
        origin="foreground",
    ):
        handle = _DeferredHandle(targets[0].path)
        self.handles.append(handle)
        return await handle.future


def test_watch_run_once_harvests_futures_without_waiting_for_slow_batch(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archives = [tmp_path / f"sample-{index}.zip" for index in range(3)]
    for archive in archives:
        _write_zip(archive)
    engine = _DeferredPipelineEngine()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=engine,
    )

    watcher.enqueue(str(archives[0]))
    watcher.enqueue(str(archives[1]))
    submitted = _await(watcher.run_once())

    assert submitted.processed == 0
    assert len(engine.handles) == 2

    engine.handles[1].complete_no_tasks()
    harvested = _await(watcher.run_once())
    assert harvested.processed == 1
    assert engine.handles[0].done() is False

    watcher.enqueue(str(archives[2]))
    still_scheduling = _await(watcher.run_once())
    assert still_scheduling.processed == 0
    assert len(engine.handles) == 3

    engine.handles[0].complete_no_tasks()
    engine.handles[2].complete_no_tasks()
    final = _await(watcher.run_once())
    assert final.processed == 2


def test_watch_candidate_coroutines_are_harvested_without_completion_pool(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    _write_zip(first)
    _write_zip(second)

    class Runner:
        recent_passwords = []

        def __init__(self, config):
            self.output_root = Path(config["output"]["root"])
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])
            self.path = ""

        def run_targets(self, paths):
            self.path = paths[0]
            output = self.output_root / Path(self.path).stem
            output.mkdir(parents=True, exist_ok=True)
            (output / "payload.bin").write_bytes(b"payload")
            self.context.flatten_candidates = {str(output)}
            return _watch_summary(self.path, OutcomeKind.COMPLETE_SUCCESS, {"decision_hint": "accept"})

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(Runner),
    )
    watcher.enqueue(str(first))
    watcher.enqueue(str(second))

    harvested = _await(watcher.run_once())
    deadline = time.monotonic() + 5
    while harvested.succeeded < 2 and time.monotonic() < deadline:
        next_result = _await(watcher.run_once())
        harvested.succeeded += next_result.succeeded
        time.sleep(0.01)
    assert harvested.succeeded == 2


def _watch_summary(path: str, kind: OutcomeKind, verification: dict):
    return SimpleNamespace(
        success_count=1 if kind == OutcomeKind.COMPLETE_SUCCESS else 0,
        partial_success_count=1 if kind == OutcomeKind.PARTIAL_SUCCESS else 0,
        failed_tasks=[],
        failures=[],
        processed_keys=[path],
        target_results=[TargetRunResult(path, kind, verification=verification)],
    )


def test_successful_watch_task_commits_postprocess_after_promotion(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)

    class SuccessRunner:
        recent_passwords = []

        def __init__(self, config):
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates={str(self.output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            self.output_dir.mkdir(parents=True)
            (self.output_dir / "payload.bin").write_bytes(b"payload")
            return _watch_summary(paths[0], OutcomeKind.COMPLETE_SUCCESS, {"decision_hint": "accept"})

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(SuccessRunner),
    )
    watcher.enqueue(str(archive))
    result = _await(watcher.run_once())

    assert result.succeeded == 1
    assert list((tmp_path / "out").rglob("payload.bin"))


def test_failed_watch_task_does_not_commit_probe_output(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)

    class FailureRunner:
        recent_passwords = []

        def __init__(self, config):
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            self.output_dir.mkdir(parents=True)
            (self.output_dir / "invalid.bin").write_bytes(b"invalid")
            return SimpleNamespace(
                success_count=0,
                partial_success_count=0,
                failed_tasks=["boom"],
                failures=[FailureInfo(kind=FailureKind.UNKNOWN, stage="extraction", message="boom")],
                processed_keys=[paths[0]],
                target_results=[
                    TargetRunResult(paths[0], OutcomeKind.FAILURE, verification={"decision_hint": "reject"})
                ],
            )

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FailureRunner),
    )
    watcher.enqueue(str(archive))
    result = _await(watcher.run_once())

    assert result.failed == 1
    probe_root = tmp_path / ".sunpack_watch_probes"
    assert probe_root.is_dir()
    assert list(probe_root.iterdir()) == []


def test_partial_result_does_not_self_retry_but_modified_epoch_does(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)
    calls = []
    outcomes = [OutcomeKind.PARTIAL_SUCCESS, OutcomeKind.COMPLETE_SUCCESS]

    class SequenceRunner:
        recent_passwords = []

        def __init__(self, config):
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            kind = outcomes[len(calls)]
            calls.append(kind)
            self.output_dir.mkdir(parents=True)
            (self.output_dir / "payload.bin").write_bytes(b"payload")
            if kind == OutcomeKind.PARTIAL_SUCCESS:
                self.context.recovered_outputs = [{"out_dir": str(self.output_dir)}]
                verification = {"decision_hint": "accept_partial", "archive_coverage": {"complete_files": 1}}
            else:
                self.context.flatten_candidates = {str(self.output_dir)}
                verification = {"decision_hint": "accept"}
            return _watch_summary(paths[0], kind, verification)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(SequenceRunner),
    )
    watcher.enqueue(str(archive))
    assert _await(watcher.run_once()).processed == 1
    probe_root = tmp_path / ".sunpack_watch_probes"
    assert probe_root.is_dir()
    assert list(probe_root.iterdir()) == []
    assert _await(watcher.run_once()).processed == 0
    with archive.open("ab") as stream:
        stream.write(b"changed")
    watcher.enqueue(str(archive), event_type="modified")
    final = _await(watcher.run_once())

    assert final.succeeded == 1
    assert (tmp_path / "out" / "sample" / "payload.bin").is_file()
    assert probe_root.is_dir()
    assert list(probe_root.iterdir()) == []


def test_partial_result_is_rejected_and_probe_output_is_discarded(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)

    class PartialRunner:
        recent_passwords = []

        def __init__(self, config):
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            self.output_dir.mkdir(parents=True)
            (self.output_dir / "recovered.bin").write_bytes(b"partial")
            self.context.recovered_outputs = [{"out_dir": str(self.output_dir)}]
            return _watch_summary(
                paths[0],
                OutcomeKind.PARTIAL_SUCCESS,
                {"decision_hint": "accept_partial", "archive_coverage": {"complete_files": 1}},
            )

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(PartialRunner),
    )
    watcher.enqueue(str(archive))

    result = _await(watcher.run_once())

    assert result.processed == 1
    assert result.succeeded == 0
    assert result.failed == 1
    assert result.errors == ["Watch extraction rejected partial content"]
    assert not (tmp_path / "out" / "sample" / "recovered.bin").exists()
    probe_root = tmp_path / ".sunpack_watch_probes"
    assert probe_root.is_dir()
    assert list(probe_root.iterdir()) == []
    assert _await(watcher.run_once()).processed == 0


def test_probe_promotion_keeps_nested_outputs_inside_outer_directory(tmp_path):
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(watch_root),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
    )
    workspace = Path(watcher._prepare_probe_workspace(str(watch_root / "outer.zip")))
    outer = workspace / "outer"
    inner = outer / "inner"
    inner.mkdir(parents=True)
    (inner / "payload.bin").write_bytes(b"payload")

    promoted, path_map = _await(watcher._promote_probe_outputs(
        [str(outer), str(inner)],
        [str(watch_root / "outer")],
        str(workspace),
    ))

    assert promoted == [str(watch_root / "outer")]
    assert path_map[str(inner)] == str(watch_root / "outer" / "inner")
    assert (watch_root / "outer" / "inner" / "payload.bin").is_file()
    assert not (watch_root / "inner").exists()


def test_probe_promotion_retries_winerror_5_until_success(tmp_path, monkeypatch):
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(watch_root),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
    )
    workspace = Path(watcher._prepare_probe_workspace(str(watch_root / "sample.zip")))
    source = workspace / "sample"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"payload")
    real_replace = scheduler_module.os.replace
    replace_attempts = []
    sleeps = []

    def intermittently_denied(current, target):
        replace_attempts.append((current, target))
        if len(replace_attempts) < 3:
            error = PermissionError("temporarily denied")
            error.winerror = 5
            raise error
        real_replace(current, target)

    monkeypatch.setattr(scheduler_module.os, "replace", intermittently_denied)
    async def record_sleep(delay):
        sleeps.append(delay)
    monkeypatch.setattr(scheduler_module.asyncio, "sleep", record_sleep)

    promoted, _ = _await(watcher._promote_probe_outputs(
        [str(source)],
        [str(watch_root / "sample")],
        str(workspace),
    ))

    assert promoted == [str(watch_root / "sample")]
    assert len(replace_attempts) == 3
    assert sleeps == [0.02, 0.04]
    assert (watch_root / "sample" / "payload.bin").is_file()


def test_probe_promotion_does_not_retry_other_errors(tmp_path, monkeypatch):
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(watch_root),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
    )
    workspace = Path(watcher._prepare_probe_workspace(str(watch_root / "sample.zip")))
    source = workspace / "sample"
    source.mkdir()
    sleeps = []
    error = PermissionError("sharing violation")
    error.winerror = 32
    monkeypatch.setattr(scheduler_module.os, "replace", lambda *_args: (_ for _ in ()).throw(error))
    async def record_sleep(delay):
        sleeps.append(delay)
    monkeypatch.setattr(scheduler_module.asyncio, "sleep", record_sleep)

    try:
        _await(watcher._promote_probe_outputs(
            [str(source)],
            [str(watch_root / "sample")],
            str(workspace),
        ))
    except PermissionError as exc:
        assert exc is error
    else:
        raise AssertionError("expected non-WinError 5 failure to propagate")

    assert sleeps == []


def test_probe_promotion_stops_after_bounded_winerror_5_retries(tmp_path, monkeypatch):
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(watch_root),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
    )
    workspace = Path(watcher._prepare_probe_workspace(str(watch_root / "sample.zip")))
    source = workspace / "sample"
    source.mkdir()
    attempts = []
    sleeps = []

    def always_denied(*_args):
        attempts.append("attempt")
        error = PermissionError("still denied")
        error.winerror = 5
        raise error

    monkeypatch.setattr(scheduler_module.os, "replace", always_denied)
    async def record_sleep(delay):
        sleeps.append(delay)
    monkeypatch.setattr(scheduler_module.asyncio, "sleep", record_sleep)

    try:
        _await(watcher._promote_probe_outputs(
            [str(source)],
            [str(watch_root / "sample")],
            str(workspace),
        ))
    except PermissionError as exc:
        assert exc.winerror == 5
    else:
        raise AssertionError("expected retries to stop at the configured limit")

    assert len(attempts) == scheduler_module.PROBE_PROMOTION_MAX_RETRIES + 1
    assert len(sleeps) == scheduler_module.PROBE_PROMOTION_MAX_RETRIES
    assert sleeps == sorted(sleeps)
    assert sleeps[-1] == scheduler_module.PROBE_PROMOTION_MAX_RETRY_SECONDS


def test_content_event_during_processing_starts_a_new_active_epoch(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)
    attempts = 0
    watcher = None

    class MutatingRunner:
        recent_passwords = []

        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                archive.write_bytes(archive.read_bytes() + b"new-data")
                watcher.enqueue(str(archive), event_type="modified")
            return _watch_summary(paths[0], OutcomeKind.PARTIAL_SUCCESS, {"decision_hint": "accept_partial"})

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(MutatingRunner),
    )
    watcher.enqueue(str(archive))

    assert _await(watcher.run_once()).processed == 1
    assert watcher.pending_count == 1
    assert len(watcher.state.pending_work_items()) == 1
    assert _await(watcher.run_once()).processed == 1
    assert attempts == 2


def test_metadata_event_during_and_after_processing_does_not_start_new_epoch(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)
    engine = _DeferredPipelineEngine()
    wakeups = []
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=engine,
        wake_callback=lambda: wakeups.append("wake"),
    )
    watcher.enqueue(str(archive), event_type="created")
    assert _await(watcher.run_once()).processed == 0
    assert len(engine.handles) == 1

    baseline = watcher._latest_observations[str(archive)]
    tracker = watcher._quiet_trackers[str(archive)]
    model_before = (
        tracker.last_content_event_at,
        tracker.intervals,
        tracker.quiet_seconds,
    )
    wakeups_before = len(wakeups)
    metadata = WatchCandidate(
        str(archive),
        baseline.size,
        baseline.mtime - 60.0,
        baseline.file_id,
        max(1, baseline.change_usn + 1),
        change_reasons=0x00008000,
        change_reasons_without_close=0,
        change_reasons_known=True,
    )
    monkeypatch.setattr(
        scheduler_module,
        "_candidate_for_event_path",
        lambda _path, *, since_usn=0: metadata,
    )

    watcher.enqueue(str(archive), event_type="modified")

    assert watcher.pending_count == 0
    assert watcher._latest_observations[str(archive)] == metadata
    assert len(wakeups) == wakeups_before
    assert (
        tracker.last_content_event_at,
        tracker.intervals,
        tracker.quiet_seconds,
    ) == model_before
    assert tracker.last_mtime == metadata.mtime
    assert tracker.last_change_usn == metadata.change_usn

    engine.handles[0].complete_no_tasks()
    assert _await(watcher.run_once()).processed == 1
    metadata_after = WatchCandidate(
        str(archive),
        metadata.size,
        metadata.mtime - 1.0,
        metadata.file_id,
        metadata.change_usn + 1,
        change_reasons=0x00008000,
        change_reasons_without_close=0,
        change_reasons_known=True,
    )
    monkeypatch.setattr(
        scheduler_module,
        "_candidate_for_event_path",
        lambda _path, *, since_usn=0: metadata_after,
    )
    watcher.enqueue(str(archive), event_type="modified")
    assert watcher.pending_count == 0
    assert watcher._latest_observations[str(archive)] == metadata_after
    assert _await(watcher.run_once()).processed == 0


def test_content_event_during_processing_still_starts_new_epoch_from_latest_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)
    engine = _DeferredPipelineEngine()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=engine,
    )
    watcher.enqueue(str(archive), event_type="created")
    assert _await(watcher.run_once()).processed == 0

    baseline = watcher._latest_observations[str(archive)]
    metadata = WatchCandidate(
        str(archive),
        baseline.size,
        baseline.mtime - 60.0,
        baseline.file_id,
        max(1, baseline.change_usn + 1),
        change_reasons=0x00008000,
        change_reasons_without_close=0,
        change_reasons_known=True,
    )
    monkeypatch.setattr(
        scheduler_module,
        "_candidate_for_event_path",
        lambda _path, *, since_usn=0: metadata,
    )
    watcher.enqueue(str(archive), event_type="modified")
    assert watcher.pending_count == 0

    content = WatchCandidate(
        str(archive),
        metadata.size,
        metadata.mtime,
        metadata.file_id,
        metadata.change_usn + 1,
        change_reasons=scheduler_module.USN_REASON_DATA_OVERWRITE,
        change_reasons_without_close=scheduler_module.USN_REASON_DATA_OVERWRITE,
        change_reasons_known=True,
    )
    monkeypatch.setattr(
        scheduler_module,
        "_candidate_for_event_path",
        lambda _path, *, since_usn=0: content,
    )

    watcher.enqueue(str(archive), event_type="modified")

    assert watcher.pending_count == 1
    assert watcher._latest_observations[str(archive)] == content
    engine.handles[0].complete_no_tasks()
    assert _await(watcher.run_once()).processed == 1
    assert len(engine.handles) == 2
    engine.handles[1].complete_no_tasks()
    assert _await(watcher.run_once()).processed == 1


def test_watch_scheduler_uses_watchdog_observer_and_initial_scan(tmp_path, monkeypatch):
    FakeObserver.started_count = 0
    FakeObserver.stopped_count = 0
    FakeObserver.join_timeouts = []
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    _write_zip(watch_root / "sample.zip")
    state_path = tmp_path / "state.json"

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=True,
    )

    _await(watcher.start())

    assert watcher.pending_count == 1
    assert FakeObserver.started_count == 1
    assert (watch_root / ".sunpack-passwords.txt").read_text(encoding="utf-8") == ""

    _await(watcher.stop())
    assert FakeObserver.stopped_count == 1


def test_watch_scheduler_scans_only_requested_initial_scan_roots(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    _write_zip(first_root / "first.zip")
    _write_zip(second_root / "second.zip")

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(first_root), str(second_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        initial_scan_roots=[str(second_root)],
    )

    _await(watcher.start())

    assert {Path(path).name for path in watcher._pending} == {"second.zip"}
    _await(watcher.stop())


def test_watch_scheduler_observes_builtin_password_file_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    builtin_path = tmp_path / "resources" / "builtin_passwords.txt"
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    watch_root = tmp_path / "in"
    watch_root.mkdir()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
    )

    _await(watcher.start())

    scheduled = {(Path(path), recursive) for _handler, path, recursive in watcher._observer.scheduled}
    assert (watch_root.resolve(), False) in scheduled
    assert (builtin_path.parent.resolve(), False) in scheduled


def test_watch_scheduler_preserves_existing_directory_password_file(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watch_root = tmp_path / "in"
    watch_root.mkdir()
    password_file = watch_root / ".sunpack-passwords.txt"
    password_file.write_text("existing-secret\n", encoding="utf-8")

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=True,
    )

    _await(watcher.start())

    assert password_file.read_text(encoding="utf-8") == "existing-secret\n"
    assert watcher.pending_count == 0


def test_watch_scheduler_start_cleans_probe_contents_but_keeps_probe_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    probe_root = tmp_path / ".sunpack_watch_probes"
    stale_workspace = probe_root / "stale-owner" / "work"
    stale_workspace.mkdir(parents=True)
    (stale_workspace / "partial.bin").write_bytes(b"partial")
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
    )

    _await(watcher.start())

    assert probe_root.is_dir()
    assert list(probe_root.iterdir()) == []
    _await(watcher.stop())


def test_watch_scheduler_never_recurses_for_current_directory_scan_mode(tmp_path, monkeypatch):
    FakeObserver.started_count = 0
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    nested = watch_root / "nested"
    nested.mkdir(parents=True)
    _write_zip(watch_root / "root.zip")
    _write_zip(nested / "nested.zip")

    watcher = WatchScheduler(
        {"filesystem": {"directory_scan_mode": "-", "scan_filters": []}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=True,
    )

    _await(watcher.start())

    assert watcher._observer.scheduled[0][1:] == (str(watch_root.resolve()), False)
    pending_names = {Path(path).name for path in watcher._pending}
    assert pending_names == {"root.zip"}


def test_watch_scheduler_never_recurses_for_recursive_directory_scan_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    nested = watch_root / "nested"
    nested.mkdir(parents=True)
    _write_zip(watch_root / "root.zip")
    _write_zip(nested / "nested.zip")

    watcher = WatchScheduler(
        {"filesystem": {"directory_scan_mode": "*", "scan_filters": []}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=True,
    )

    _await(watcher.start())

    assert watcher._observer.scheduled[0][1:] == (str(watch_root.resolve()), False)
    pending_names = {Path(path).name for path in watcher._pending}
    assert pending_names == {"root.zip"}


def test_watch_scheduler_uses_stop_timeout_without_suffix_prefilter(tmp_path, monkeypatch):
    FakeObserver.started_count = 0
    FakeObserver.stopped_count = 0
    FakeObserver.join_timeouts = []
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    (watch_root / "sample.rar").write_bytes(b"Rar!\x1a\x07\x00payload")
    _write_zip(watch_root / "sample.zip")

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        observer_stop_timeout_seconds=1.25,
    )

    _await(watcher.start())
    watcher.enqueue(str(watch_root / "sample.rar"))
    watcher.enqueue(str(watch_root / "sample.zip"))

    pending_paths = set(watcher._pending)
    assert any(path.endswith("sample.rar") for path in pending_paths)
    assert any(path.endswith("sample.zip") for path in pending_paths)

    _await(watcher.stop())
    assert FakeObserver.join_timeouts == [1.25]


def test_watch_scheduler_uses_filesystem_filters_for_candidates(tmp_path, monkeypatch):
    FakeObserver.started_count = 0
    FakeObserver.stopped_count = 0
    FakeObserver.join_timeouts = []
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    keep = watch_root / "keep.weird"
    blocked = watch_root / "blocked.zip"
    keep.write_bytes(b"PK\x03\x04payload")
    blocked.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {
            "filesystem": {
                "scan_filters": [
                    {"name": "blacklist", "enabled": True, "blocked_files": ["blocked.zip"]},
                    {"name": "size_range", "enabled": True, "range": "r >= 1 B"},
                ],
            }
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
    )

    watcher.enqueue(str(keep))
    watcher.enqueue(str(blocked))

    pending_paths = set(watcher._pending)
    assert any(path.endswith("keep.weird") for path in pending_paths)
    assert not any(path.endswith("blocked.zip") for path in pending_paths)


def test_watch_scheduler_accepts_small_split_tail_only_when_family_is_anchored(tmp_path):
    watch_root = tmp_path / "in"
    watch_root.mkdir()
    first = watch_root / "payload.7z.001"
    tail = watch_root / "payload.7z.002"
    unrelated = watch_root / "unrelated.7z.002"
    first.write_bytes(b"a" * 16)
    tail.write_bytes(b"tail")
    unrelated.write_bytes(b"noise")
    watcher = WatchScheduler(
        {
            "filesystem": {
                "scan_filters": [
                    {"name": "size_range", "enabled": True, "gte": 10},
                ],
            },
            "watch": {"clipboard_monitor_enabled": False},
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
        group_coordinator=WatchGroupCoordinator({
            "filesystem": {
                "scan_filters": [
                    {"name": "size_range", "enabled": True, "gte": 10},
                ],
            },
        }),
    )

    watcher.enqueue(str(tail))
    watcher.enqueue(str(unrelated))

    pending_paths = set(watcher._pending)
    assert str(tail.resolve()) in pending_paths
    assert str(unrelated.resolve()) not in pending_paths


def test_watch_scheduler_reuses_filter_result_for_unchanged_pending_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive = watch_root / "sample.zip"
    archive.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {
            "filesystem": {
                "scan_filters": [
                    {"name": "size_range", "enabled": True, "range": "r >= 1 B"},
                ],
            },
            "watch": {"clipboard_monitor_enabled": False},
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=30,
        initial_scan=False,
    )
    original_passes = watcher._passes_filesystem_filters
    filter_calls = []

    def counted_passes(candidate):
        filter_calls.append((candidate.size, candidate.mtime))
        return original_passes(candidate)

    monkeypatch.setattr(watcher, "_passes_filesystem_filters", counted_passes)

    watcher.enqueue(str(archive))
    watcher.enqueue(str(archive), event_type="modified")
    _await(watcher.run_once())
    _await(watcher.run_once())

    assert len(filter_calls) == 1
    assert watcher.pending_count == 1
    archive.write_bytes(b"PK\x03\x04payload-more")
    watcher.enqueue(str(archive), event_type="modified")

    assert len(filter_calls) == 1
    assert watcher.pending_count == 1


def test_event_burst_with_unchanged_usn_does_not_restart_quiet_window(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(lambda _config: SimpleNamespace(
            context=SimpleNamespace(flatten_candidates=set(), recovered_outputs=[]),
            run_targets=lambda paths: _watch_summary(paths[0], OutcomeKind.PARTIAL_SUCCESS, {}),
            recent_passwords=[],
        )),
    )

    for _ in range(100):
        watcher.enqueue(str(archive), event_type="modified")

    assert watcher.pending_count == 1
    assert watcher._active_states[str(archive)].generation == 1
    assert _await(watcher.run_once()).processed == 1


def test_candidate_deadline_changes_wake_watch_service(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK\x03\x04payload")
    wakeups = []
    watcher = WatchScheduler(
        {"filesystem": {"scan_filters": []}, "watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=30,
        initial_scan=False,
        wake_callback=lambda: wakeups.append("wake"),
    )

    watcher.enqueue(str(archive), event_type="created")
    assert wakeups == ["wake"]

    watcher.enqueue(str(archive), event_type="modified")
    assert wakeups == ["wake"]

    archive.write_bytes(b"PK\x03\x04payload-more")
    watcher.enqueue(str(archive), event_type="modified")
    assert wakeups == ["wake", "wake"]

    watcher.notify_path_departed(str(archive))
    assert wakeups == ["wake", "wake", "wake"]


def test_watch_scheduler_rechecks_filesystem_filters_before_processing(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive = watch_root / "sample.zip"
    archive.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"filesystem": {"scan_filters": []}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
    )
    original_passes = watcher._passes_filesystem_filters
    filter_calls = []

    def counted_passes(candidate):
        filter_calls.append((candidate.size, candidate.mtime))
        return original_passes(candidate)

    monkeypatch.setattr(watcher, "_passes_filesystem_filters", counted_passes)
    watcher.enqueue(str(archive))
    assert watcher.pending_count == 1

    watcher.filters = scheduler_module.build_filters({
        "filesystem": {
            "scan_filters": [
                {"name": "blacklist", "enabled": True, "blocked_files": ["sample.zip"]},
            ],
        }
    })

    result = _await(watcher.run_once())

    assert result.processed == 0
    assert watcher.pending_count == 0
    assert len(filter_calls) == 2


def test_watch_scheduler_processes_direct_quiet_candidate_with_watch_root_common_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    captured = {}

    class FakePipelineRunner:
        def __init__(self, config):
            captured["config"] = config

        def run_targets(self, paths):
            captured["paths"] = paths
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    watcher.enqueue(str(archive_path))

    result = _await(watcher.run_once())

    assert result.processed == 1
    assert result.succeeded == 1
    assert captured["paths"] == [str(archive_path.resolve())]
    assert Path(captured["config"]["output"]["root"]).parent.parent.name == ".sunpack_watch_probes"
    assert Path(captured["config"]["output"]["root"]).is_relative_to(watch_root)
    assert captured["config"]["output"]["common_root"] == str(watch_root.resolve())


def test_watch_scheduler_sends_quiet_nonstandard_extension_to_main_pipeline(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    captured = {}

    class FakePipelineRunner:
        def __init__(self, config):
            captured["config"] = config

        def run_targets(self, paths):
            captured["paths"] = paths
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    target = watch_root / "payload.weird"
    target.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"filesystem": {"scan_filters": []}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    watcher.enqueue(str(target))

    result = _await(watcher.run_once())

    assert result.processed == 1
    assert result.succeeded == 1
    assert captured["paths"] == [str(target.resolve())]


def test_watch_scheduler_moved_file_uses_common_quiet_window(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000000000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=10,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    watcher.enqueue(str(archive_path), event_type="moved", src_path=str(tmp_path / "sample.zip"))

    now[0] = 2000000009.9
    assert _await(watcher.run_once()).processed == 0
    now[0] = 2000000010.1
    assert _await(watcher.run_once()).processed == 1


def test_watch_scheduler_timestamp_restore_does_not_reset_content_quiet_window(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000001000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04" + b"x" * 1024)
    os_time = 2000001000.0
    import os
    os.utime(archive_path, (os_time, os_time))

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=10,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    watcher.enqueue(str(archive_path), event_type="created")

    now[0] = 2000001000.1
    archive_path.write_bytes(b"PK\x03\x04" + b"x" * 4096)
    os.utime(archive_path, (2000001000.1, 2000001000.1))
    watcher.enqueue(str(archive_path), event_type="modified")

    now[0] = 2000001000.2
    os.utime(archive_path, (2000000000.0, 2000000000.0))
    watcher.enqueue(str(archive_path), event_type="modified")

    now[0] = 2000001010.1
    assert _await(watcher.run_once()).processed == 1
    now[0] = 2000001010.3
    assert _await(watcher.run_once()).processed == 0


def test_pending_metadata_event_advances_snapshot_without_generation_or_wakeup(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive = tmp_path / "sample.zip"
    _write_zip(archive)
    wakeups = []
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=10,
        initial_scan=False,
        wake_callback=lambda: wakeups.append("wake"),
    )
    watcher.enqueue(str(archive), event_type="created")
    baseline = watcher._pending[str(archive)]
    state = watcher._active_states[str(archive)]
    tracker = watcher._quiet_trackers[str(archive)]
    generation = state.generation
    last_event_at = state.last_event_at
    model_before = (
        tracker.last_content_event_at,
        tracker.intervals,
        tracker.quiet_seconds,
    )
    wakeups_before = len(wakeups)
    metadata = WatchCandidate(
        str(archive),
        baseline.size,
        baseline.mtime - 60.0,
        baseline.file_id,
        max(1, baseline.change_usn + 1),
        change_reasons=0x00008000,
        change_reasons_without_close=0,
        change_reasons_known=True,
    )
    monkeypatch.setattr(
        scheduler_module,
        "_candidate_for_event_path",
        lambda _path, *, since_usn=0: metadata,
    )

    watcher.enqueue(str(archive), event_type="modified")

    assert watcher._pending[str(archive)] == metadata
    assert watcher._latest_observations[str(archive)] == metadata
    assert state.generation == generation
    assert state.last_event_at == last_event_at
    assert len(wakeups) == wakeups_before
    assert (
        tracker.last_content_event_at,
        tracker.intervals,
        tracker.quiet_seconds,
    ) == model_before
    assert tracker.last_mtime == metadata.mtime
    assert tracker.last_change_usn == metadata.change_usn


def test_watch_scheduler_growth_resets_the_common_quiet_window(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    now = [2000002000.0]
    monkeypatch.setattr(scheduler_module.time, "time", lambda: now[0])

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "slow.zip"
    archive_path.write_bytes(b"PK\x03\x04" + b"x" * 1024)
    import os
    os.utime(archive_path, (2000002000.0, 2000002000.0))

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=10,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    watcher.enqueue(str(archive_path), event_type="created")

    now[0] = 2000002000.2
    archive_path.write_bytes(b"PK\x03\x04" + b"x" * 4096)
    os.utime(archive_path, (2000002000.2, 2000002000.2))
    watcher.enqueue(str(archive_path), event_type="modified")

    now[0] = 2000002002.0
    assert _await(watcher.run_once()).processed == 0
    now[0] = 2000002010.3
    assert _await(watcher.run_once()).processed == 1


def test_watch_scheduler_does_not_log_duplicate_pending_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
    )
    watcher.enqueue(str(archive_path))
    watcher.enqueue(str(archive_path))

    assert watcher.pending_count == 1
    log_text = (tmp_path / ".sunpack_watch" / "events.jsonl").read_text(encoding="utf-8")
    assert log_text.count('"event":"candidate_active"') == 1


def test_watch_scheduler_ignores_unchanged_event_after_no_tasks_result(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    class NoTasksRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return SimpleNamespace(success_count=0, failed_tasks=[], processed_keys=[], recovered_outputs=[], failures=[])

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    target = watch_root / "paper.pdf"
    target.write_bytes(b"%PDF-" + b"x" * 1024)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(NoTasksRunner),
    )
    watcher.enqueue(str(target))

    result = _await(watcher.run_once())
    watcher.enqueue(str(target))
    unchanged = _await(watcher.run_once())

    assert result.processed == 1
    assert result.succeeded == 0
    assert unchanged.processed == 0
    assert watcher.pending_count == 0
    assert not watcher.state.entries
    log_text = (tmp_path / ".sunpack_watch" / "events.jsonl").read_text(encoding="utf-8")
    assert '"event":"no_tasks_found"' in log_text
    assert '"event":"done"' not in log_text


def test_watch_scheduler_ignores_nested_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path
    out_root = tmp_path / "out"
    out_root.mkdir()
    archive_path = out_root / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(out_root),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
    )
    watcher.enqueue(str(archive_path))

    assert watcher.pending_count == 0


def test_watch_scheduler_processes_archive_when_output_root_matches_watch_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    captured = {}

    class FakePipelineRunner:
        def __init__(self, config):
            captured["config"] = config
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates={str(self.output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            captured["paths"] = paths
            self.output_dir.mkdir(parents=True)
            return FakeSummary()

    archive_path = tmp_path / "sample.zip"
    _write_zip(archive_path)

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    watcher.enqueue(str(archive_path))

    result = _await(watcher.run_once())

    assert result.processed == 1
    assert result.succeeded == 1
    assert captured["paths"] == [str(archive_path.resolve())]
    assert not watcher.state.entries
    assert not watcher.state.pending_work_items()


def test_watch_scheduler_does_not_reprocess_unchanged_input_when_output_is_deleted(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive_path = tmp_path / "sample.zip"
    output_dir = tmp_path / "sample"
    _write_zip(archive_path)
    runs = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates={str(output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            runs.append(list(paths))
            output_dir.mkdir(exist_ok=True)
            return FakeSummary()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=".",
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )

    watcher.enqueue(str(archive_path), event_type="created")
    assert _await(watcher.run_once()).succeeded == 1
    assert len(runs) == 1

    watcher.enqueue(str(archive_path), event_type="modified")
    assert _await(watcher.run_once()).succeeded == 0
    assert len(runs) == 1

    output_dir.rmdir()
    watcher.enqueue(str(archive_path), event_type="modified")

    assert _await(watcher.run_once()).succeeded == 0
    assert len(runs) == 1


def test_watch_scheduler_reprocesses_identical_archive_after_it_moves_out_and_back(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watch_root = tmp_path / "watched"
    outside_root = tmp_path / "outside"
    watch_root.mkdir()
    outside_root.mkdir()
    archive_path = watch_root / "sample.zip"
    outside_path = outside_root / archive_path.name
    output_dir = watch_root / "sample"
    _write_zip(archive_path)
    runs = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates={str(output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            runs.append(list(paths))
            output_dir.mkdir(exist_ok=True)
            return FakeSummary()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=".",
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    handler = scheduler_module._WatchEventHandler(watcher)
    watcher.enqueue(str(archive_path))
    assert _await(watcher.run_once()).succeeded == 1

    archive_path.replace(outside_path)
    handler.on_moved(SimpleNamespace(src_path=str(archive_path), dest_path=str(outside_path), is_directory=False))
    outside_path.replace(archive_path)
    handler.on_moved(SimpleNamespace(src_path=str(outside_path), dest_path=str(archive_path), is_directory=False))

    assert watcher.pending_count == 1
    assert _await(watcher.run_once()).succeeded == 1
    assert len(runs) == 2


def test_watch_scheduler_reprocesses_split_group_after_source_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watch_root = tmp_path / "watched"
    watch_root.mkdir()
    archive_path = watch_root / "sample.7z.001"
    output_dir = watch_root / "sample"
    archive_path.write_bytes(b"split archive")
    original_mtime = archive_path.stat().st_mtime
    runs = []

    def snapshot():
        return scheduler_module.WatchGroupSnapshot(
            group_id="split-group",
            directory=str(watch_root),
            logical_name="sample",
            split_family="7z_numbered",
            head_path=str(archive_path),
            input_paths=(str(archive_path),),
            companion_paths=(),
            owned_paths=(str(archive_path),),
            input_fingerprint="same-input",
            ownership_fingerprint="same-owner",
            complete=True,
        )

    class GroupCoordinator:
        def resolve_paths(self, paths):
            if not archive_path.exists():
                return {}
            current = snapshot()
            return {path_key(path): current for path in paths}

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates={str(output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            runs.append(list(paths))
            output_dir.mkdir(exist_ok=True)
            archive_path.unlink()
            return FakeSummary()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=".",
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
        group_coordinator=GroupCoordinator(),
    )

    watcher.enqueue(str(archive_path))
    assert _await(watcher.run_once()).succeeded == 1
    assert watcher.state.group_state("split-group") is None

    archive_path.write_bytes(b"split archive")
    os.utime(archive_path, (original_mtime, original_mtime))
    watcher.enqueue(str(archive_path), force=True)

    assert _await(watcher.run_once()).succeeded == 1
    assert len(runs) == 2


def test_predicted_output_dir_uses_split_group_logical_name(tmp_path):
    watch_root = tmp_path / "watched"
    watch_root.mkdir()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=".",
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
    )

    result = watcher._predicted_output_dirs(
        str(watch_root / "sample.7z.001"),
        {"output": {"root": str(tmp_path / "out"), "common_root": str(watch_root)}},
        logical_name="sample",
    )

    assert result == [str(tmp_path / "out" / "sample")]


def test_watch_scheduler_processes_same_path_again_after_input_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive_path = tmp_path / "sample.zip"
    _write_zip(archive_path)
    runs = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            runs.append(list(paths))
            return FakeSummary()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=".",
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    watcher.enqueue(str(archive_path))
    assert _await(watcher.run_once()).succeeded == 1

    archive_path.write_bytes(archive_path.read_bytes() + b"changed")
    watcher.enqueue(str(archive_path), event_type="modified")

    assert _await(watcher.run_once()).succeeded == 1
    assert len(runs) == 2


def test_watch_scheduler_recovers_persisted_pending_input_after_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    archive_path = tmp_path / "sample.zip"
    _write_zip(archive_path)
    state_path = tmp_path / ".sunpack_watch" / "state.json"
    first = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=".",
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=False,
    )
    stat = archive_path.stat()
    first.state.queue_active(
        SimpleNamespace(path=str(archive_path), size=stat.st_size, mtime=stat.st_mtime),
    )
    runs = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            runs.append(list(paths))
            return FakeSummary()

    restarted = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=".",
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    _await(restarted.start())

    assert _await(restarted.run_once()).succeeded == 1
    assert len(runs) == 1
    assert not restarted.state.pending_work_items()
    _await(restarted.stop())


def test_relative_output_directory_is_resolved_per_matching_watch_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    archive_path = second_root / "sample.zip"
    _write_zip(archive_path)
    captured = {}

    class FakePipelineRunner:
        def __init__(self, config):
            captured["output"] = config["output"]
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates={str(self.output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            self.output_dir.mkdir(parents=True)
            return FakeSummary()

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(first_root), str(second_root)],
        out_dir=".",
        state_path=str(first_root / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    watcher.enqueue(str(archive_path))

    result = _await(watcher.run_once())

    assert result.succeeded == 1
    assert Path(captured["output"]["root"]).is_relative_to(second_root)
    assert ".sunpack_watch_probes" in Path(captured["output"]["root"]).parts
    assert captured["output"]["common_root"] == str(second_root.resolve())


def test_watch_scheduler_routes_each_watch_root_to_its_configured_output_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first_out = tmp_path / "out-first"
    second_out = tmp_path / "elsewhere" / "out-second"
    archive_path = second_root / "sample.zip"
    _write_zip(archive_path)
    captured = {}

    class SuccessRunner:
        recent_passwords = []

        def __init__(self, config):
            self.output_dir = Path(config["output"]["root"]) / "sample"
            self.context = SimpleNamespace(flatten_candidates={str(self.output_dir)}, recovered_outputs=[])

        def run_targets(self, paths):
            captured["probe_root"] = self.output_dir
            self.output_dir.mkdir(parents=True)
            (self.output_dir / "payload.bin").write_bytes(b"payload")
            return _watch_summary(paths[0], OutcomeKind.COMPLETE_SUCCESS, {"decision_hint": "accept"})

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(first_root), str(second_root)],
        out_dir=str(tmp_path / "legacy-out"),
        output_roots={
            str(first_root): str(first_out),
            str(second_root): str(second_out),
        },
        state_path=str(first_root / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(SuccessRunner),
    )
    watcher.enqueue(str(archive_path))

    result = _await(watcher.run_once())

    assert result.succeeded == 1
    # Promotion stays a rename: compression runs in the probe workspace below the input root.
    assert captured["probe_root"].is_relative_to(second_root / ".sunpack_watch_probes")
    assert list(second_out.rglob("payload.bin"))
    assert not (tmp_path / "legacy-out").exists()
    assert not list(first_out.rglob("payload.bin"))


def test_watch_root_always_has_a_resolved_output_root(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sub" / "sample.zip"
    archive_path.parent.mkdir()
    _write_zip(archive_path)

    def output_root_for(out_dir, output_roots=None):
        watcher = WatchScheduler(
            {},
            [str(watch_root)],
            out_dir=out_dir,
            output_roots=output_roots,
            state_path=str(tmp_path / "state.json"),
            quiet_seconds=0,
            initial_scan=False,
        )
        return watcher.output_roots[scheduler_module.path_key(str(watch_root.resolve()))]

    # A caller that does not enumerate outputs still gets one absolute output root per watch root.
    assert output_root_for(".") == str(watch_root.resolve())
    assert output_root_for(str(tmp_path / "global-out")) == str((tmp_path / "global-out").resolve())
    # An enumerated output root wins over the process-wide one.
    assert output_root_for(".", {str(watch_root): str(tmp_path / "per-root")}) == str(
        (tmp_path / "per-root").resolve()
    )


def test_watch_scheduler_initial_scan_ignores_nested_archives(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    output_dir = tmp_path / "old"
    output_dir.mkdir()
    nested = output_dir / "nested.zip"
    fresh = tmp_path / "fresh.zip"
    _write_zip(nested)
    _write_zip(fresh)

    state_path = tmp_path / ".sunpack_watch" / "state.json"
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path),
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=True,
    )
    _await(watcher.start())

    ready_names = {Path(candidate.path).name for candidate in watcher._pop_ready(float("inf"))}
    assert ready_names == {"fresh.zip"}

    _await(watcher.stop())


def test_watch_scheduler_does_not_retry_terminal_failure_for_unchanged_event(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    class FailingRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["damaged"],
                failures=[FailureInfo(FailureKind.DAMAGED, "extraction", "damaged")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")

    notifications = CapturingNotificationSink()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FailingRunner),
        notification_sink=notifications,
    )
    watcher.enqueue(str(archive_path))

    result = _await(watcher.run_once())
    watcher.enqueue(str(archive_path))
    unchanged = _await(watcher.run_once())

    assert result.failed == 1
    assert unchanged.processed == 0
    assert watcher.pending_count == 0
    assert not watcher.state.entries
    assert [event[0] for event in notifications.events] == ["submitted", "failed"]


def test_nested_password_failure_notifies_but_keeps_password_blocker(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    class NestedPasswordRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            return _nested_failure_summary(
                Path(paths[0]),
                FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password"),
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "outer.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    notifications = CapturingNotificationSink()
    watcher = WatchScheduler(
        {"cli": {"language": "zh"}, "watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(NestedPasswordRunner),
        notification_sink=notifications,
    )

    watcher.enqueue(str(archive_path))
    result = _await(watcher.run_once())

    entry = next(iter(watcher.state.entries.values()))
    failed_event = next(event for event in notifications.events if event[0] == "failed")
    assert result.failed == 1
    assert entry.status == "failed_password"
    assert entry.failure_payload["blockers"] == ["password"]
    assert entry.failure_payload["details"] == {
        "scope": "nested_archive",
        "reason": "password",
    }
    assert failed_event[2][0].startswith("内层压缩包密码错误：")
    assert not any(event[0] == "suppressed" for event in notifications.events)


def test_nested_missing_volume_notifies_without_missing_volume_blocker(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    class NestedMissingRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            return _nested_failure_summary(
                Path(paths[0]),
                FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing split volume"),
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "outer.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    notifications = CapturingNotificationSink()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(NestedMissingRunner),
        notification_sink=notifications,
    )

    watcher.enqueue(str(archive_path))
    result = _await(watcher.run_once())

    failed_event = next(event for event in notifications.events if event[0] == "failed")
    assert result.failed == 1
    assert not watcher.state.entries
    assert failed_event[2][0].startswith("Nested archive missing volume:")
    assert failed_event[3][0]["details"] == {
        "scope": "nested_archive",
        "reason": "missing_volume",
    }
    assert not any(event[0] == "suppressed" for event in notifications.events)


def test_watch_scheduler_does_not_retry_password_inconclusive_after_password_source_change(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    attempts = {"count": 0}

    class InconclusiveRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts["count"] += 1
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["password or damage is inconclusive"],
                failures=[FailureInfo(
                    FailureKind.PASSWORD_INCONCLUSIVE,
                    "extraction",
                    "password or damage is inconclusive",
                )],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(InconclusiveRunner),
    )
    watcher.enqueue(str(archive_path))
    first = _await(watcher.run_once())
    watcher.notify_password_source_changed("test")
    second = _await(watcher.run_once())

    assert first.failed == 1
    assert second.processed == 0
    assert attempts["count"] == 1
    assert not watcher.state.entries


def test_watch_scheduler_retries_password_failure_after_password_source_change(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    attempts = {"count": 0}

    class PasswordThenSuccessRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts["count"] += 1
            if attempts["count"] == 1:
                return SimpleNamespace(
                    success_count=0,
                    failed_tasks=["wrong password"],
                    failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
                )
            return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")

    notifications = CapturingNotificationSink()
    watcher = WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "password_retry_debounce_seconds": 0,
            }
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(PasswordThenSuccessRunner),
        notification_sink=notifications,
    )
    watcher.enqueue(str(archive_path))
    first = _await(watcher.run_once())
    watcher.enqueue(str(archive_path))

    watcher.notify_password_source_changed("test")
    second = _await(watcher.run_once())

    assert first.failed == 1
    assert second.succeeded == 1
    assert attempts["count"] == 2
    assert not watcher.state.entries
    assert [event[0] for event in notifications.events] == [
        "submitted",
        "suppressed",
        "submitted",
        "succeeded",
    ]


def test_password_retry_wakeup_uses_debounce_deadline_without_pending_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    monotonic_clock = {"value": 100.0}
    monkeypatch.setattr(scheduler_module.time, "monotonic", lambda: monotonic_clock["value"])
    wakeups = []
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    stat = archive_path.stat()
    watcher = WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "password_retry_debounce_seconds": 5,
            }
        },
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        wake_callback=lambda: wakeups.append(monotonic_clock["value"]),
    )
    watcher.state.mark(
        str(archive_path),
        stat.st_size,
        stat.st_mtime,
        status="failed_password",
    )

    watcher.notify_password_source_changed("test")

    assert wakeups == [100.0]
    assert watcher.pending_count == 0
    assert watcher.next_delay_seconds() == 5.0
    monotonic_clock["value"] = 104.75
    assert watcher.next_delay_seconds() == 0.25


def test_idle_scheduler_has_no_polling_deadline(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
    )

    assert watcher.pending_count == 0
    assert watcher.next_delay_seconds() is None


def test_password_retry_bypasses_learned_quiet_for_unchanged_failed_archive(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    attempts = {"count": 0}

    class PasswordThenSuccessRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts["count"] += 1
            if attempts["count"] == 1:
                return SimpleNamespace(
                    success_count=0,
                    failed_tasks=["wrong password"],
                    failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
                )
            return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])

    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    watcher = WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "password_retry_debounce_seconds": 0,
            }
        },
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(PasswordThenSuccessRunner),
    )
    watcher.enqueue(str(archive_path))
    watcher._active_states[str(archive_path)].last_event_at = 0.0
    assert _await(watcher.run_once()).failed == 1
    watcher._quiet_trackers[str(archive_path)].quiet_seconds = 30.0

    watcher.notify_password_source_changed("test")
    retried = _await(watcher.run_once())

    assert retried.succeeded == 1
    assert attempts["count"] == 2
    assert watcher._quiet_trackers[str(archive_path)].quiet_seconds == 30.0


def test_password_retry_preserves_quiet_when_failed_archive_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    class PasswordFailureRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["wrong password"],
                failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
            )

    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    watcher = WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "password_retry_debounce_seconds": 0,
                "cold_start_seconds": 1.0,
                "quiet_min_seconds": 1.25,
            }
        },
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(PasswordFailureRunner),
    )
    watcher.enqueue(str(archive_path))
    watcher._active_states[str(archive_path)].last_event_at = 0.0
    assert _await(watcher.run_once()).failed == 1
    watcher._quiet_trackers[str(archive_path)].quiet_seconds = 30.0
    archive_path.write_bytes(b"PK\x03\x04changed-payload")

    watcher.notify_password_source_changed("test")
    retried = _await(watcher.run_once())

    assert retried.processed == 0
    assert watcher.pending_count == 1
    assert watcher._active_states[str(archive_path)].quiet_seconds >= 30.0


def test_password_retry_debounce_uses_monotonic_clock_when_wall_clock_moves_backward(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    wall_clock = WatchClock(1_000.0)
    wall_clock.install(monkeypatch)
    monotonic_clock = {"value": 100.0}
    monkeypatch.setattr(scheduler_module.time, "monotonic", lambda: monotonic_clock["value"])
    attempts = {"count": 0}

    class PasswordThenSuccessRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts["count"] += 1
            if attempts["count"] == 1:
                return SimpleNamespace(
                    success_count=0,
                    failed_tasks=["wrong password"],
                    failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
                )
            return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    watcher = WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "password_retry_debounce_seconds": 5,
            }
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(PasswordThenSuccessRunner),
    )

    watcher.enqueue(str(archive_path))
    first = _await(watcher.run_once())
    watcher.notify_password_source_changed("test")

    wall_clock.value = 10.0
    monotonic_clock["value"] = 104.9
    before_debounce = _await(watcher.run_once())
    monotonic_clock["value"] = 105.0
    after_debounce = _await(watcher.run_once())

    assert first.failed == 1
    assert before_debounce.processed == 0
    assert after_debounce.succeeded == 1
    assert attempts["count"] == 2


def test_watch_scheduler_defaults_to_user_and_builtin_password_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    monkeypatch.setattr(scheduler_module, "get_builtin_passwords", lambda: ["builtin-secret"])
    captured = []

    class CapturingRunner:
        recent_passwords = []

        def __init__(self, config):
            captured.append(config)

        def run_targets(self, paths):
            return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    state_path = tmp_path / "state.json"
    watcher = WatchScheduler(
        {"user_passwords": ["user-secret"], "watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(CapturingRunner),
    )

    watcher.enqueue(str(archive_path))
    _await(watcher.run_once())

    assert captured[0]["user_passwords"] == ["user-secret"]
    assert captured[0]["builtin_passwords"] == ["builtin-secret"]
    state_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (state_path, watcher.state.journal_path)
        if path.exists()
    )
    assert "user-secret" not in state_text
    assert "builtin-secret" not in state_text


def test_watch_scheduler_clipboard_persistence_refreshes_candidates_and_retries(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    builtin_path = tmp_path / "builtin_passwords.txt"
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    monkeypatch.setattr(clipboard_monitor_module, "read_clipboard_passwords", lambda: ["clipboard-secret"])
    attempts = []

    class ConfigAwareRunner:
        recent_passwords = []

        def __init__(self, config):
            self.config = config

        def run_targets(self, paths):
            candidates = list(self.config.get("builtin_passwords") or [])
            attempts.append(candidates)
            if "clipboard-secret" in candidates:
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["wrong password"],
                failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": True, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(ConfigAwareRunner),
    )
    watcher.enqueue(str(archive_path))
    first = _await(watcher.run_once())

    watcher._clipboard_monitor._handle_clipboard_update()
    generation = watcher.state.password_generation
    scheduler_module._WatchEventHandler(watcher)._handle_path(str(builtin_path), event_type="modified")
    second = _await(watcher.run_once())

    assert first.failed == 1
    assert second.succeeded == 1
    assert "clipboard-secret" not in attempts[0]
    assert "clipboard-secret" in attempts[1]
    assert "clipboard-secret" in builtin_path.read_text(encoding="utf-8")
    assert watcher.state.password_generation == generation


def test_watch_scheduler_retries_on_builtin_password_file_watchdog_event(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    builtin_path = tmp_path / "resources" / "builtin_passwords.txt"
    builtin_path.parent.mkdir()
    builtin_path.write_text("wrong\n", encoding="utf-8")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    builtin_passwords = ["wrong"]
    monkeypatch.setattr(scheduler_module, "get_builtin_passwords", lambda: list(builtin_passwords))
    attempts = []

    class ConfigAwareRunner:
        recent_passwords = []

        def __init__(self, config):
            self.config = config

        def run_targets(self, paths):
            attempts.append(list(self.config.get("builtin_passwords") or []))
            if "new-secret" in self.config.get("builtin_passwords", []):
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["wrong password"],
                failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(ConfigAwareRunner),
    )
    watcher.enqueue(str(archive_path))
    _await(watcher.run_once())

    builtin_passwords.append("new-secret")
    assert _await(watcher.run_once()).processed == 0
    handler = scheduler_module._WatchEventHandler(watcher)
    handler.on_moved(
        SimpleNamespace(
            src_path=str(builtin_path.with_name(".builtin_passwords.txt.tmp")),
            dest_path=str(builtin_path),
            is_directory=False,
        )
    )
    result = _await(watcher.run_once())

    assert result.succeeded == 1
    assert attempts == [["wrong"], ["wrong", "new-secret"]]


def test_watch_scheduler_retries_persisted_password_failure_when_config_passwords_change(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    monkeypatch.setattr(scheduler_module, "get_builtin_passwords", lambda: [])
    attempts = []

    class ConfigAwareRunner:
        recent_passwords = []

        def __init__(self, config):
            self.config = config

        def run_targets(self, paths):
            attempts.append(list(self.config.get("user_passwords") or []))
            if "new-secret" in self.config.get("user_passwords", []):
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["wrong password"],
                failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")
    state_path = tmp_path / "state.json"
    first_watcher = WatchScheduler(
        {"user_passwords": ["wrong"], "watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(ConfigAwareRunner),
    )
    first_watcher.enqueue(str(archive_path))
    _await(first_watcher.run_once())

    second_watcher = WatchScheduler(
        {"user_passwords": ["new-secret"], "watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(state_path),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(ConfigAwareRunner),
    )
    result = _await(second_watcher.run_once())

    assert result.succeeded == 1
    assert attempts == [["wrong"], ["new-secret"]]


def test_watch_scheduler_promotes_recent_success_password_and_retries_other_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    monkeypatch.setattr(scheduler_module, "get_builtin_passwords", lambda: [])
    attempts = []

    class LearningRunner:
        def __init__(self, config):
            self.config = config
            self.recent_passwords = []

        def run_targets(self, paths):
            archive_name = Path(paths[0]).name
            candidates = list(self.config.get("user_passwords") or [])
            attempts.append((archive_name, candidates))
            if archive_name == "teacher.zip":
                self.recent_passwords = ["learned-secret"]
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
            if "learned-secret" in candidates:
                return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["wrong password"],
                failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    failed_archive = watch_root / "failed.zip"
    teacher_archive = watch_root / "teacher.zip"
    failed_archive.write_bytes(b"PK\x03\x04failed")
    teacher_archive.write_bytes(b"PK\x03\x04teacher")
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(LearningRunner),
    )
    watcher.enqueue(str(failed_archive))
    _await(watcher.run_once())
    watcher.enqueue(str(teacher_archive))
    learned = _await(watcher.run_once())
    retried = _await(watcher.run_once())

    assert learned.succeeded == 1
    assert retried.succeeded == 1
    assert attempts == [
        ("failed.zip", []),
        ("teacher.zip", []),
        ("failed.zip", ["learned-secret"]),
    ]


def test_watch_scheduler_password_table_event_retries_password_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    attempts = {"count": 0}

    class PasswordThenSuccessRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            attempts["count"] += 1
            if attempts["count"] == 1:
                return SimpleNamespace(
                    success_count=0,
                    failed_tasks=["password required"],
                    failures=[FailureInfo(FailureKind.PASSWORD_REQUIRED, "password_resolution", "password required")],
                )
            return SimpleNamespace(success_count=1, failed_tasks=[], failures=[])

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    password_table = watch_root / ".sunpack-passwords.txt"
    archive_path.write_bytes(b"PK\x03\x04payload")
    password_table.write_text("secret\n", encoding="utf-8")

    watcher = WatchScheduler(
        {
            "watch": {
                "clipboard_monitor_enabled": False,
                "password_retry_debounce_seconds": 0,
            }
        },
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(PasswordThenSuccessRunner),
    )
    watcher.enqueue(str(archive_path))
    _await(watcher.run_once())

    handler = scheduler_module._WatchEventHandler(watcher)
    handler._handle_path(str(password_table))
    result = _await(watcher.run_once())

    assert result.succeeded == 1
    assert attempts["count"] == 2
    assert not any(path.endswith(".sunpack-passwords.txt") for path in watcher._pending)


def test_watch_scheduler_writes_jsonl_log_for_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    class FailingRunner:
        def __init__(self, config):
            pass

        def run_targets(self, paths):
            return SimpleNamespace(
                success_count=0,
                failed_tasks=["wrong password"],
                failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")],
            )

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / ".sunpack_watch" / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FailingRunner),
    )
    watcher.enqueue(str(archive_path))
    _await(watcher.run_once())

    log_path = tmp_path / ".sunpack_watch" / "events.jsonl"
    text = log_path.read_text(encoding="utf-8")
    assert '"event":"failed_password"' in text
    assert "wrong password" in text


def test_watch_scheduler_silently_ignores_metadata_events(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)

    watch_root = tmp_path
    metadata_dir = tmp_path / ".sunpack_watch"
    metadata_dir.mkdir()
    log_path = metadata_dir / "events.jsonl"
    log_path.write_text("", encoding="utf-8")

    watcher = WatchScheduler(
        {},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(metadata_dir / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
    )

    handler = scheduler_module._WatchEventHandler(watcher)
    handler._handle_path(str(log_path))
    watcher.enqueue(str(log_path))
    handler._handle_path(str(watcher.state.journal_path))
    watcher.enqueue(str(watcher.state.journal_path))

    assert watcher.pending_count == 0
    assert log_path.read_text(encoding="utf-8") == ""


def test_watch_event_handler_keeps_dispatcher_alive_when_native_observation_is_temporarily_blocked():
    ignored = []

    class Scheduler:
        config = {}

        @staticmethod
        def is_builtin_password_file(path):
            return False

        @staticmethod
        def should_ignore_event_path(path):
            return False

        @staticmethod
        def enqueue(path, **kwargs):
            raise OSError(f'native resource registration blocked by promotion: ["{path}"]')

        @staticmethod
        def _log_candidate_ignored(path, reason, **payload):
            ignored.append((path, reason, payload))

    handler = scheduler_module._WatchEventHandler(Scheduler())
    handler._handle_path("sample.7z.001", event_type="modified", src_path="source.tmp")

    assert ignored == [
        (
            "sample.7z.001",
            "observation_error",
            {
                "event_type": "modified",
                "src_path": "source.tmp",
                "error": 'OSError: native resource registration blocked by promotion: ["sample.7z.001"]',
            },
        )
    ]


def test_watch_scheduler_does_not_special_case_downloader_suffixes(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    watch_root = tmp_path / "in"
    watch_root.mkdir()
    temporary = watch_root / "sample.zip.baiduyun.p.downloading"
    temporary.write_bytes(b"PK\x03\x04payload")

    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
    )
    watcher.enqueue(str(temporary), event_type="created")
    watcher.enqueue(str(temporary), event_type="modified")

    assert watcher.pending_count == 1


def test_watch_scheduler_same_stat_same_usn_event_does_not_reset_quiet_window(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    clock = WatchClock(2000010000.0)
    clock.install(monkeypatch)

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    _write_zip(archive_path)
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=10,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    events = WatchEvents(watcher, clock)
    events.emit(archive_path)
    events.emit(archive_path, event_type="modified", after=0.8)

    events.run_after(9.3, processed=1)


def test_modified_epoch_triggers_even_when_size_mtime_and_file_id_are_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    clock = WatchClock(2000020000.0)
    clock.install(monkeypatch)

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"A" * (512 * 1024))
    original_mtime = archive_path.stat().st_mtime
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=10,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    events = WatchEvents(watcher, clock)
    events.emit(archive_path)
    with archive_path.open("r+b") as handle:
        handle.seek(0)
        handle.write(b"B" * 32 * 1024)
    os.utime(archive_path, (original_mtime, original_mtime))
    events.emit(archive_path, event_type="modified")

    events.run_after(9.9, processed=0)
    events.run_after(0.2, processed=1)


def test_watch_scheduler_adapts_quiet_window_to_fast_content_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    clock = WatchClock(2000030000.0)
    clock.install(monkeypatch)
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"0")
    os.utime(archive_path, (clock.value, clock.value))
    watcher = WatchScheduler(
        {"watch": {
            "clipboard_monitor_enabled": False,
            "cold_start_seconds": 1.0,
            "quiet_min_seconds": 1.25,
        }},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
        pipeline_engine=_summary_pipeline_engine(),
    )
    events = WatchEvents(watcher, clock)
    events.emit(archive_path)
    for index in range(20):
        clock.advance(0.5)
        archive_path.write_bytes(bytes([index % 256]) * (index + 2))
        os.utime(archive_path, (clock.value, clock.value))
        events.emit(archive_path, event_type="modified")

    quiet_seconds = WatchState.assert_quiet_seconds(watcher, archive_path, minimum=1.8, maximum=2.0)
    events.run_after(quiet_seconds - 0.01, processed=0)
    events.run_after(0.02, processed=1)


def test_watch_scheduler_default_cold_start_is_zero_seconds(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    clock = WatchClock(2000035000.0)
    clock.install(monkeypatch)
    archive_path = tmp_path / "sample.zip"
    _write_zip(archive_path)
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
        pipeline_engine=_summary_pipeline_engine(),
    )
    events = WatchEvents(watcher, clock)
    events.emit(archive_path)

    assert watcher._active_states[str(archive_path)].quiet_seconds == 0.0
    events.run_after(0.0, processed=1)


def test_watch_scheduler_retains_slow_interval_learning_across_active_epochs(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    clock = WatchClock(2000040000.0)
    clock.install(monkeypatch)
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(b"first")
    os.utime(archive_path, (clock.value, clock.value))
    watcher = WatchScheduler(
        {"watch": {
            "clipboard_monitor_enabled": False,
            "cold_start_seconds": 1.0,
            "quiet_min_seconds": 1.25,
        }},
        [str(tmp_path)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        initial_scan=False,
        pipeline_engine=_summary_pipeline_engine(),
    )
    events = WatchEvents(watcher, clock)
    events.emit(archive_path)

    events.run_after(10.01, processed=1)
    clock.advance(9.99)
    archive_path.write_bytes(b"second")
    os.utime(archive_path, (clock.value, clock.value))
    events.emit(archive_path, event_type="modified")

    WatchState.assert_quiet_seconds(watcher, archive_path, minimum=20.0)
    events.run_after(20.0, processed=0)


def test_modified_event_retries_same_metadata_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(scheduler_module, "Observer", FakeObserver)
    attempts = []

    class FakePipelineRunner:
        def __init__(self, config):
            self.context = SimpleNamespace(flatten_candidates=set(), recovered_outputs=[])

        def run_targets(self, paths):
            attempts.append(list(paths))
            return FakeSummary()

    watch_root = tmp_path / "in"
    watch_root.mkdir()
    archive_path = watch_root / "sample.zip"
    archive_path.write_bytes(b"A" * (256 * 1024))
    original_mtime = archive_path.stat().st_mtime
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False}},
        [str(watch_root)],
        out_dir=str(tmp_path / "out"),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(FakePipelineRunner),
    )
    events = WatchEvents(watcher, WatchClock(0.0))
    events.emit(archive_path, event_type="modified")
    WatchState.assert_processed(_await(events.watcher.run_once()), 1)

    archive_path.write_bytes(b"B" * (256 * 1024))
    os.utime(archive_path, (original_mtime, original_mtime))
    events.emit(archive_path, event_type="modified")
    WatchState.assert_processed(_await(events.watcher.run_once()), 1)
    assert len(attempts) == 2
