import asyncio
import os

import sunpack.filesystem.watcher.scheduler as scheduler_module
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse
from sunpack.contracts.results import OutcomeKind, RunSummary, TargetRunResult
from sunpack.filesystem.watcher.scanner import WatchCandidate
from sunpack.filesystem.watcher.scheduler import WatchScheduler, _ActivePipelineRequest
from tests.helpers.fake_pipeline_engine import FakePipelineEngine


class _Sink:
    def __init__(self):
        self.actions = []

    def submitted(self, *args):
        self.actions.append(("submitted", args))

    def progress(self, *args):
        pass

    def succeeded(self, *args):
        self.actions.append(("succeeded", args))

    def failed(self, *args):
        self.actions.append(("failed", args))

    def suppressed(self, *args):
        self.actions.append(("suppressed", args))

    def aborted(self, *args):
        self.actions.append(("aborted", args))


class _Runner:
    def __init__(self, _config):
        pass

    def run_targets(self, _paths):
        return RunSummary(1, [], [])


def _candidate(path):
    stat = os.stat(path)
    return WatchCandidate(str(path), stat.st_size, stat.st_mtime)


def _watcher(tmp_path, monkeypatch):
    root = tmp_path / "in"
    output = tmp_path / "out"
    root.mkdir()
    output.mkdir()
    monkeypatch.setattr(scheduler_module, "validate_ntfs_watch_roots", lambda _roots: None)
    sink = _Sink()
    watcher = WatchScheduler(
        {"watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0}},
        [str(root)],
        output_roots={str(root): str(output)},
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=FakePipelineEngine(_Runner),
        notification_sink=sink,
    )
    monkeypatch.setattr(
        scheduler_module,
        "_candidate_for_event_path",
        lambda path, since_usn=0: _candidate(path) if os.path.isfile(path) else None,
    )
    return watcher, root, output, sink


async def _complete(watcher, candidate, response):
    async def done():
        return response

    request = _ActivePipelineRequest(
        notification_id="request",
        candidate=candidate,
        group=None,
        task=asyncio.create_task(done()),
    )
    return await watcher._complete_candidate(request)


def _response(direct, nested=None):
    results = [direct, *([nested] if nested is not None else [])]
    failures = [item.failure for item in results if item.failure is not None]
    failed_tasks = [
        f"{os.path.basename(item.input_path)} [{item.error or item.failure.message}]"
        for item in results
        if item.failure is not None
    ]
    return PipelineResponse(
        "request",
        RunSummary(
            success_count=sum(item.outcome_kind == OutcomeKind.COMPLETE_SUCCESS for item in results),
            failed_tasks=failed_tasks,
            processed_keys=[],
            partial_success_count=sum(item.outcome_kind == OutcomeKind.PARTIAL_SUCCESS for item in results),
            failures=failures,
            target_results=results,
        ),
        PipelineArtifacts(),
    )


def test_generated_password_failure_is_anchored_to_failed_task(tmp_path, monkeypatch):
    watcher, root, output, sink = _watcher(tmp_path, monkeypatch)
    outer = root / "outer.zip"
    inner_dir = output / "outer"
    inner_dir.mkdir()
    inner = inner_dir / "inner.zip"
    outer.write_bytes(b"outer")
    inner.write_bytes(b"inner")
    failure = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")
    response = _response(
        TargetRunResult(str(outer), OutcomeKind.COMPLETE_SUCCESS, output_dir=str(inner_dir)),
        TargetRunResult(str(inner), OutcomeKind.FAILURE, error="wrong password", failure=failure),
    )
    result = asyncio.run(_complete(watcher, _candidate(outer), response))

    assert result.failed == 1
    assert watcher.state.latest_entry_for_path(str(outer)) is None
    entry = watcher.state.latest_entry_for_path(str(inner))
    assert entry is not None and entry.status == "failed_password"
    assert entry.password_scope_dir == str(root.resolve())
    assert [action for action, _ in sink.actions] == ["suppressed"]

    watcher.enqueue(
        str(inner),
        force=True,
        event_type="password_retry",
        _password_retry_snapshot=entry,
    )
    assert watcher.pending_count == 1
    assert watcher._output_root_for(str(inner)) == str(output.resolve())


def test_password_retry_can_advance_to_the_next_generated_task(tmp_path, monkeypatch):
    watcher, root, output, sink = _watcher(tmp_path, monkeypatch)
    second_dir = output / "outer"
    second_dir.mkdir()
    second = second_dir / "second.zip"
    third = second_dir / "third.zip"
    second.write_bytes(b"second")
    third.write_bytes(b"third")
    second_candidate = _candidate(second)
    watcher.state.mark(
        str(second),
        second_candidate.size,
        second_candidate.mtime,
        status="failed_password",
        error="wrong password",
        failure_payload={
            "kind": "wrong_password",
            "blockers": ["password"],
            "password_scope_dir": str(root),
        },
    )
    failure = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")
    response = _response(
        TargetRunResult(str(second), OutcomeKind.COMPLETE_SUCCESS),
        TargetRunResult(str(third), OutcomeKind.FAILURE, error="wrong password", failure=failure),
    )
    result = asyncio.run(_complete(watcher, second_candidate, response))

    assert result.failed == 1
    assert watcher.state.latest_entry_for_path(str(second)) is None
    entry = watcher.state.latest_entry_for_path(str(third))
    assert entry is not None and entry.status == "failed_password"
    assert entry.password_scope_dir == str(root.resolve())
    assert [action for action, _ in sink.actions] == ["suppressed"]


def test_generated_missing_volume_is_terminal_and_not_suspended(tmp_path, monkeypatch):
    watcher, root, output, sink = _watcher(tmp_path, monkeypatch)
    outer = root / "outer.zip"
    inner_dir = output / "outer"
    inner_dir.mkdir()
    inner = inner_dir / "inner.7z.001"
    outer.write_bytes(b"outer")
    inner.write_bytes(b"inner")
    failure = FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing inner volume")
    response = _response(
        TargetRunResult(str(outer), OutcomeKind.COMPLETE_SUCCESS),
        TargetRunResult(str(inner), OutcomeKind.FAILURE, error="missing inner volume", failure=failure),
    )
    result = asyncio.run(_complete(watcher, _candidate(outer), response))

    assert result.failed == 1
    assert watcher.state.latest_entry_for_path(str(outer)) is None
    assert watcher.state.latest_entry_for_path(str(inner)) is None
    assert [action for action, _ in sink.actions] == ["failed"]


def test_direct_missing_volume_still_suspends_watch_input(tmp_path, monkeypatch):
    watcher, root, _output, sink = _watcher(tmp_path, monkeypatch)
    archive = root / "direct.7z.001"
    archive.write_bytes(b"part")
    failure = FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing volume")
    response = _response(
        TargetRunResult(str(archive), OutcomeKind.FAILURE, error="missing volume", failure=failure)
    )
    result = asyncio.run(_complete(watcher, _candidate(archive), response))

    assert result.failed == 1
    entry = watcher.state.latest_entry_for_path(str(archive))
    assert entry is not None and entry.status == "suspended_missing_volume"
    assert [action for action, _ in sink.actions] == ["suppressed"]
