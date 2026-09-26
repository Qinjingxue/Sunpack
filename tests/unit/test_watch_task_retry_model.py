import asyncio
import os

import sunpack.runtime.watch.scheduler as scheduler_module
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.pipeline import PipelineArtifacts, PipelineDiscovery, PipelineResponse
from sunpack.core.contracts.results import OutcomeKind, RunSummary, TargetRunResult
from sunpack.runtime.watch.scanner import WatchCandidate
from sunpack.runtime.watch.scheduler import WatchScheduler, _ActivePipelineRequest
from sunpack.runtime.watch.roots import WatchRootEntry
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
        return RunSummary(target_results=[TargetRunResult('archive.zip', OutcomeKind.COMPLETE_SUCCESS)])


def _candidate(path):
    stat = os.stat(path)
    return WatchCandidate(str(path), stat.st_size, stat.st_mtime)


def _watcher(tmp_path, monkeypatch, *, deep_detect=False):
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
        root_entries=[WatchRootEntry(str(root), str(output), deep_detect)],
        state_path=str(tmp_path / "state.json"),
        cold_start_seconds=0,
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
        task=asyncio.create_task(done()),
        source_input_root=watcher._source_input_root_for(candidate.path),
    )
    return await watcher._complete_candidate(request)


def _response(direct, nested=None):
    results = [direct, *([nested] if nested is not None else [])]
    return PipelineResponse(
        "request",
        RunSummary(target_results=results),
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
            "source_input_root": str(root),
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


def test_shared_output_password_retry_keeps_original_input_detection_mode(tmp_path, monkeypatch):
    async def scenario():
        watcher, root, output, _sink = _watcher(tmp_path, monkeypatch, deep_detect=True)
        ordinary_root = tmp_path / "ordinary"
        ordinary_root.mkdir()
        watcher.watch_roots.append(str(ordinary_root))
        watcher.root_entries[scheduler_module.path_key(str(ordinary_root))] = WatchRootEntry(
            str(ordinary_root), str(output), False,
        )
        watcher.output_roots[scheduler_module.path_key(str(ordinary_root))] = str(output)
        outer = root / "outer.bin"
        ordinary = ordinary_root / "ordinary.bin"
        inner = output / "outer" / "inner.bin"
        inner.parent.mkdir()
        for path in (outer, ordinary, inner):
            path.write_bytes(b"payload")
        failure = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")
        await _complete(watcher, _candidate(outer), _response(
            TargetRunResult(str(outer), OutcomeKind.COMPLETE_SUCCESS),
            TargetRunResult(str(inner), OutcomeKind.FAILURE, failure=failure),
        ))
        entry = watcher.state.latest_entry_for_path(str(inner))
        assert entry.source_input_root == str(root)
        watcher.enqueue(str(inner), force=True, event_type="password_retry", _password_retry_snapshot=entry)
        assert watcher.state.pending_work_for_path(str(inner)).source_input_root == str(root)

        # Restart reads both pending provenance and the blocker from native persistence.
        watcher.state = scheduler_module.WatchStateStore(str(watcher.state.path))
        captured = []

        async def run(_targets, **kwargs):
            captured.append(kwargs)
            return PipelineResponse("request", RunSummary(), PipelineArtifacts())

        watcher.pipeline_engine.run = run
        for path in (inner, ordinary):
            request = await watcher._submit_candidate(_candidate(path))
            assert request is not None
            await request.task
        assert [item["detection_options"].force_scan for item in captured] == [True, False]
        assert captured[0]["request_config"]["filesystem"]["scan_filters_enabled"] is False
        assert "filesystem" not in watcher.config

    asyncio.run(scenario())


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


def test_coalesced_password_retry_preserves_blocker_until_owner_finishes(tmp_path, monkeypatch):
    watcher, root, _output, sink = _watcher(tmp_path, monkeypatch)
    archive = root / "archive.part1.rar"
    archive.write_bytes(b"rar")
    candidate = _candidate(archive)
    watcher.state.mark(
        str(archive),
        candidate.size,
        candidate.mtime,
        status="failed_password",
        error="wrong password",
        failure_payload={
            "kind": "wrong_password",
            "blockers": ["password"],
            "password_scope_dir": str(root),
        },
    )

    response = PipelineResponse(
        "retry",
        RunSummary(),
        PipelineArtifacts(),
        PipelineDiscovery(
            entry_paths=(str(archive),),
            claimed_paths=(str(archive),),
            coalesced_from_request_id="owner-request",
        ),
    )
    result = asyncio.run(_complete(watcher, candidate, response))

    assert result.processed == 1
    entry = watcher.state.latest_entry_for_path(str(archive))
    assert entry is not None and entry.status == "failed_password"
    assert [action for action, _ in sink.actions] == ["suppressed"]
