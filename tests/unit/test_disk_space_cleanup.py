import asyncio
import os
from dataclasses import asdict

import sunpack.core.support.resource_lifecycle as resource_lifecycle
import sunpack.pipeline.postprocess.internal.cleanup as cleanup
from sunpack.core.contracts.pipeline import PipelineArtifacts
from sunpack.core.contracts.results import OutcomeKind
from sunpack.core.contracts.run_state import RunState
from sunpack.pipeline.coordinator.cleanup_refs import CleanupRefTable
from sunpack.pipeline.coordinator.engine import _SourceCleanup
from sunpack.pipeline.postprocess.actions import PostProcessActions
from tests.helpers.fake_pipeline_engine import _InlineBroker


class _Task:
    def __init__(self, key, paths):
        self.key = key
        self.main_path = key
        self.cleanup_parts = [str(path) for path in paths]
        self.all_parts = [str(path) for path in paths]


def config(mode="recycle"):
    return {
        "post_extract": {
            "archive_cleanup_mode": mode,
            "flatten_single_directory": False,
        }
    }


def locked():
    error = OSError("sharing violation")
    error.winerror = 32
    return error


def denied():
    error = OSError("denied")
    error.winerror = 5
    return error


def _scope(mode="recycle"):
    return _SourceCleanup(
        RunState(),
        config(mode),
        PostProcessActions,
        "request-1",
    )


def _release_and_apply(scope, task, outcome_kind):
    request = scope.release_task(task, outcome_kind=outcome_kind)
    return asyncio.run(scope.apply(request, broker=_InlineBroker()))


def test_shared_source_is_deleted_only_after_last_successful_owner(tmp_path, monkeypatch):
    shared = tmp_path / "carrier.bin"
    shared.write_text("payload")
    calls = []

    def recycle(target):
        calls.append(target)
        os.remove(target)

    monkeypatch.setattr(cleanup, "send2trash", recycle)
    scope = _scope()
    first = _Task("a", [shared])
    second = _Task("b", [shared])
    scope.register([first, second])

    first_request = scope.release_task(first, outcome_kind=OutcomeKind.COMPLETE_SUCCESS)
    assert first_request.paths == ()
    assert shared.exists()

    second_outcome = asyncio.run(
        scope.apply(
            scope.release_task(second, outcome_kind=OutcomeKind.COMPLETE_SUCCESS),
            broker=_InlineBroker(),
        )
    )

    assert second_outcome.deleted == (str(shared),)
    assert calls == [str(shared)]
    assert not shared.exists()


def test_failed_owner_releases_reference_without_deleting_source(tmp_path, monkeypatch):
    source = tmp_path / "broken.zip"
    source.write_text("payload")
    calls = []
    monkeypatch.setattr(cleanup, "send2trash", calls.append)
    scope = _scope()
    task = _Task("broken", [source])
    scope.register([task])

    outcome = _release_and_apply(scope, task, OutcomeKind.FAILURE)

    assert outcome.deleted == ()
    assert calls == []
    assert source.exists()


def test_successful_owner_can_request_shared_cleanup_after_failed_sibling(tmp_path):
    shared = str(tmp_path / "carrier.bin")
    table = CleanupRefTable()
    failed = _Task("failed", [shared])
    success = _Task("success", [shared])
    table.register_all([failed, success])
    table.mark_cleanup_eligible(success)

    assert table.release(failed).should_clean is False
    request = table.release(success)

    assert request.paths == (shared,)
    assert request.should_clean is True
    assert table.count(shared) == 0


def test_source_cleanup_retry_is_local_to_cleanup_side_task(tmp_path, monkeypatch):
    source = tmp_path / "busy.zip"
    source.write_text("payload")
    calls = []

    def fail(target):
        calls.append(target)
        raise locked()

    monkeypatch.setattr(cleanup, "send2trash", fail)
    scope = _scope()
    task = _Task("busy", [source])
    scope.register([task])

    outcome = _release_and_apply(scope, task, OutcomeKind.COMPLETE_SUCCESS)

    assert calls == [str(source)] * 3
    assert len(outcome.failed) == 1
    assert outcome.failed[0].attempts == 3
    assert outcome.failed[0].retryable is True
    assert source.exists()


def test_source_cleanup_stops_retrying_nonretryable_failure(tmp_path, monkeypatch):
    source = tmp_path / "denied.zip"
    source.write_text("payload")
    calls = []

    def fail(target):
        calls.append(target)
        raise denied()

    monkeypatch.setattr(cleanup, "send2trash", fail)
    scope = _scope()
    task = _Task("denied", [source])
    scope.register([task])

    outcome = _release_and_apply(scope, task, OutcomeKind.COMPLETE_SUCCESS)

    assert calls == [str(source)]
    assert len(outcome.failed) == 1
    assert outcome.failed[0].error_code == 5
    assert outcome.failed[0].attempts == 1


def test_source_cleanup_retry_can_succeed_without_request_finalizer(tmp_path, monkeypatch):
    source = tmp_path / "retry.zip"
    source.write_text("payload")
    calls = []

    def recycle(target):
        calls.append(target)
        if len(calls) == 1:
            raise locked()
        os.remove(target)

    monkeypatch.setattr(cleanup, "send2trash", recycle)
    scope = _scope()
    task = _Task("retry", [source])
    scope.register([task])

    outcome = _release_and_apply(scope, task, OutcomeKind.COMPLETE_SUCCESS)

    assert calls == [str(source), str(source)]
    assert outcome.deleted == (str(source),)
    assert outcome.failed == ()
    assert not source.exists()


def test_keep_mode_never_enters_source_promotion_barrier(tmp_path, monkeypatch):
    source = tmp_path / "kept.zip"
    source.write_text("payload")

    def exploding_barrier(*_args, **_kwargs):
        raise AssertionError("keep cleanup must not establish a promotion barrier")

    monkeypatch.setattr(resource_lifecycle, "promotion_barrier", exploding_barrier)
    scope = _scope("keep")
    task = _Task("keep", [source])
    scope.register([task])

    outcome = _release_and_apply(scope, task, OutcomeKind.COMPLETE_SUCCESS)

    assert outcome.failed == ()
    assert source.exists()


def test_sweep_only_releases_unreported_refs_and_does_not_request_deletion(tmp_path):
    shared = tmp_path / "carrier.bin"
    table = CleanupRefTable()
    task = _Task("cancelled", [shared])
    table.register(task)

    requests = table.sweep()

    assert [request.paths for request in requests] == [(str(shared),)]
    assert requests[0].should_clean is False
    assert table.pending_tasks() == ()


def test_native_delete_reports_missing_and_deleted(tmp_path):
    path = tmp_path / "a.zip"
    path.write_text("data")
    report = PostProcessActions(config("delete")).apply(
        archives_to_clean=[[str(path), str(tmp_path / "missing")]]
    )
    assert {item.status for item in report} == {"deleted", "missing"}
    assert not path.exists()


def test_pipeline_artifacts_public_schema_has_no_flatten_queue():
    assert set(asdict(PipelineArtifacts()).keys()) == {"shell_refresh_paths"}


def test_cleanup_result_public_schema_is_stable():
    result = cleanup.ArchiveCleanupResult(
        "archive.zip",
        "recycle",
        "failed",
        error_code=32,
    )
    assert result.retryable
    assert set(asdict(result)) == {
        "path",
        "mode",
        "status",
        "attempts",
        "error_code",
        "message",
    }
