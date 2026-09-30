import asyncio
import os
import gc
import weakref
from dataclasses import asdict

import pytest
from sunpack_native import file_generation_tokens

import sunpack.core.support.resource_lifecycle as resource_lifecycle
import sunpack.pipeline.postprocess.internal.cleanup as cleanup
from sunpack.core.contracts.pipeline import PipelineArtifacts
from sunpack.core.contracts.results import OutcomeKind
from sunpack.core.contracts.run_state import RunState
from sunpack.pipeline.coordinator.cleanup_refs import CleanupRefTable
from sunpack.pipeline.coordinator.engine import _SourceCleanup
from sunpack.pipeline.postprocess.actions import PostProcessActions
from tests.helpers.fake_pipeline_engine import _InlineBroker
from sunpack.core.support.path_keys import absolute_path_key


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


def _assert_staged_paths(calls, originals):
    assert len(calls) == len(originals)
    for staged, original in zip(calls, originals):
        assert os.path.dirname(staged) == str(original.parent)
        assert os.path.basename(staged).startswith(".sunpack-cleanup-")
        assert staged != str(original)


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
    _assert_staged_paths(calls, [shared])
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


@pytest.mark.parametrize("success_first", [False, True])
def test_failed_sibling_vetoes_shared_cleanup(tmp_path, success_first):
    shared = str(tmp_path / "carrier.bin")
    table = CleanupRefTable()
    failed = _Task("failed", [shared])
    success = _Task("success", [shared])
    table.register_all([failed, success])
    table.mark_cleanup_eligible(success)

    first, last = (success, failed) if success_first else (failed, success)
    assert table.release(first).should_clean is False
    request = table.release(last)

    assert request.paths == (shared,)
    assert request.should_clean is False
    assert table.count(shared) == 0


def test_source_cleanup_reports_external_lock_without_timed_retry(tmp_path, monkeypatch):
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

    _assert_staged_paths(calls, [source])
    assert len(outcome.failed) == 1
    assert outcome.failed[0].attempts == 1
    assert outcome.failed[0].retryable is True
    assert tuple(scope._context.cleanup_results) == outcome.failed
    assert source.exists()


@pytest.mark.parametrize("mode", ["recycle", "delete"])
@pytest.mark.parametrize("release_kind,success_first", [
    ("failure", True), ("failure", False),
    ("partial", True), ("partial", False), ("sweep", True),
])
def test_shared_cleanup_preserves_unsuccessful_owner_shared_and_exclusive_parts(
    tmp_path, monkeypatch, mode, release_kind, success_first,
):
    shared = tmp_path / "carrier.bin"
    exclusive = tmp_path / "failed-only.002"
    success_only = tmp_path / "success-only.002"
    shared.write_text("shared payload")
    exclusive.write_text("unrecovered payload")
    success_only.write_text("recovered payload")
    monkeypatch.setattr(cleanup, "send2trash", os.remove)
    scope = _scope(mode)
    success = _Task("success", [shared, success_only])
    unsuccessful = _Task("unsuccessful", [shared, exclusive])
    scope.register([success, unsuccessful])

    def release_unsuccessful():
        if release_kind == "sweep":
            return scope.sweep_requests()[0]
        return scope.release_task(
            unsuccessful,
            outcome_kind=(
                OutcomeKind.FAILURE if release_kind == "failure"
                else OutcomeKind.PARTIAL_SUCCESS
            ),
        )

    async def run():
        if success_first:
            first = scope.release_task(success, outcome_kind=OutcomeKind.COMPLETE_SUCCESS)
            second = release_unsuccessful()
        else:
            first = release_unsuccessful()
            second = scope.release_task(success, outcome_kind=OutcomeKind.COMPLETE_SUCCESS)
        return [await scope.apply(request, broker=_InlineBroker()) for request in (first, second)]

    outcomes = asyncio.run(run())
    assert [path for outcome in outcomes for path in outcome.deleted] == [str(success_only)]
    assert set(path for outcome in outcomes for path in outcome.released) == {
        str(shared), str(exclusive), str(success_only),
    }
    assert exclusive.exists()
    assert shared.exists()
    assert not success_only.exists()
    assert scope._table.pending_tasks() == ()


def test_source_cleanup_reports_each_failure_once(tmp_path, monkeypatch):
    inaccessible = tmp_path / "denied.001"
    busy = tmp_path / "busy.002"
    inaccessible.write_text("payload")
    busy.write_text("payload")
    calls = []

    def recycle(target):
        calls.append(target)
        raise denied() if len(calls) == 1 else locked()

    monkeypatch.setattr(cleanup, "send2trash", recycle)
    scope = _scope()
    task = _Task("mixed", [inaccessible, busy])
    scope.register([task])
    outcome = _release_and_apply(scope, task, OutcomeKind.COMPLETE_SUCCESS)

    failures = {item.path: (item.error_code, item.attempts) for item in outcome.failed}
    assert failures == {str(inaccessible): (5, 1), str(busy): (32, 1)}
    assert tuple(scope._context.cleanup_results) == outcome.failed
    _assert_staged_paths(calls, [inaccessible, busy])
    assert inaccessible.exists()
    assert busy.exists()


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

    _assert_staged_paths(calls, [source])
    assert len(outcome.failed) == 1
    assert outcome.failed[0].error_code == 5
    assert outcome.failed[0].attempts == 1


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
    paths = [str(path), str(tmp_path / "missing")]
    report = PostProcessActions(config("delete")).apply(
        archives_to_clean=[paths],
        expected_generations=dict(zip(map(absolute_path_key, paths), file_generation_tokens(paths))),
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


def test_replacement_plan_cleans_added_volumes_and_preserves_rejected_paths(tmp_path):
    first, added, rejected = [tmp_path / name for name in ("a.001", "a.002", "unrelated.bin")]
    for path in (first, added, rejected):
        path.write_text("payload")
    scope = _scope("delete")
    task = _Task("old", [first, rejected])
    scope.register([task])
    task.key = "resolved"
    task.cleanup_parts = [str(first), str(added)]
    # Retry inputs are registered before extraction, including added volumes.
    scope.register([task])

    outcome = _release_and_apply(scope, task, OutcomeKind.COMPLETE_SUCCESS)
    assert set(outcome.deleted) == {str(first), str(added)}
    assert outcome.task_key == "resolved"
    assert rejected.exists()
    assert scope._table.count(str(rejected)) == 0
    assert scope.release_task(task, outcome_kind=OutcomeKind.COMPLETE_SUCCESS).paths == ()


def test_refresh_adds_shared_volume_reference_once(tmp_path):
    first, added = [str(tmp_path / name) for name in ("a.001", "a.002")]
    table = CleanupRefTable()
    retry = _Task("retry", [first])
    sibling = _Task("sibling", [added])
    table.register_all([retry, sibling])
    retry.cleanup_parts.append(added)
    table.register(retry)
    table.register(retry)
    assert table.count(added) == 2
    table.mark_cleanup_eligible(sibling)
    assert table.release(sibling).paths == ()
    table.mark_cleanup_eligible(retry)
    assert set(table.release(retry).cleanup_paths) == {first, added}
    assert table.count(added) == 0


def test_failed_sibling_veto_survives_replacement_plan_and_clears_after_release(tmp_path):
    shared, added = [str(tmp_path / name) for name in ("carrier.bin", "added.002")]
    table = CleanupRefTable()
    failed = _Task("failed", [shared])
    success = _Task("success", [shared])
    table.register_all([failed, success])
    table.release(failed)
    success.cleanup_parts.append(added)
    table.refresh(success)
    table.mark_cleanup_eligible(success)
    request = table.release(success)
    assert set(request.paths) == {shared, added}
    assert request.cleanup_paths == (added,)

    # A subsequent successful retry is a new ownership lifetime.
    table.register(failed)
    table.mark_cleanup_eligible(failed)
    assert table.release(failed).cleanup_paths == (shared,)


@pytest.mark.parametrize("mode", ["delete", "recycle"])
def test_destructive_cleanup_requires_recorded_generations(tmp_path, monkeypatch, mode):
    source = tmp_path / "source.dat"
    source.write_text("preserve")
    monkeypatch.setattr(cleanup, "prepare_file_cleanup", lambda *_args: pytest.fail("must reject before native cleanup"))
    with pytest.raises(ValueError, match="generations recorded before extraction"):
        PostProcessActions(config(mode)).apply(archives_to_clean=[[str(source)]])
    assert source.exists()


def test_plan_reconciliation_drops_abandoned_generations_immediately(tmp_path, monkeypatch):
    import sunpack_native

    monkeypatch.setattr(sunpack_native, "file_generation_tokens", lambda paths: ["snapshot"] * len(paths))
    scope = _scope("delete")
    task = _Task("retry", [tmp_path / "start.001"])
    scope.register([task])
    for index in range(100):
        current = tmp_path / f"part-{index}.001"
        task.cleanup_parts = [str(current)]
        scope.register([task])
        assert scope._table._generations == {absolute_path_key(current): "snapshot"}
        assert len(scope._table._counts) == 1
    scope.sweep_requests()
    assert scope._table._generations == {}
    assert scope._table._counts == {}


def test_reconciled_batch_transfers_generation_to_the_new_owner(tmp_path, monkeypatch):
    import sunpack_native

    batches = []
    def snapshots(paths):
        batches.append(tuple(paths))
        return ["snapshot"] * len(paths)

    monkeypatch.setattr(sunpack_native, "file_generation_tokens", snapshots)
    path, added = tmp_path / "shared.001", tmp_path / "new.002"
    scope = _scope("delete")
    first = _Task("first", [path])
    second = _Task("second", [added])
    scope.register([first, second])
    first.cleanup_parts = [str(added)]
    second.cleanup_parts = [str(path)]
    scope.register([first, second])
    assert len(batches) == 1
    assert scope._table.generation_for(str(path)) == "snapshot"
    scope.release_task(first, outcome_kind=OutcomeKind.FAILURE)
    request = scope.release_task(second, outcome_kind=OutcomeKind.COMPLETE_SUCCESS)
    assert request.generations == ((absolute_path_key(path), "snapshot"),)
    assert scope._table._generations == {}


@pytest.mark.parametrize("terminal", ["success", "failure", "sweep"])
def test_final_release_drops_task_references_and_generation_storage(tmp_path, terminal):
    table = CleanupRefTable()
    path = str(tmp_path / "carrier.dat")
    task = _Task("owner", [path])
    reference = weakref.ref(task)
    table.register(task, generations={absolute_path_key(path): "snapshot"})
    if terminal == "sweep":
        table.sweep()
    else:
        if terminal == "success":
            table.mark_cleanup_eligible(task)
        table.release(task)
    del task
    gc.collect()
    assert reference() is None
    assert table._owned == table._counts == table._generations == {}
    assert table._preserved == set()
