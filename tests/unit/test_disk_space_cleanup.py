import asyncio
import os
from dataclasses import asdict

import pytest

import sunpack.coordinator.engine as engine_module
import sunpack.support.resource_lifecycle as resource_lifecycle
from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse
from sunpack.contracts.results import ArchiveCleanupResult, OutcomeKind, RunSummary
from sunpack.contracts.run_context import RunContext
from sunpack.coordinator.cleanup_refs import CleanupRefTable
from sunpack.coordinator.engine import DirectOutputCommitter, MappedOutputCommitter, _CleanupRefScope
from sunpack.postprocess.actions import PostProcessActions
import sunpack.postprocess.internal.cleanup as cleanup
from tests.helpers.fake_pipeline_engine import _InlineBroker


class _Task:
    def __init__(self, key, paths):
        self.key = key
        self.main_path = key
        self.cleanup_parts = list(paths)
        self.all_parts = list(paths)
        self.result = None


def response_for(paths=None):
    return PipelineResponse('cleanup-test', RunSummary(1, [], []), PipelineArtifacts())


def config(mode='recycle'):
    return {
        'post_extract': {
            'archive_cleanup_mode': mode,
            'flatten_single_directory': False,
        }
    }


def locked():
    error = OSError('sharing violation')
    error.winerror = 32
    return error


def failed_result(path, error_code=32):
    return ArchiveCleanupResult(str(path), 'recycle', 'failed', 1, error_code, 'sharing violation')


def _scope(mode='recycle'):
    context = RunContext()
    return _CleanupRefScope(context, config(mode), engine_module.PostProcessActions).bind('request-1')


# reference counting


def test_last_owner_deletes_and_failed_owner_never_does(tmp_path):
    shared = str(tmp_path / 'carrier.png')
    table = CleanupRefTable()
    first, second = _Task('a.zip', [shared]), _Task('b.zip', [shared])
    table.register_all([first, second])

    table.mark_cleanup_eligible(first)
    assert table.release(first).paths == ()

    table.mark_cleanup_eligible(second)
    request = table.release(second)
    assert request.paths == (shared,)
    assert request.should_clean is True
    assert table.count(shared) == 0


def test_failed_owner_releases_but_never_requests_deletion(tmp_path):
    shared = str(tmp_path / 'carrier.png')
    table = CleanupRefTable()
    failing = _Task('a.zip', [shared])
    table.register(failing)

    request = table.release(failing)
    assert request.paths == (shared,)
    assert request.should_clean is False


def test_success_survives_a_failed_owner_releasing_first(tmp_path):
    shared = str(tmp_path / 'carrier.png')
    table = CleanupRefTable()
    failing, succeeding = _Task('a.zip', [shared]), _Task('b.zip', [shared])
    table.register_all([failing, succeeding])
    table.mark_cleanup_eligible(succeeding)

    assert table.release(failing).should_clean is False
    request = table.release(succeeding)
    assert request.paths == (shared,)
    assert request.should_clean is True


def test_sweep_releases_unreported_owners(tmp_path):
    shared = str(tmp_path / 'carrier.png')
    table = CleanupRefTable()
    cancelled = _Task('a.zip', [shared])
    table.register(cancelled)

    requests = table.sweep()
    assert [request.paths for request in requests] == [(shared,)]
    assert requests[0].should_clean is False
    assert table.pending_tasks() == ()
    assert table.sweep() == []


def test_registration_is_idempotent_per_task(tmp_path):
    shared = str(tmp_path / 'carrier.png')
    table = CleanupRefTable()
    task = _Task('a.zip', [shared])
    table.register(task)
    table.register(task)
    assert table.count(shared) == 1


# task level scope


def test_scope_cleans_when_the_last_owner_finishes(tmp_path, monkeypatch):
    shared = tmp_path / 'carrier.png'
    shared.write_text('payload')
    calls = []

    def recycle(target):
        calls.append(target)
        os.remove(target)

    monkeypatch.setattr(cleanup, 'send2trash', recycle)
    scope = _scope()
    first, second = _Task('a.zip', [shared]), _Task('b.zip', [shared])
    scope.register([first, second])

    async def run():
        broker = _InlineBroker()
        first_outcome = await scope.release_task(
            first, outcome_kind=OutcomeKind.COMPLETE_SUCCESS, broker=broker)
        assert shared.exists() is True
        second_outcome = await scope.release_task(
            second, outcome_kind=OutcomeKind.COMPLETE_SUCCESS, broker=broker)
        return first_outcome, second_outcome

    first_outcome, second_outcome = asyncio.run(run())

    assert first_outcome.deleted == ()
    assert second_outcome.deleted == (str(shared),)
    assert calls == [str(shared)]
    assert shared.exists() is False


def test_scope_keeps_source_of_a_failed_task(tmp_path, monkeypatch):
    source = tmp_path / 'broken.zip'
    source.write_text('payload')
    calls = []
    monkeypatch.setattr(cleanup, 'send2trash', calls.append)
    scope = _scope()
    task = _Task('broken.zip', [source])
    scope.register([task])

    outcome = asyncio.run(scope.release_task(
        task, outcome_kind=OutcomeKind.FAILURE, broker=_InlineBroker()))

    assert outcome.deleted == ()
    assert calls == []
    assert source.exists() is True


def test_scope_barrier_failure_is_recorded_for_retry(tmp_path, monkeypatch):
    source = tmp_path / 'a.zip'
    source.write_text('payload')
    scope = _scope()
    task = _Task('a.zip', [source])
    scope.register([task])

    def exploding_barrier(*_args, **_kwargs):
        raise resource_lifecycle.ResourceBusyError(
            'timed out waiting for an overlapping promotion barrier')

    monkeypatch.setattr(resource_lifecycle, 'promotion_barrier', exploding_barrier)

    outcome = asyncio.run(scope.release_task(
        task, outcome_kind=OutcomeKind.COMPLETE_SUCCESS, broker=_InlineBroker()))

    assert outcome.deleted == ()
    assert len(outcome.failed) == 1
    assert outcome.failed[0].status == 'failed'
    assert outcome.failed[0].retryable is True
    assert 'barrier' in outcome.failed[0].message
    assert source.exists() is True


def test_scope_keep_skips_cleanup_promotion_barrier(tmp_path, monkeypatch):
    source = tmp_path / 'kept.zip'
    source.write_text('payload')
    scope = _scope('keep')
    task = _Task('kept.zip', [source])
    scope.register([task])

    def exploding_barrier(*_args, **_kwargs):
        raise AssertionError('keep cleanup must not establish a promotion barrier')

    monkeypatch.setattr(resource_lifecycle, 'promotion_barrier', exploding_barrier)

    outcome = asyncio.run(scope.release_task(
        task, outcome_kind=OutcomeKind.COMPLETE_SUCCESS, broker=_InlineBroker()))

    assert outcome.released == (str(source),)
    assert outcome.deleted == ()
    assert outcome.failed == ()
    assert outcome.error == ''
    assert source.exists() is True


# request level retry


class _RecordingBroker:
    """Runs finalize for real but records which retry payload it was handed."""

    def __init__(self):
        self.calls = []
        self.responses = []

    async def run(self, _stage, _file_id, operation, *args, **kwargs):
        kwargs.pop("request_id", None)
        kwargs.pop("cancellation", None)
        kwargs.pop("origin", None)
        kwargs.pop("stdout", None)
        self.calls.append(kwargs.get("retry_results"))
        result = operation(*args, **kwargs)
        self.responses.append(result)
        return result


def test_committer_retries_only_the_failed_leftovers(tmp_path, monkeypatch):
    first_path, second_path = tmp_path / 'a.zip', tmp_path / 'b.zip'
    first_path.write_text('a')
    second_path.write_text('b')
    first, second = failed_result(first_path), failed_result(second_path)

    def fail(target):
        raise locked()

    monkeypatch.setattr(cleanup, 'send2trash', fail)
    response = PipelineResponse('cleanup-retry', RunSummary(1, [], []), PipelineArtifacts())
    response.summary.cleanup_results = [first, second]
    broker = _RecordingBroker()

    asyncio.run(DirectOutputCommitter(broker).commit(config(), response))

    # First pass has no retry payload, then two passes carrying the two failures.
    assert [None if call is None else len(call) for call in broker.calls] == [None, 2, 2]
    final = broker.responses[-1].summary.cleanup_results
    assert sorted(item.attempts for item in final) == [3, 3]


def test_committer_skips_the_retry_pass_when_nothing_is_retryable(tmp_path, monkeypatch):
    path = tmp_path / 'a.zip'
    path.write_text('a')

    def deny(_target):
        error = OSError('denied')
        error.winerror = 5
        raise error

    monkeypatch.setattr(cleanup, 'send2trash', deny)
    response = PipelineResponse('cleanup-retry', RunSummary(1, [], []), PipelineArtifacts())
    response.summary.cleanup_results = [failed_result(path, error_code=5)]
    broker = _RecordingBroker()

    asyncio.run(DirectOutputCommitter(broker).commit(config(), response))

    assert broker.calls == [None]


def test_committer_stops_retrying_once_the_attempt_budget_is_spent(tmp_path, monkeypatch):
    path = tmp_path / 'a.zip'
    path.write_text('a')

    def fail(_target):
        raise locked()

    monkeypatch.setattr(cleanup, 'send2trash', fail)
    exhausted = ArchiveCleanupResult(str(path), 'recycle', 'failed', 3, 32, 'busy')
    response = PipelineResponse('cleanup-retry', RunSummary(1, [], []), PipelineArtifacts())
    response.summary.cleanup_results = [exhausted]
    broker = _RecordingBroker()

    asyncio.run(DirectOutputCommitter(broker).commit(config(), response))

    assert broker.calls == [None]


def test_retry_pass_deletes_the_failed_leftover(tmp_path, monkeypatch):
    path = tmp_path / 'a.zip'
    path.write_text('a')
    calls = []

    def recycle(target):
        calls.append(target)
        os.remove(target)

    monkeypatch.setattr(cleanup, 'send2trash', recycle)
    response = response_for()
    response.summary.cleanup_results = [failed_result(path)]

    response = asyncio.run(DirectOutputCommitter(_InlineBroker()).commit(config(), response))

    assert calls == [str(path)]
    assert [item.attempts for item in response.summary.cleanup_results] == [2]
    assert response.summary.cleanup_results[0].status == 'recycled'


def test_failed_cleanup_is_bounded_and_repeat_commit_is_idempotent(tmp_path, monkeypatch):
    path = tmp_path / 'a.zip'
    path.write_text('a')
    calls = []

    def fail(target):
        calls.append(target)
        raise locked()

    monkeypatch.setattr(cleanup, 'send2trash', fail)
    committer = DirectOutputCommitter(_InlineBroker())

    def fresh_response():
        response = response_for()
        response.summary.cleanup_results = [failed_result(path)]
        return response

    response = asyncio.run(committer.commit(config(), fresh_response()))
    assert response.summary.cleanup_results[0].attempts == 3
    assert len(calls) == 2

    asyncio.run(committer.commit(config(), response))
    assert len(calls) == 2
    assert response.summary.success_count == 1


def test_mapped_commit_leaves_cleanup_alone(tmp_path, monkeypatch):
    """Cleanup travels through the summary rather than artifacts: a mapped commit is a no-op."""

    probe_dir = tmp_path / 'probe'
    probe_dir.mkdir()
    promoted = tmp_path / 'promoted.zip'
    promoted.write_text('data')
    calls = []

    def deny(target):
        calls.append(target)

    monkeypatch.setattr(cleanup, 'send2trash', deny)
    response = asyncio.run(
        MappedOutputCommitter(_InlineBroker(), {str(probe_dir): str(tmp_path)}).commit(
            config(), response_for()
        )
    )
    assert calls == []
    assert response.summary.cleanup_results == []
    assert set(asdict(PipelineArtifacts()).keys()) == {'flatten_targets', 'shell_refresh_paths'}


def test_retry_only_touches_the_failed_leftovers(tmp_path, monkeypatch):
    """A retry must never re-clean archives the per-task pass already removed."""

    first_path, second_path = tmp_path / 'a.zip', tmp_path / 'b.zip'
    first_path.write_text('a')
    second_path.write_text('b')
    calls = []

    def fail(target):
        calls.append(target)
        raise locked()

    monkeypatch.setattr(cleanup, 'send2trash', fail)
    response = PipelineResponse('cleanup-retry', RunSummary(1, [], []), PipelineArtifacts())
    response.summary.cleanup_results = [failed_result(second_path)]
    broker = _RecordingBroker()

    asyncio.run(DirectOutputCommitter(broker).commit(config(), response))

    assert set(calls) == {str(second_path)}
    assert str(first_path) not in calls
    assert [len(call) for call in broker.calls if call] == [1, 1]


# unrelated pipeline contracts


def test_native_delete_reports_missing_and_deleted(tmp_path):
    path = tmp_path / 'a.zip'
    path.write_text('data')
    report = PostProcessActions(config('delete')).apply(
        archives_to_clean=[[str(path), str(tmp_path / 'missing')]])
    assert {r.status for r in report} == {'deleted', 'missing'} and not path.exists()


def test_cleanup_result_public_schema_is_stable():
    result = cleanup.ArchiveCleanupResult(
        'archive.zip',
        'recycle',
        'failed',
        error_code=32,
    )
    assert result.retryable
    assert set(asdict(result)) == {
        'path', 'mode', 'status', 'attempts', 'error_code', 'message'
    }
