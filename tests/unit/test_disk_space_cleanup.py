import asyncio
from dataclasses import asdict

import pytest

from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse
from sunpack.contracts.results import RunSummary
from sunpack.coordinator.engine import DirectOutputCommitter, MappedOutputCommitter
from sunpack.postprocess.actions import PostProcessActions
import sunpack.postprocess.internal.cleanup as cleanup
from tests.helpers.fake_pipeline_engine import _InlineBroker


def response_for(paths):
    return PipelineResponse('cleanup-test', RunSummary(1, [], []),
                            PipelineArtifacts(archives_to_clean=tuple((str(p),) for p in paths)))


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


def test_retry_only_failed_members_and_report_success(tmp_path, monkeypatch):
    first, second = tmp_path/'a.zip', tmp_path/'b.zip'
    first.write_text('a'); second.write_text('b')
    calls = []
    def recycle(path):
        calls.append(path)
        if path == str(second) and calls.count(path) < 3:
            raise locked()
    monkeypatch.setattr(cleanup, 'send2trash', recycle)
    response = asyncio.run(DirectOutputCommitter(_InlineBroker()).commit(config(), response_for([first, first, second])))
    assert calls.count(str(first)) == 1 and calls.count(str(second)) == 3
    assert sorted(r.attempts for r in response.summary.cleanup_results) == [1, 3]
    assert all(r.status == 'recycled' for r in response.summary.cleanup_results)
    assert response.summary.success_count == 1 and not response.summary.failed_tasks
    assert not response.artifacts.archives_to_clean


def test_failed_cleanup_is_bounded_and_repeat_commit_is_idempotent(tmp_path, monkeypatch):
    path = tmp_path/'a.zip'; path.write_text('a')
    calls = []
    def fail(path):
        calls.append(path)
        raise locked()
    monkeypatch.setattr(cleanup, 'send2trash', fail)
    original = response_for([path]); committer = DirectOutputCommitter(_InlineBroker())
    response = asyncio.run(committer.commit(config(), original))
    assert response.summary.cleanup_results[0].attempts == 3
    assert response.artifacts.archives_to_clean == ((str(path),),)
    asyncio.run(committer.commit(config(), original))
    assert len(calls) == 3
    assert response.summary.success_count == 1


def test_mapped_commit_reports_real_path_and_permanent_error_once(tmp_path, monkeypatch):
    original = tmp_path/'old.zip'; promoted = tmp_path/'promoted.zip'; promoted.write_text('data')
    def fail(path):
        error = OSError('denied'); error.winerror = 5; raise error
    monkeypatch.setattr(cleanup, 'send2trash', fail)
    response = asyncio.run(MappedOutputCommitter(_InlineBroker(), {str(original):str(promoted)}).commit(config(),response_for([original])))
    item = response.summary.cleanup_results[0]
    assert item.path == str(promoted) and item.attempts == 1 and item.error_code == 5
    assert response.artifacts.archives_to_clean == ((str(promoted),),)


def test_cancel_during_backoff_never_starts_new_cleanup(tmp_path, monkeypatch):
    path = tmp_path/'a.zip'; path.write_text('data'); calls=[]
    def fail(path):
        calls.append(path); raise locked()
    monkeypatch.setattr(cleanup, 'send2trash', fail)
    async def run():
        task = asyncio.create_task(DirectOutputCommitter(_InlineBroker()).commit(config(),response_for([path])))
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(run())
    assert len(calls) == 1


def test_native_delete_reports_missing_and_deleted(tmp_path):
    path=tmp_path/'a.zip'; path.write_text('data')
    report=PostProcessActions(config('delete')).apply(archives_to_clean=[[str(path),str(tmp_path/'missing')]])
    assert {r.status for r in report} == {'deleted','missing'} and not path.exists()


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
