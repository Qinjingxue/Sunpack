from types import SimpleNamespace

import pytest

from sunpack.pipeline.coordinator.content_recovery import (
    CONTENT_REQUIREMENT_ALLOW_PARTIAL,
    ContentRecoveryPolicy,
)
from sunpack.core.contracts.extraction import ExtractionResult, InputExecutionResult
from sunpack.core.i18n import I18nContext
from sunpack.pipeline.coordinator import archive_job
from sunpack.pipeline.coordinator.archive_job import ArchiveJobExecutor


def _executor(*, allow_partial: bool) -> ArchiveJobExecutor:
    executor = object.__new__(ArchiveJobExecutor)
    executor.scanning = False
    executor.content_policy = ContentRecoveryPolicy(
        CONTENT_REQUIREMENT_ALLOW_PARTIAL if allow_partial else "complete"
    )
    executor.progress_reporter = None
    executor.i18n = I18nContext("en")
    return executor


def _finish_first_attempt(executor, task, result):
    state = executor._extract_state_machine(task, result.out_dir)
    request = next(state)
    assert request["task"] is task
    assert request["out_dir"] == result.out_dir
    with pytest.raises(StopIteration) as stopped:
        state.send(result)
    return stopped.value.value


@pytest.mark.parametrize("allow_partial", [False, True])
def test_terminal_policy_is_shared_by_cleanup_report_and_result(tmp_path, monkeypatch, allow_partial):
    """One lifecycle test catches policy bypasses in every terminal consumer.

    Worker-only tests cannot catch extraction success being reported
    before policy, repeated decisions, or cleanup seeing a different decision.
    """
    import asyncio
    from sunpack.core.contracts.failures import FailureInfo, FailureKind
    from sunpack.core.contracts.results import OutcomeKind
    from sunpack.core.contracts.run_state import RunState
    from sunpack.pipeline.coordinator.archive_job import ArchiveJobOutcome
    from tests.helpers.archive_tasks import make_archive_task

    accepted_partial = OutcomeKind.PARTIAL_SUCCESS if allow_partial else OutcomeKind.FAILURE
    cases = (
        # worker success, failure, completed members, partial bytes, retained inputs,
        # final outcome, force cleanup
        (True, None, 0, False, 0, OutcomeKind.COMPLETE_SUCCESS, False),
        (True, None, 1, False, 0, OutcomeKind.COMPLETE_SUCCESS, False),
        (False, FailureKind.DAMAGED, 1, True, 0, accepted_partial, not allow_partial),
        (False, FailureKind.MISSING_VOLUME, 1, True, 0, accepted_partial, not allow_partial),
        (False, FailureKind.DAMAGED, 0, True, 0, OutcomeKind.FAILURE, not allow_partial),
        (False, FailureKind.WRONG_PASSWORD, 1, True, 0, OutcomeKind.FAILURE, not allow_partial),
        (False, FailureKind.PASSWORD_INCONCLUSIVE, 1, True, 0, OutcomeKind.FAILURE, not allow_partial),
        (False, FailureKind.FILESYSTEM_ERROR, 1, True, 0, OutcomeKind.FAILURE, not allow_partial),
        (False, FailureKind.INPUTS_FAILED, 1, True, 1, OutcomeKind.FAILURE, False),
        (False, FailureKind.PROCESS_ERROR, 1, False, 0, OutcomeKind.FAILURE, False),
    )

    class Broker:
        async def run(self, _phase, _file_id, function, *args, **_kwargs):
            return function(*args)

    for success, failure_kind, complete, partial, retained, expected, force_cleanup in cases:
        task = make_archive_task(tmp_path / "source.zip")
        result = ExtractionResult(
            success, str(tmp_path / "output"), partial_outputs=partial,
            failure=FailureInfo(failure_kind, "extract", "failure") if failure_kind else None,
            input_results=[InputExecutionResult(None, ExtractionResult(True, "retained"), retained=True)] if retained else [],
            progress_manifest_payload=SimpleNamespace(worker_status="failed", summary={"complete": complete}),
        )
        outcome = ArchiveJobOutcome(result, planned_out_dir=result.out_dir)
        executor = _executor(allow_partial=allow_partial)
        policy = executor.content_policy
        decisions, events = [], []

        def decide(extracted):
            decisions.append(extracted)
            return policy.decide(extracted)

        def cleanup(_out_dir, **kwargs):
            assert len(decisions) == 1
            assert kwargs["force_owned_output_cleanup"] is force_cleanup
            assert kwargs["failed"] is (expected == OutcomeKind.FAILURE and not retained)
            events.append("cleanup")
            return SimpleNamespace(cleaned=False, to_dict=lambda: {})

        def reported(_task, finalized, _depth):
            assert events == ["cleanup"]
            assert finalized.outcome_kind == expected
            assert finalized.policy_rejected_partial_output is force_cleanup
            events.append("reported")

        async def extracted(*_args, **_kwargs):
            return task, outcome

        monkeypatch.setattr(archive_job, "cleanup_failed_output_if_eligible", cleanup)
        executor.content_policy = SimpleNamespace(decide=decide)
        executor.context = RunState()
        executor.origin, executor.request_id = "foreground", "policy-test"
        executor._uncommitted_outputs = {}
        executor.password_scope_context = SimpleNamespace(remember=lambda *_args: None)
        executor.progress_reporter = SimpleNamespace(task_finished=reported)
        executor._execute_one_async = extracted
        _, finalized, returned = asyncio.run(executor.execute_async(
            task, depth=1, output_dir_resolver=None, broker=Broker(), cancellation=None,
        ))
        assert events == ["cleanup", "reported"]
        assert len(decisions) == 1
        assert returned.outcome_kind == finalized.outcome_kind == expected
        if expected == OutcomeKind.FAILURE:
            assert returned.failure_message
        else:
            assert returned.failure_message == ""
        assert executor.context.target_results == [returned]


def test_worker_result_finishes_once_and_retry_requires_clean_output(tmp_path, monkeypatch):
    from sunpack.core.contracts.failures import FailureInfo, FailureKind
    from tests.helpers.archive_tasks import make_archive_task
    from sunpack.pipeline.postprocess.output_cleanup import OutputCleanupResult

    monkeypatch.setattr(archive_job, "write_extraction_result", lambda *_args: None)
    executor = _executor(allow_partial=False)
    task = make_archive_task(tmp_path / "source")
    success = ExtractionResult(True, str(tmp_path / "out"))
    assert _finish_first_attempt(executor, task, success).result is success
    failed = ExtractionResult(False, success.out_dir,
        failure=FailureInfo(FailureKind.MISSING_VOLUME, "extract", "missing"))
    monkeypatch.setattr(archive_job.DEFAULT_OUTPUT_CLEANUP_MANAGER, "cleanup_canonical",
                        lambda *_args, **_kwargs: OutputCleanupResult(error="locked"))
    state = executor._extract_state_machine(task, success.out_dir,
        missing_volume_retry=lambda *_args: make_archive_task(tmp_path / "replacement"))
    next(state)
    with pytest.raises(StopIteration) as stopped:
        state.send(failed)
    assert stopped.value.value.result is failed
    assert task.main_path.endswith("source")
