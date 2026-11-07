from types import SimpleNamespace

import pytest

from sunpack.core.contracts.content_recovery import (
    CONTENT_REQUIREMENT_ALLOW_PARTIAL,
    ContentRecoveryPolicy,
)
from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.verification import (
    DECISION_ACCEPT_PARTIAL,
    DECISION_FAIL,
    DECISION_RETRY_EXTRACT,
    VerificationResult,
)
from sunpack.core.i18n import I18nContext
from sunpack.pipeline.coordinator import archive_job
from sunpack.pipeline.coordinator.archive_job import ArchiveJobExecutor


def _executor(*, allow_partial: bool) -> ArchiveJobExecutor:
    executor = object.__new__(ArchiveJobExecutor)
    executor.verifier = SimpleNamespace(config={})
    executor.content_policy = ContentRecoveryPolicy(
        CONTENT_REQUIREMENT_ALLOW_PARTIAL if allow_partial else "complete"
    )
    executor.progress_reporter = None
    executor.i18n = I18nContext("en")
    return executor


def _finish_first_attempt(executor, task, result):
    state = executor._extract_verify_state_machine(task, result.out_dir)
    request = next(state)
    assert request["task"] is task
    assert request["out_dir"] == result.out_dir
    with pytest.raises(StopIteration) as stopped:
        state.send(result)
    return stopped.value.value


@pytest.mark.parametrize(("decision", "allow_partial"), [
    (DECISION_FAIL, False),
    (DECISION_ACCEPT_PARTIAL, True),
    (DECISION_RETRY_EXTRACT, False),
])
def test_verification_finishes_without_cleanup_or_reextraction(
    monkeypatch, tmp_path, decision, allow_partial,
):
    verification = VerificationResult(decision_hint=decision)
    monkeypatch.setattr(archive_job, "write_extraction_result", lambda _task, _result: None)
    monkeypatch.setattr(archive_job, "verify_and_project", lambda _verifier, _task, _result: verification)
    cleanup_calls = []
    monkeypatch.setattr(
        archive_job,
        "cleanup_output_for_retry",
        lambda *_args, **_kwargs: cleanup_calls.append(True),
    )

    executor = _executor(allow_partial=allow_partial)
    task = SimpleNamespace(runtime={})
    result = ExtractionResult(
        success=True, out_dir=str(tmp_path / "out"), partial_outputs=allow_partial,
    )

    outcome = _finish_first_attempt(executor, task, result)

    assert outcome.result is result
    assert outcome.verification is verification
    assert outcome.attempts == 1
    assert cleanup_calls == []
    if decision == DECISION_RETRY_EXTRACT:
        assert outcome.outcome_kind.value == "failure"


@pytest.mark.parametrize("allow_partial", [False, True])
def test_terminal_policy_is_shared_by_cleanup_report_and_result(tmp_path, monkeypatch, allow_partial):
    """One lifecycle test catches policy bypasses in every terminal consumer.

    Verification-only tests cannot catch raw extraction success being reported
    before policy, repeated decisions, or cleanup seeing a different decision.
    """
    import asyncio
    from sunpack.core.contracts.failures import FailureInfo, FailureKind
    from sunpack.core.contracts.results import OutcomeKind
    from sunpack.core.contracts.run_state import RunState
    from sunpack.core.contracts.verification import DECISION_ACCEPT
    from sunpack.pipeline.coordinator.archive_job import ArchiveJobOutcome
    from tests.helpers.archive_tasks import make_archive_task

    accepted_partial = OutcomeKind.PARTIAL_SUCCESS if allow_partial else OutcomeKind.FAILURE
    cases = (
        # raw success, verification, failure, partial output, retained children,
        # final outcome, force cleanup. No new per-file recovery behavior.
        (True, DECISION_ACCEPT, None, False, 0, OutcomeKind.COMPLETE_SUCCESS, False),
        (True, DECISION_ACCEPT_PARTIAL, None, True, 0, accepted_partial, not allow_partial),
        (False, DECISION_ACCEPT_PARTIAL, FailureKind.DAMAGED, True, 0, accepted_partial, not allow_partial),
        (False, DECISION_ACCEPT_PARTIAL, FailureKind.MISSING_VOLUME, True, 0, accepted_partial, not allow_partial),
        (False, DECISION_ACCEPT_PARTIAL, FailureKind.WRONG_PASSWORD, True, 0, OutcomeKind.FAILURE, not allow_partial),
        (False, DECISION_ACCEPT_PARTIAL, FailureKind.INPUTS_FAILED, True, 1, OutcomeKind.FAILURE, False),
        (True, DECISION_FAIL, None, False, 0, OutcomeKind.FAILURE, False),
        (False, DECISION_ACCEPT, FailureKind.PROCESS_ERROR, False, 0, OutcomeKind.FAILURE, False),
        (False, None, FailureKind.DAMAGED, True, 0, OutcomeKind.FAILURE, not allow_partial),
    )

    class Broker:
        async def run(self, _phase, _file_id, function, *args, **_kwargs):
            return function(*args)

    for success, hint, failure_kind, partial, retained, expected, force_cleanup in cases:
        task = make_archive_task(tmp_path / "source.zip")
        result = ExtractionResult(
            success, str(tmp_path / "output"), partial_outputs=partial,
            failure=FailureInfo(failure_kind, "extract", "failure") if failure_kind else None,
            retained_complete_count=retained,
        )
        verification = VerificationResult(decision_hint=hint) if hint is not None else None
        outcome = ArchiveJobOutcome(result, verification, planned_out_dir=result.out_dir)
        executor = _executor(allow_partial=allow_partial)
        policy = executor.content_policy
        decisions, events = [], []

        def decide(extracted, verified):
            decisions.append((extracted, verified))
            return policy.decide(extracted, verified)

        def cleanup(_out_dir, **kwargs):
            assert len(decisions) == 1
            assert kwargs["force_owned_output_cleanup"] is force_cleanup
            assert kwargs["failed"] is (expected == OutcomeKind.FAILURE)
            events.append("cleanup")
            return SimpleNamespace(to_dict=lambda: {})

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
