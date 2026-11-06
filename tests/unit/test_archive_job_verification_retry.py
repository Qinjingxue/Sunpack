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
