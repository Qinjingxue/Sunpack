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
    VerificationResult,
)
from sunpack.core.i18n import I18nContext
from sunpack.pipeline.coordinator import archive_job
from sunpack.pipeline.coordinator.archive_job import ArchiveJobExecutor


def _executor(*, allow_partial: bool, retry_on_failure: bool) -> ArchiveJobExecutor:
    executor = object.__new__(ArchiveJobExecutor)
    executor.verifier = SimpleNamespace(
        config={
            "max_retries": 2,
            "cleanup_failed_output": True,
            "retry_on_verification_failure": retry_on_failure,
        }
    )
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


def test_disabled_verification_retry_preserves_real_failed_verification(monkeypatch, tmp_path):
    verification = VerificationResult(decision_hint=DECISION_FAIL)
    monkeypatch.setattr(archive_job, "write_extraction_result", lambda _task, _result: None)
    monkeypatch.setattr(archive_job, "verify_and_project", lambda _verifier, _task, _result: verification)
    cleanup_calls = []
    monkeypatch.setattr(
        archive_job,
        "cleanup_output_for_retry",
        lambda *_args, **_kwargs: cleanup_calls.append(True),
    )

    executor = _executor(allow_partial=False, retry_on_failure=False)
    task = SimpleNamespace(runtime={})
    result = ExtractionResult(success=True, out_dir=str(tmp_path / "out"))

    outcome = _finish_first_attempt(executor, task, result)

    assert outcome.result is result
    assert outcome.verification is verification
    assert outcome.attempts == 1
    assert cleanup_calls == []


def test_allowed_partial_verification_is_not_reextracted(monkeypatch, tmp_path):
    verification = VerificationResult(decision_hint=DECISION_ACCEPT_PARTIAL)
    monkeypatch.setattr(archive_job, "write_extraction_result", lambda _task, _result: None)
    monkeypatch.setattr(archive_job, "verify_and_project", lambda _verifier, _task, _result: verification)
    cleanup_calls = []
    monkeypatch.setattr(
        archive_job,
        "cleanup_output_for_retry",
        lambda *_args, **_kwargs: cleanup_calls.append(True),
    )

    executor = _executor(allow_partial=True, retry_on_failure=True)
    task = SimpleNamespace(runtime={})
    result = ExtractionResult(
        success=True,
        out_dir=str(tmp_path / "out"),
        partial_outputs=True,
    )

    outcome = _finish_first_attempt(executor, task, result)

    assert outcome.result is result
    assert outcome.verification is verification
    assert outcome.attempts == 1
    assert cleanup_calls == []
