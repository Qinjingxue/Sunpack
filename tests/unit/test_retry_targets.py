from pathlib import Path

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import OutcomeKind, RunSummary, TargetRunResult
from sunpack.core.contracts.retry_targets import merge_latest_results, password_retry_paths, result_outcome


def _summary(*results):
    failures = [item.failure for item in results if item.failure is not None]
    return RunSummary(
        success_count=sum(item.outcome_kind == OutcomeKind.COMPLETE_SUCCESS for item in results),
        failed_tasks=[item.error for item in results if item.failure is not None],
        processed_keys=[],
        failures=failures,
        target_results=list(results),
    )


def test_password_retry_paths_are_task_scoped(tmp_path):
    outer = tmp_path / "outer.zip"
    inner = tmp_path / "inner.zip"
    failure = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")
    summary = _summary(
        TargetRunResult(str(outer), OutcomeKind.COMPLETE_SUCCESS),
        TargetRunResult(str(inner), OutcomeKind.FAILURE, error="wrong password", failure=failure),
    )
    assert password_retry_paths(summary) == [str(inner)]


def test_missing_volume_is_never_a_password_retry_target(tmp_path):
    archive = tmp_path / "inner.7z.001"
    failure = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction",
        "missing volume and password",
        causes=(FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password"),),
    )
    summary = _summary(
        TargetRunResult(str(archive), OutcomeKind.FAILURE, error="missing volume", failure=failure)
    )
    assert password_retry_paths(summary) == []


def test_latest_result_ledger_keeps_unrelated_terminal_failure(tmp_path):
    outer = tmp_path / "outer.zip"
    password_archive = tmp_path / "password.zip"
    missing_archive = tmp_path / "missing.7z.001"
    password = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "wrong password")
    missing = FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "missing volume")
    first = _summary(
        TargetRunResult(str(outer), OutcomeKind.COMPLETE_SUCCESS),
        TargetRunResult(str(password_archive), OutcomeKind.FAILURE, error="wrong password", failure=password),
        TargetRunResult(str(missing_archive), OutcomeKind.FAILURE, error="missing volume", failure=missing),
    )
    second = _summary(TargetRunResult(str(password_archive), OutcomeKind.COMPLETE_SUCCESS))
    latest = {}
    merge_latest_results(latest, first)
    merge_latest_results(latest, second)
    outcomes = {Path(item.input_path).name: result_outcome(item) for item in latest.values()}
    assert outcomes == {
        "outer.zip": OutcomeKind.COMPLETE_SUCCESS,
        "password.zip": OutcomeKind.COMPLETE_SUCCESS,
        "missing.7z.001": OutcomeKind.FAILURE,
    }
