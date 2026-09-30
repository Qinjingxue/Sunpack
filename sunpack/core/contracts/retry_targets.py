from __future__ import annotations

import os

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import OutcomeKind, RunSummary, TargetRunResult


def target_results(summary: RunSummary) -> list[TargetRunResult]:
    return list(summary.target_results)


def result_path(result: TargetRunResult) -> str:
    return result.input_path


def result_failure(result: TargetRunResult | None) -> FailureInfo | None:
    return result.failure if result is not None else None


def result_error(result: TargetRunResult | None) -> str:
    return result.error if result is not None else ""


def result_outcome(result: TargetRunResult | None) -> OutcomeKind | None:
    return result.outcome_kind if result is not None else None


def failure_contains(failure: FailureInfo | None, kind: FailureKind) -> bool:
    return failure is not None and failure.contains(kind)


def failure_is_password(failure: FailureInfo | None) -> bool:
    return failure is not None and failure.is_password_failure


def is_password_retry_result(result: TargetRunResult) -> bool:
    failure = result.failure
    return failure_is_password(failure) and not failure_contains(failure, FailureKind.MISSING_VOLUME)


def password_retry_results(summary: RunSummary) -> list[TargetRunResult]:
    return [result for result in summary.target_results if is_password_retry_result(result)]


def password_retry_paths(summary: RunSummary) -> list[str]:
    paths = {os.path.normcase(os.path.abspath(result.input_path)): result.input_path
             for result in password_retry_results(summary)}
    return list(paths.values())


def merge_latest_results(latest: dict[str, TargetRunResult], summary: RunSummary) -> None:
    for result in summary.target_results:
        latest[os.path.normcase(os.path.abspath(result.input_path))] = result
