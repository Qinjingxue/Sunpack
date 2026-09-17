from __future__ import annotations

import os

from sunpack.contracts.failures import FailureKind, PASSWORD_FAILURE_KINDS
from sunpack.contracts.results import OutcomeKind


def target_results(summary) -> list:
    return list(getattr(summary, "target_results", []) or [])


def result_path(result) -> str:
    if isinstance(result, dict):
        return str(result.get("input_path") or "")
    return str(getattr(result, "input_path", "") or "")


def result_failure(result):
    if isinstance(result, dict):
        return result.get("failure")
    return getattr(result, "failure", None) if result is not None else None


def result_error(result) -> str:
    if isinstance(result, dict):
        return str(result.get("error") or "")
    return str(getattr(result, "error", "") or "") if result is not None else ""


def result_outcome(result) -> OutcomeKind | None:
    raw = result.get("outcome_kind") if isinstance(result, dict) else getattr(result, "outcome_kind", None)
    if isinstance(raw, OutcomeKind):
        return raw
    if not raw:
        return None
    try:
        return OutcomeKind(str(raw))
    except ValueError:
        return None


def failure_contains(failure, kind: FailureKind) -> bool:
    if failure is None:
        return False
    if isinstance(failure, dict):
        raw_kind = failure.get("kind")
        if raw_kind in {kind, kind.value, str(kind)}:
            return True
        return any(failure_contains(cause, kind) for cause in (failure.get("causes") or []))
    contains = getattr(failure, "contains", None)
    if callable(contains):
        try:
            return bool(contains(kind))
        except Exception:
            pass
    return getattr(failure, "kind", None) == kind


def failure_is_password(failure) -> bool:
    if failure is None:
        return False
    if isinstance(failure, dict):
        raw_kind = failure.get("kind")
        try:
            if FailureKind(str(raw_kind)) in PASSWORD_FAILURE_KINDS:
                return True
        except (TypeError, ValueError):
            pass
        return any(failure_is_password(cause) for cause in (failure.get("causes") or []))
    return bool(getattr(failure, "is_password_failure", False))


def is_password_retry_result(result) -> bool:
    failure = result_failure(result)
    return failure_is_password(failure) and not failure_contains(failure, FailureKind.MISSING_VOLUME)


def password_retry_results(summary) -> list:
    return [result for result in target_results(summary) if is_password_retry_result(result)]


def password_retry_paths(summary) -> list[str]:
    paths: dict[str, str] = {}
    for result in password_retry_results(summary):
        path = result_path(result)
        if path:
            paths.setdefault(os.path.normcase(os.path.abspath(path)), path)
    return list(paths.values())


def merge_latest_results(latest: dict[str, object], summary) -> None:
    for result in target_results(summary):
        path = result_path(result)
        if path:
            latest[os.path.normcase(os.path.abspath(path))] = result
