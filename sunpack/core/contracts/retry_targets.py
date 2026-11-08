from __future__ import annotations

import os
from dataclasses import replace

from sunpack.core.support.path_keys import case_key, path_key
from sunpack.core.contracts.input_plan import InputRecovery, recovery_blockers
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import RunSummary, TargetRunResult


def failure_contains(failure: FailureInfo | None, kind: FailureKind) -> bool:
    return failure is not None and (failure.contains(kind) or (
        kind == FailureKind.MISSING_VOLUME and "missing_volume" in recovery_blockers(failure)))


def failure_is_password(failure: FailureInfo | None) -> bool:
    return failure is not None and failure.is_password_failure


def is_password_retry_result(result: TargetRunResult) -> bool:
    failure = result.failure
    if failure is not None and failure.details.get("input_recovery"):
        return "password" in recovery_blockers(failure)
    return failure_is_password(failure) and not failure_contains(failure, FailureKind.MISSING_VOLUME)


def password_retry_results(summary: RunSummary) -> list[TargetRunResult]:
    return [result for result in summary.target_results if is_password_retry_result(result)]


def password_retry_paths(summary: RunSummary) -> list[str]:
    paths = {case_key(os.path.abspath(result.input_path)): result.input_path
             for result in password_retry_results(summary)}
    return list(paths.values())


def password_retry_failures(summary: RunSummary) -> dict[str, FailureInfo]:
    """Request-local continuations; Watch persists the same failure payload."""
    return {path_key(result.input_path): result.failure
            for result in password_retry_results(summary)
            if result.failure.details.get("input_recovery")}


def apply_input_retry(task, failure: FailureInfo | None, generation: tuple, *, password_changed: bool = True) -> None:
    recovery = InputRecovery.from_failure(failure)
    if not recovery.checkpoints or not generation:
        return
    previous = task.inputs
    selected, recovery = recovery.select(previous, generation, password_changed=password_changed)
    task.set_inputs(selected)
    task.recovery = recovery
    task.release_unused_sources(path for node in previous if node.descriptor.volume_attempts
                                for path in node.source_paths)
    if recovery.output_dir:
        task.runtime["retry_output_dir"] = recovery.output_dir


def remap_retry_failure(failure: FailureInfo, path_map: dict[str, str], generation: tuple) -> FailureInfo:
    recovery = InputRecovery.from_failure(failure)
    if not recovery.checkpoints:
        return failure
    mapping = {path_key(old): new for old, new in path_map.items()}
    recovery = recovery.remap(lambda path: mapping.get(path_key(path), path), generation)
    return replace(failure, details={**failure.details, "input_recovery": recovery.to_dict()})


def merge_latest_results(latest: dict[str, TargetRunResult], summary: RunSummary) -> None:
    for result in summary.target_results:
        latest[case_key(os.path.abspath(result.input_path))] = result
