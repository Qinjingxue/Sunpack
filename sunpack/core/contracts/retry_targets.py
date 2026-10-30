from __future__ import annotations

import os
from dataclasses import replace

from sunpack.core.support.path_keys import case_key, path_key
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
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
    paths = {case_key(os.path.abspath(result.input_path)): result.input_path
             for result in password_retry_results(summary)}
    return list(paths.values())


def password_retry_failures(summary: RunSummary) -> dict[str, FailureInfo]:
    """Request-local continuations; Watch persists the same failure payload."""
    return {path_key(result.input_path): result.failure
            for result in password_retry_results(summary)
            if result.failure.details.get("retry_generation")}


def _input_key(value: dict) -> tuple:
    descriptor = ArchiveInputDescriptor.from_dict(value)
    extents = descriptor.extents or [part.extent for part in descriptor.parts]
    return (descriptor.open_mode, descriptor.format_hint, descriptor.volume_style,
            tuple((path_key(item.path), item.start, item.end) for item in extents))


def apply_password_retry(task, failure: FailureInfo | None, generation: tuple) -> None:
    """Narrow the canonical discovery plan only for unchanged physical inputs.

    Keep unrelated failures, not successful results or native inventories. An
    old record without a continuation follows ordinary discovery unchanged.
    """
    if failure is None or not generation:
        return
    previous = failure.details.get("retry_generation") or ()
    if tuple(tuple(row) for row in previous) != generation:
        return
    causes = failure.causes
    if not causes or any(not cause.details.get("retry_input") for cause in causes):
        return
    wanted = {_input_key(cause.details["retry_input"]) for cause in causes
              if cause.is_password_failure and not cause.contains(FailureKind.MISSING_VOLUME)}
    if not wanted:
        return
    segments = task.knowledge().get("source.extractable_segments", ())
    selected = []
    matched = set()
    for segment in segments:
        key = _input_key(segment["archive_input"])
        if key in wanted:
            selected.append(segment)
            matched.add(key)
    if matched != wanted:
        return
    from sunpack.core.support.archive_input_projection import write_source_extractable_segments

    write_source_extractable_segments(task, selected)
    task.runtime["password_retry_other_failures"] = tuple(
        cause for cause in causes if not cause.is_password_failure
        or cause.contains(FailureKind.MISSING_VOLUME)
    )
    task.runtime["password_retry_segment_count"] = failure.details["segment_count"]
    output_dir = failure.details.get("retry_output_dir")
    if output_dir:
        task.runtime["retry_output_dir"] = output_dir


def remap_retry_failure(failure: FailureInfo, path_map: dict[str, str], generation: tuple) -> FailureInfo:
    """Promotion renames the source without changing its logical ranges."""
    if not failure.details.get("retry_generation"):
        return failure
    mapping = {path_key(old): new for old, new in path_map.items()}
    causes = []
    for cause in failure.causes:
        descriptor = cause.details.get("retry_input")
        if descriptor:
            descriptor = ArchiveInputDescriptor.from_dict(descriptor).with_path_mapping(
                lambda path: mapping.get(path_key(path), path))
            cause = replace(cause, details={**cause.details, "retry_input": descriptor.to_dict()})
        causes.append(cause)
    return replace(failure, causes=tuple(causes),
                   details={**failure.details, "retry_generation": generation})


def merge_latest_results(latest: dict[str, TargetRunResult], summary: RunSummary) -> None:
    for result in summary.target_results:
        latest[case_key(os.path.abspath(result.input_path))] = result
