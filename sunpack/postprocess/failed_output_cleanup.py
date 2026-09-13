from __future__ import annotations

import os
from dataclasses import asdict, dataclass

from sunpack.support.output_cleanup import DEFAULT_OUTPUT_CLEANUP_MANAGER, OutputCleanupEvent


@dataclass(frozen=True)
class FailedOutputCleanupResult:
    cleaned: bool = False
    eligible: bool = False
    reason: str = ""
    output_dir: str = ""
    payload_file_count: int = 0
    payload_bytes: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def cleanup_failed_output_if_eligible(
    output_dir: str,
    *,
    planned_output_dir: str,
    failed: bool,
    force_owned_output_cleanup: bool = False,
) -> FailedOutputCleanupResult:
    """Apply the postprocess cleanup policy to a terminal extraction output."""
    path = os.path.abspath(str(output_dir or "")) if output_dir else ""
    planned = os.path.abspath(str(planned_output_dir or "")) if planned_output_dir else ""
    if not failed:
        return FailedOutputCleanupResult(reason="task_not_failed", output_dir=path)
    if not path or not planned or os.path.normcase(path) != os.path.normcase(planned):
        return FailedOutputCleanupResult(reason="unowned_output_dir", output_dir=path)
    cleanup = DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_canonical(
        path,
        event=(
            OutputCleanupEvent.POLICY_REJECTED_PARTIAL
            if force_owned_output_cleanup
            else OutputCleanupEvent.TERMINAL_FAILURE
        ),
        planned_output_dir=planned,
        allow_nonempty=force_owned_output_cleanup,
    )
    reason = cleanup.reason
    if reason in {
        "already_absent",
        "filesystem_root_refused",
        "symlink_refused",
        "managed_directory_required",
    }:
        reason = "output_dir_missing_or_unsafe"
    elif reason == "unowned_output":
        reason = "unowned_output_dir"
    elif reason == "cleanup_failed":
        reason = f"cleanup_failed: {cleanup.error}"
    return FailedOutputCleanupResult(
        cleaned=cleanup.cleaned,
        eligible=cleanup.eligible,
        reason=reason,
        output_dir=path,
        payload_file_count=cleanup.payload_file_count,
        payload_bytes=cleanup.payload_bytes,
    )
