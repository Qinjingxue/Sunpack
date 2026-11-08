"""Central policy and guarded execution for managed extraction-output cleanup."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum

from sunpack.core.support.path_keys import case_key
from sunpack.core.support.resource_lifecycle import promotion_barrier, task_walk
from sunpack_native import remove_output_path


LOGGER = logging.getLogger(__name__)


class OutputCleanupEvent(str, Enum):
    """A finite set of reasons for removing extraction-owned output."""

    EXTRACTION_ABORT = "extraction_abort"
    USER_CANCELLED = "user_cancelled"
    EXTRACT_RETRY = "extract_retry"
    VERIFICATION_RETRY = "verification_retry"
    UNRECOVERABLE_FAILURE = "unrecoverable_failure"
    TERMINAL_FAILURE = "terminal_failure"
    POLICY_REJECTED_PARTIAL = "policy_rejected_partial"


@dataclass(frozen=True, slots=True)
class OutputCleanupResult:
    eligible: bool = False
    cleaned: bool = False
    already_absent: bool = False
    reason: str = ""
    payload_file_count: int = 0
    payload_bytes: int = 0
    error: str = ""


class OutputCleanupExecutor:
    """The only component allowed to physically remove managed output paths."""

    @staticmethod
    def remove_tree(path: str) -> None:
        remove_output_path(path, True)

    @staticmethod
    def remove_file(path: str) -> None:
        remove_output_path(path, False)


class OutputCleanupManager:
    """Authorize, apply, and report all extraction-output cleanup operations."""

    def __init__(self, executor: OutputCleanupExecutor | None = None):
        self.executor = executor or OutputCleanupExecutor()

    def cleanup_canonical(
        self,
        path: str,
        *,
        event: OutputCleanupEvent,
        planned_output_dir: str | None = None,
        allow_nonempty: bool | None = None,
        payload_inventory: tuple[int, int] | None = None,
    ) -> OutputCleanupResult:
        planned = _absolute(planned_output_dir or path)
        path = _absolute(path)
        if not path:
            return OutputCleanupResult(reason="empty_path")
        if _is_filesystem_root(path):
            return OutputCleanupResult(reason="filesystem_root_refused")
        if not planned or not _same_path(path, planned):
            return OutputCleanupResult(reason="unowned_output")
        if not os.path.lexists(path):
            return OutputCleanupResult(
                eligible=True,
                already_absent=True,
                reason="already_absent",
            )
        if os.path.islink(path):
            return OutputCleanupResult(reason="symlink_refused")

        if not os.path.isdir(path):
            return OutputCleanupResult(reason="managed_directory_required")

        payload_file_count = 0
        payload_bytes = 0
        if allow_nonempty is None:
            allow_nonempty = event != OutputCleanupEvent.TERMINAL_FAILURE
        if not allow_nonempty:
            # Positive native counts already prove this output must be kept.
            # An empty manifest need not include untracked files or links.
            inventory = payload_inventory
            if inventory is None or inventory[0] <= 0:
                inventory = _payload_inventory(path)
            if inventory is None:
                return OutputCleanupResult(reason="output_inventory_failed")
            payload_file_count, payload_bytes = inventory
            if payload_file_count > 0:
                return OutputCleanupResult(
                    reason="nonempty_payload",
                    payload_file_count=payload_file_count,
                    payload_bytes=payload_bytes,
                )

        try:
            from sunpack.core.support.archive_sessions import release_archive_sessions_under_roots

            with promotion_barrier(
                (path,),
                cache_releasers=(release_archive_sessions_under_roots,),
                # A request can still be extracting sibling archives. The
                # path barrier protects this output without quiescing them.
                quiesce=False,
            ):
                self.executor.remove_tree(path)
        except OSError as exc:
            LOGGER.warning("output cleanup failed event=%s path=%s: %s", event.value, path, exc)
            return OutputCleanupResult(
                eligible=True,
                reason="cleanup_failed",
                error=str(exc),
                payload_file_count=payload_file_count,
                payload_bytes=payload_bytes,
            )
        LOGGER.info("output cleaned event=%s path=%s", event.value, path)
        return OutputCleanupResult(
            eligible=True,
            cleaned=True,
            reason=(
                "policy_rejected_partial_cleaned"
                if event == OutputCleanupEvent.POLICY_REJECTED_PARTIAL
                else "cleaned"
            ),
            payload_file_count=payload_file_count,
            payload_bytes=payload_bytes,
        )


DEFAULT_OUTPUT_CLEANUP_MANAGER = OutputCleanupManager()


def _absolute(path: str) -> str:
    return os.path.abspath(str(path or "")) if path else ""


def _same_path(left: str, right: str) -> bool:
    return case_key(_absolute(left)) == case_key(_absolute(right))


def _is_filesystem_root(path: str) -> bool:
    parent = os.path.dirname(_absolute(path))
    return _same_path(parent, path)


def _payload_inventory(root: str) -> tuple[int, int] | None:
    file_count = 0
    byte_count = 0
    try:
        for current, directories, files in task_walk(
            root,
            followlinks=False,
            onerror=_raise_walk_error,
        ):
            for name in [*directories, *files]:
                path = os.path.join(current, name)
                if not os.path.islink(path):
                    continue
                file_count += 1
                byte_count += max(1, int(os.lstat(path).st_size))
            for name in files:
                path = os.path.join(current, name)
                if os.path.islink(path):
                    continue
                file_count += 1
                byte_count += int(os.stat(path, follow_symlinks=False).st_size)
    except OSError:
        return None
    return file_count, byte_count


def _raise_walk_error(error: OSError) -> None:
    raise error
