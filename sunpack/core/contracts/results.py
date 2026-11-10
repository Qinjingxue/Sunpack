import os
from dataclasses import dataclass, field
from enum import Enum
from typing import List

from sunpack.core.support.path_keys import case_key, path_key_is_under
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.support.filesystem_scan_errors import is_filesystem_scan_failure, filesystem_scan_error_count


class OutcomeKind(str, Enum):
    SCANNED = "scanned"
    COMPLETE_SUCCESS = "complete_success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"


@dataclass(frozen=True)
class ArchiveCleanupResult:
    path: str
    mode: str
    status: str
    error_code: int = 0
    message: str = ""


@dataclass(frozen=True)
class DirectoryFlattenResult:
    path: str
    output_dir: str
    source_dir: str = ""
    moved: int = 0
    removed_dirs: int = 0
    errors: tuple[str, ...] = ()

    def relocate(self, path: str) -> str:
        """Project a recorded output through the native directory rename."""
        if not path or not self.source_dir:
            return path
        candidate = case_key(os.path.abspath(path))
        source = case_key(os.path.abspath(self.source_dir))
        root = case_key(os.path.abspath(self.path))
        try:
            if path_key_is_under(candidate, source):
                relative = os.path.relpath(path, self.source_dir)
                return os.path.normpath(os.path.join(self.output_dir, relative))
            # Removed wrapper directories now refer to the promoted payload root.
            if (self.moved and path_key_is_under(candidate, root)
                    and path_key_is_under(source, candidate)):
                return self.output_dir
        except ValueError:
            pass
        return path


@dataclass(frozen=True)
class TargetRunResult:
    input_path: str
    outcome_kind: OutcomeKind
    task_key: str = ""
    output_dir: str = ""
    verification: dict = field(default_factory=dict)
    error: str = ""
    failure: FailureInfo | None = None
    failure_message: str = ""
    recovery: dict | None = None
    # Sparse CLI facts only; never retain native readers, inventories or tasks.
    scan_items: tuple[dict, ...] = ()


@dataclass(frozen=True)
class RunSummary:
    target_results: tuple[TargetRunResult, ...] = ()
    scan_failures: tuple[FailureInfo, ...] = ()
    policy_skips: tuple[dict, ...] = ()
    cleanup_results: tuple[ArchiveCleanupResult, ...] = ()
    postprocess_completed: bool = False

    def __post_init__(self) -> None:
        for name in ("target_results", "scan_failures", "policy_skips", "cleanup_results"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    @property
    def success_count(self) -> int:
        return sum(item.outcome_kind == OutcomeKind.COMPLETE_SUCCESS for item in self.target_results)

    @property
    def processed_keys(self) -> List[str]:
        return list(dict.fromkeys(item.task_key for item in self.target_results if item.task_key))

    @property
    def partial_success_count(self) -> int:
        return sum(item.outcome_kind == OutcomeKind.PARTIAL_SUCCESS for item in self.target_results)

    @property
    def failed_count(self) -> int:
        return (sum(not is_filesystem_scan_failure(failure) for failure in self.scan_failures)
                + sum(item.outcome_kind == OutcomeKind.FAILURE and (
                    item.failure is None or item.failure.kind != FailureKind.INVALID_INPUT
                ) for item in self.target_results))

    @property
    def input_error_count(self) -> int:
        return sum(item.outcome_kind == OutcomeKind.FAILURE and item.failure is not None
                   and item.failure.kind == FailureKind.INVALID_INPUT for item in self.target_results)

    @property
    def scan_error_count(self) -> int:
        return filesystem_scan_error_count(self.scan_failures)

    @property
    def failed_tasks(self) -> List[str]:
        return [
            *(failure.display_message for failure in self.scan_failures),
            *(item.failure_message or f"{item.input_path} [{item.error}]"
              for item in self.target_results if item.outcome_kind == OutcomeKind.FAILURE),
        ]

    @property
    def failures(self) -> List[FailureInfo]:
        values = list(self.scan_failures)
        for item in self.target_results:
            if item.failure is not None and item.failure not in values:
                values.append(item.failure)
        return values

    @property
    def recovered_outputs(self) -> List[dict]:
        return [item.recovery for item in self.target_results if item.recovery is not None]
