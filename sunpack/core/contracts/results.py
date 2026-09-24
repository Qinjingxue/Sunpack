from dataclasses import dataclass, field
from enum import Enum
from typing import List

from sunpack.core.contracts.failures import FailureInfo


class OutcomeKind(str, Enum):
    COMPLETE_SUCCESS = "complete_success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"


@dataclass(frozen=True)
class ArchiveCleanupResult:
    path: str
    mode: str
    status: str
    attempts: int = 1
    error_code: int = 0
    message: str = ""

    @property
    def retryable(self) -> bool:
        return self.status == "failed" and self.error_code in {32, 33}


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


@dataclass(frozen=True)
class RunSummary:
    target_results: tuple[TargetRunResult, ...] = ()
    scan_failed_tasks: tuple[str, ...] = ()
    scan_failures: tuple[FailureInfo, ...] = ()
    policy_skips: tuple[dict, ...] = ()
    cleanup_results: tuple[ArchiveCleanupResult, ...] = ()
    postprocess_completed: bool = False

    def __post_init__(self) -> None:
        for name in ("target_results", "scan_failed_tasks", "scan_failures", "policy_skips", "cleanup_results"):
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
    def failed_tasks(self) -> List[str]:
        return [
            *self.scan_failed_tasks,
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
