from dataclasses import dataclass, field
from enum import Enum
from typing import List

from sunpack.contracts.failures import FailureInfo


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
    output_dir: str = ""
    verification: dict = field(default_factory=dict)
    error: str = ""
    failure: FailureInfo | None = None


@dataclass
class RunSummary:
    success_count: int
    failed_tasks: List[str]
    processed_keys: List[str]
    partial_success_count: int = 0
    recovered_outputs: List[dict] = field(default_factory=list)
    failures: List[FailureInfo] = field(default_factory=list)
    target_results: List[TargetRunResult] = field(default_factory=list)
    policy_skips: List[dict] = field(default_factory=list)
    cleanup_results: List[ArchiveCleanupResult] = field(default_factory=list)
