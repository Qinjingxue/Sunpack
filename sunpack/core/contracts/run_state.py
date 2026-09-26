"""Mutable coordinator state for one pipeline execution."""

import threading
from typing import Any

from sunpack.core.contracts.failures import FailureInfo
from sunpack.core.contracts.results import RunSummary, TargetRunResult


class RunState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.scan_failed_tasks: list[str] = []
        self.scan_failures: list[FailureInfo] = []
        self.processed_keys: set[str] = set()
        self.cleanup_refs: dict[str, Any] = {}
        self.cleanup_results = []
        self.target_results: list[TargetRunResult] = []
        self.policy_skips: list[dict] = []

    def snapshot(
        self,
        *,
        target_results: list[TargetRunResult],
        scan_failed_tasks: list[str],
        scan_failures: list[FailureInfo],
        policy_skips: list[dict],
    ) -> RunSummary:
        return RunSummary(
            target_results=tuple(target_results),
            scan_failed_tasks=tuple(scan_failed_tasks),
            scan_failures=tuple(scan_failures),
            policy_skips=tuple(policy_skips),
            cleanup_results=tuple(self.cleanup_results),
        )
