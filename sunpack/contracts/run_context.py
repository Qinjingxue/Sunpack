import threading
from typing import Any, Dict, List, Set

from sunpack.contracts.failures import FailureInfo
from sunpack.contracts.results import TargetRunResult


class RunContext:
    def __init__(self):
        self.lock = threading.Lock()
        self.success_count: int = 0
        self.partial_success_count: int = 0
        self.failed_tasks: List[str] = []
        self.failures: List[FailureInfo] = []
        self.recovered_outputs: List[dict] = []
        self.processed_keys: Set[str] = set()
        self.cleanup_refs: Dict[str, Any] = {}
        self.flatten_candidates: Set[str] = set()
        self.target_results: List[TargetRunResult] = []
        self.policy_skips: List[dict] = []
