from dataclasses import dataclass
from typing import Any, Dict, List

from sunpack.contracts.run_context import RunContext
from sunpack.coordinator.task_scan import ArchiveTaskScanner
from sunpack.embedded.options import EmbeddedOptions


@dataclass
class ScanResult:
    logical_name: str
    main_path: str
    all_parts: List[str]
    should_extract: bool
    stop_reason: str
    matched_rules: List[str]
    format: str
    discovery_source: str
    archive_input: dict
    decision: str


class ScanOrchestrator:
    def __init__(
        self,
        config: Dict[str, Any],
        detection_options: EmbeddedOptions | None = None,
    ):
        self.task_scanner = ArchiveTaskScanner(
            config,
            RunContext(),
            detection_options=detection_options,
        )

    def scan(self, root_dir: str) -> List[ScanResult]:
        return self.scan_targets([root_dir])

    def scan_targets(self, target_paths: List[str]) -> List[ScanResult]:
        return [
            ScanResult(
                logical_name=task.logical_name,
                main_path=task.main_path,
                all_parts=list(task.all_parts or []),
                should_extract=True,
                stop_reason=task.stop_reason,
                matched_rules=list(task.matched_rules),
                format=task.archive_input().format_hint,
                discovery_source=task.discovery_source,
                archive_input=task.archive_input().to_dict(),
                decision=task.decision,
            )
            for task in self.task_scanner.scan_targets(target_paths)
        ]
