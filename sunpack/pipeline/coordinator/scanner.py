from dataclasses import dataclass
from typing import Any, Dict, List

from sunpack.core.contracts.run_state import RunState
from sunpack.pipeline.coordinator.task_scan import ArchiveTaskScanner
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions


@dataclass
class ScanResult:
    logical_name: str
    main_path: str
    all_parts: List[str]
    format: str
    discovery_source: str
    discovery_reason: str
    archive_input: dict


class ScanOrchestrator:
    def __init__(
        self,
        config: Dict[str, Any],
        detection_options: EmbeddedOptions | None = None,
    ):
        self.task_scanner = ArchiveTaskScanner(
            config,
            RunState(),
            detection_options=detection_options,
        )

    def scan(self, root_dir: str) -> List[ScanResult]:
        return self.scan_targets([root_dir])

    def scan_targets(self, target_paths: List[str]) -> List[ScanResult]:
        return [
            ScanResult(
                logical_name=task.logical_name,
                main_path=task.main_path,
                all_parts=list(task.all_parts),
                format=task.archive_input().format_hint,
                discovery_source=task.discovery_source,
                discovery_reason=task.discovery_reason,
                archive_input=task.archive_input().to_dict(),
            )
            for task in self.task_scanner.scan_targets(target_paths)
        ]
