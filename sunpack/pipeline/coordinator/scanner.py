from dataclasses import dataclass
from typing import Any, Dict, List

from sunpack.core.contracts.discovery import DiscoveryFinding
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


@dataclass
class ScanReport:
    tasks: List[ScanResult]
    findings: List[DiscoveryFinding]


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
            _scan_result_from_task(task)
            for task in self.task_scanner.scan_targets(target_paths)
        ]

    def scan_report(self, target_paths: List[str]) -> ScanReport:
        """Return executable tasks plus archive identities observed during discovery.

        Resolved findings are projected lazily from ArchiveTask state so normal
        extraction/watch discovery does not allocate a parallel object graph.
        Findings carried by StageResult exist only when no ArchiveTask can
        represent the observation, such as a password-blocked embedded archive.
        """

        discovered = self.task_scanner.scan_stage_result(target_paths)
        tasks = self.task_scanner.filter_processed_tasks(discovered.resolved_tasks)
        findings = [
            finding
            for task in tasks
            for finding in _findings_from_task(task)
        ]
        findings.extend(discovered.findings)
        return ScanReport(
            tasks=[_scan_result_from_task(task) for task in tasks],
            findings=findings,
        )


def _scan_result_from_task(task) -> ScanResult:
    return ScanResult(
        logical_name=task.logical_name,
        main_path=task.main_path,
        all_parts=list(task.all_parts),
        format=task.archive_input().format_hint,
        discovery_source=task.discovery_source,
        discovery_reason=task.discovery_reason,
        archive_input=task.archive_input().to_dict(),
    )


def _findings_from_task(task) -> list[DiscoveryFinding]:
    segments = task.knowledge().get("source.extractable_segments", [])
    if isinstance(segments, list) and segments:
        findings: list[DiscoveryFinding] = []
        for segment in segments:
            if not isinstance(segment, dict):
                continue
            start = segment.get("start_offset")
            end = segment.get("end_offset")
            findings.append(DiscoveryFinding(
                entry_path=task.main_path,
                source=task.discovery_source,
                format=str(segment.get("format") or task.archive_input().format_hint),
                status="resolved",
                reason=task.discovery_reason,
                logical_name=str(segment.get("logical_name") or task.logical_name),
                part_paths=tuple(task.all_parts),
                offset=int(start) if start is not None else None,
                end_offset=int(end) if end is not None else None,
                boundary_kind="exact" if end is not None else "",
                extractable=True,
            ))
        if findings:
            return findings

    descriptor = task.archive_input()
    extent = descriptor.primary_extent
    offset = None
    end_offset = None
    boundary_kind = ""
    if descriptor.open_mode == "file_range" and extent is not None:
        offset = int(extent.start)
        end_offset = int(extent.end) if extent.end is not None else None
        boundary_kind = "exact" if extent.end is not None else "unresolved"

    return [DiscoveryFinding(
        entry_path=task.main_path,
        source=task.discovery_source,
        format=descriptor.format_hint,
        status="resolved",
        reason=task.discovery_reason,
        logical_name=task.logical_name,
        part_paths=tuple(task.all_parts),
        offset=offset,
        end_offset=end_offset,
        boundary_kind=boundary_kind,
        extractable=True,
    )]
