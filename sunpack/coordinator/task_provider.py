"""Public archive discovery facade and extraction-task boundary."""

from typing import Any

from sunpack.contracts.discovery import ResolvedArchiveInput, StageResult
from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureInfo
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.discovery import ArchiveDiscoveryPipeline
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from sunpack.detection.knowledge import write_detection_task
from sunpack.embedded.options import EmbeddedOptions
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.filesystem.knowledge import write_filesystem_task
from sunpack.relations.knowledge import write_relation_task
from sunpack.relations.scheduler import RelationsScheduler
from sunpack.support.archive_input_projection import write_source_extractable_segments


class ArchiveTaskProvider:
    def __init__(self, config: dict[str, Any], detection_options: EmbeddedOptions | None = None):
        self.config = config
        self.detector = DetectionScheduler(config)
        self.discovery = ArchiveDiscoveryPipeline(config, self.detector, detection_options or EmbeddedOptions())
        self._relations = RelationsScheduler(config)
        self.failed_candidates: list[str] = []
        self.failed_candidate_failures: list[FailureInfo] = []

    def discover_targets(
        self, scan_roots: list[str], *, scan_session: DetectionScanSession | None = None,
        is_recursive_scan: bool = False,
    ) -> StageResult:
        session = scan_session or DetectionScanSession(config=self.config)
        bags = build_fact_bags_for_targets(scan_roots, session=session, config=self.config)
        result, _ = self.discovery.discover(
            bags, scan_session=session, is_recursive_scan=is_recursive_scan,
        )
        return result

    def scan_targets(
        self, scan_roots: list[str], processed_keys: set[str] | None = None,
        scan_session: DetectionScanSession | None = None, *, is_recursive_scan: bool = False,
    ) -> list[ArchiveTask]:
        self.failed_candidates = []
        self.failed_candidate_failures = []
        inputs = self.discover_targets(
            scan_roots, scan_session=scan_session, is_recursive_scan=is_recursive_scan,
        ).resolved_inputs
        return self.tasks_from_inputs(inputs, processed_keys=processed_keys)

    def tasks_from_inputs(
        self, inputs: list[ResolvedArchiveInput], *, processed_keys: set[str] | None = None,
    ) -> list[ArchiveTask]:
        processed = processed_keys or set()
        tasks = []
        for resolved in inputs:
            task = ArchiveTask.from_fact_bag(resolved.facts)
            _write_initial_task_knowledge(task)
            if task.key not in processed:
                tasks.append(task)
        return tasks

    def detect_targets(
        self, scan_roots: list[str], *, scan_session: DetectionScanSession | None = None,
        is_recursive_scan: bool = False, accepted_only: bool = False,
    ):
        session = scan_session or DetectionScanSession(config=self.config)
        bags = build_fact_bags_for_targets(scan_roots, session=session, config=self.config)
        _result, decisions = self.discovery.discover(
            bags, scan_session=session, is_recursive_scan=is_recursive_scan,
        )
        return [item for item in decisions if item.decision.should_extract] if accepted_only else decisions

    def task_from_candidate_bag(self, bag: FactBag) -> ArchiveTask | None:
        if not bag.get("candidate.entry_path"):
            return None
        bag.set("filesystem.route", "relations")
        result, _ = self.discovery.discover([bag])
        tasks = self.tasks_from_inputs(result.resolved_inputs)
        return tasks[0] if tasks else None

    def resolve_volume_once_in_directory(
        self, current_paths: list[str], *, format_hint: str = "",
    ):
        return self._relations.resolve_volume_once_in_directory(
            current_paths, format_hint=format_hint,
        )


def _write_initial_task_knowledge(task: ArchiveTask) -> None:
    write_filesystem_task(task)
    write_relation_task(task)
    write_detection_task(task)
    segments = task.fact_bag.get("source.extractable_segments")
    if isinstance(segments, list):
        write_source_extractable_segments(task, segments)
