import os
from typing import Any

from sunpack.config.detection_view import detection_config, rule_pipeline_config
from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureInfo
from sunpack.contracts.tasks import ArchiveTask
from sunpack.detection.knowledge import write_detection_task
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.detection.options import DetectionOptions
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.coordinator.nested_extraction_policy import NestedExtractionPolicy
from sunpack.coordinator.nested_extraction_policy import EMBEDDED_SCAN_ALLOWED_FACT
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from sunpack.filesystem.knowledge import write_filesystem_task
from sunpack.relations.knowledge import write_relation_task
from sunpack.relations.scheduler import RelationsScheduler


STANDARD_ARCHIVE_EXTS = {".7z", ".zip", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst"}


class ArchiveTaskProvider:
    """Public detection facade that turns detection decisions into archive tasks."""

    def __init__(self, config: dict[str, Any], detection_options: DetectionOptions | None = None):
        self.config = config
        self.detection_options = detection_options or DetectionOptions()
        self.detector = DetectionScheduler(config, options=self.detection_options)
        self.nested_extraction_policy = NestedExtractionPolicy(config)
        self._relations = RelationsScheduler()
        self.failed_candidates: list[str] = []
        self.failed_candidate_failures: list[FailureInfo] = []

    def scan_targets(
        self,
        scan_roots: list[str],
        processed_keys: set[str] | None = None,
        scan_session: DetectionScanSession | None = None,
        *,
        is_recursive_scan: bool = False,
    ) -> list[ArchiveTask]:
        processed_keys = processed_keys or set()
        self.failed_candidates = []
        self.failed_candidate_failures = []
        if self._detection_pipeline_disabled():
            return self._scan_standard_archive_targets(
                scan_roots,
                processed_keys,
                scan_session=scan_session,
                is_recursive_scan=is_recursive_scan,
            )

        tasks: list[ArchiveTask] = []
        for detection in self.detect_targets(scan_roots, scan_session=scan_session, is_recursive_scan=is_recursive_scan):
            bag = detection.fact_bag
            if not bag.get("candidate.entry_path"):
                continue

            decision = detection.decision
            if decision.should_extract:
                task = ArchiveTask.from_fact_bag(bag, decision=decision)
                _write_initial_task_knowledge(task)
                if task.key in processed_keys:
                    continue
                tasks.append(task)
        return tasks

    def task_from_candidate_bag(self, bag: FactBag) -> ArchiveTask | None:
        """Re-enter detection for one Relations hypothesis."""
        if not bag.get("candidate.entry_path"):
            return None
        if not bag.has(EMBEDDED_SCAN_ALLOWED_FACT):
            bag.set(EMBEDDED_SCAN_ALLOWED_FACT, False)
        if self._detection_pipeline_disabled():
            task = ArchiveTask.from_fact_bag(bag)
        else:
            decision = self.detector.evaluate_bag(bag)
            if not decision.should_extract:
                return None
            task = ArchiveTask.from_fact_bag(bag, decision=decision)
        _write_initial_task_knowledge(task)
        return task

    def resolve_volume_once_in_directory(
        self,
        current_paths: list[str],
        *,
        format_hint: str = "",
    ):
        return self._relations.resolve_volume_once_in_directory(
            current_paths,
            format_hint=format_hint,
        )

    def _scan_standard_archive_targets(
        self,
        scan_roots: list[str],
        processed_keys: set[str],
        *,
        scan_session: DetectionScanSession | None = None,
        is_recursive_scan: bool = False,
    ) -> list[ArchiveTask]:
        tasks: list[ArchiveTask] = []
        scan_session = scan_session or DetectionScanSession(config=self.config)
        candidate_bags = build_fact_bags_for_targets(scan_roots, session=scan_session, config=self.config)
        fact_bags = self._filter_incomplete_split_groups(candidate_bags)
        self.nested_extraction_policy.plan_embedded_scan(
            fact_bags,
            is_recursive_scan=is_recursive_scan,
        ).apply(fact_bags)
        for bag in fact_bags:
            main_path = bag.get("candidate.entry_path")
            if not main_path or not self._is_standard_archive_candidate(main_path, bag):
                continue
            task = ArchiveTask.from_fact_bag(bag)
            _write_initial_task_knowledge(task)
            if task.key in processed_keys:
                continue
            tasks.append(task)
        return tasks

    def detect_targets(
        self,
        scan_roots: list[str],
        *,
        scan_session: DetectionScanSession | None = None,
        is_recursive_scan: bool = False,
    ):
        scan_session = scan_session or DetectionScanSession(config=self.config)
        candidate_bags = build_fact_bags_for_targets(scan_roots, session=scan_session, config=self.config)
        fact_bags = self._filter_incomplete_split_groups(candidate_bags)
        self.nested_extraction_policy.plan_embedded_scan(
            fact_bags,
            is_recursive_scan=is_recursive_scan,
        ).apply(fact_bags)
        return self.detector.evaluate_bags(fact_bags, scan_session=scan_session)

    def _detection_pipeline_disabled(self) -> bool:
        if self.detection_options.deep_scan:
            return False
        detector_config = detection_config(self.config)
        if detector_config.get("enabled") is False:
            return True
        if self._has_enabled_modules(detector_config.get("fact_collectors")):
            return False
        if self._has_enabled_modules(detector_config.get("processors")):
            return False
        pipeline = rule_pipeline_config(self.config)
        for layer in ("precheck",):
            if self._has_enabled_modules(pipeline.get(layer)):
                return False
        return True

    def _has_enabled_modules(self, modules_config) -> bool:
        if not isinstance(modules_config, list):
            return False
        return any(isinstance(item, dict) and item.get("enabled", False) for item in modules_config)

    def _is_standard_archive_candidate(self, path: str, bag) -> bool:
        name = os.path.basename(path).lower()
        ext = os.path.splitext(name)[1]
        if ext in STANDARD_ARCHIVE_EXTS:
            return True
        if self._relations.detect_split_role(name) == "first":
            return True
        if ext == ".exe" and bag.get("relation.is_split_exe_companion"):
            return True
        return False

    def _filter_incomplete_split_groups(self, bags: list[FactBag]) -> list[FactBag]:
        """Preserve relation hints without treating filename inference as failure evidence."""
        return list(bags)


def _write_initial_task_knowledge(task: ArchiveTask) -> None:
    write_filesystem_task(task)
    write_relation_task(task)
    write_detection_task(task)
