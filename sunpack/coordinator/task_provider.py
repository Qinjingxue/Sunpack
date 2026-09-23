"""Public archive discovery facade and extraction-task boundary."""

from typing import Any

from sunpack.contracts.discovery import DiscoveryCandidate, ResolvedArchiveInput, StageResult
from sunpack.contracts.failures import FailureInfo
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.discovery import ArchiveDiscoveryPipeline
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.coordinator.target_scan import build_discovery_candidates_for_targets
from sunpack.embedded.options import EmbeddedOptions
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.relations.scheduler import RelationsScheduler


class ArchiveTaskProvider:
    def __init__(self, config: dict[str, Any], detection_options: EmbeddedOptions | None = None):
        self.config = config
        self.detector = DetectionScheduler(config)
        self.discovery = ArchiveDiscoveryPipeline(
            config,
            self.detector,
            detection_options or EmbeddedOptions(),
        )
        self._relations = RelationsScheduler(config)
        self.failed_candidates: list[str] = []
        self.failed_candidate_failures: list[FailureInfo] = []

    def discover_targets(
        self,
        scan_roots: list[str],
        *,
        scan_session: DetectionScanSession | None = None,
        is_recursive_scan: bool = False,
    ) -> StageResult:
        session = scan_session or DetectionScanSession(config=self.config)
        candidates = build_discovery_candidates_for_targets(
            scan_roots,
            session=session,
            config=self.config,
        )
        result, _ = self.discovery.discover(
            candidates,
            scan_session=session,
            is_recursive_scan=is_recursive_scan,
        )
        return result

    def scan_targets(
        self,
        scan_roots: list[str],
        processed_keys: set[str] | None = None,
        scan_session: DetectionScanSession | None = None,
        *,
        is_recursive_scan: bool = False,
    ) -> list[ArchiveTask]:
        self.failed_candidates = []
        self.failed_candidate_failures = []
        inputs = self.discover_targets(
            scan_roots,
            scan_session=scan_session,
            is_recursive_scan=is_recursive_scan,
        ).resolved_inputs
        return self.tasks_from_inputs(inputs, processed_keys=processed_keys)

    def tasks_from_inputs(
        self,
        inputs: list[ResolvedArchiveInput],
        *,
        processed_keys: set[str] | None = None,
    ) -> list[ArchiveTask]:
        processed = processed_keys or set()
        tasks: list[ArchiveTask] = []
        for resolved in inputs:
            task = ArchiveTask.from_resolved_input(resolved)
            if task.key not in processed:
                tasks.append(task)
        return tasks

    def detect_targets(
        self,
        scan_roots: list[str],
        *,
        scan_session: DetectionScanSession | None = None,
        is_recursive_scan: bool = False,
        accepted_only: bool = False,
    ):
        session = scan_session or DetectionScanSession(config=self.config)
        candidates = build_discovery_candidates_for_targets(
            scan_roots,
            session=session,
            config=self.config,
        )
        _result, decisions = self.discovery.discover(
            candidates,
            scan_session=session,
            is_recursive_scan=is_recursive_scan,
        )
        return [
            item for item in decisions if item.decision.should_extract
        ] if accepted_only else decisions

    def task_from_candidate(self, candidate: DiscoveryCandidate) -> ArchiveTask | None:
        if not candidate.entry_path:
            return None
        routed = candidate
        if candidate.route != "relations":
            routed = DiscoveryCandidate(
                route="relations",
                entry_path=candidate.entry_path,
                member_paths=candidate.member_paths,
                logical_name=candidate.logical_name,
                carrier_path=candidate.carrier_path,
                cleanup_paths=candidate.cleanup_paths,
                companion_paths=candidate.companion_paths,
                size=candidate.size,
                format_hint=candidate.format_hint,
                format_reject_mask=candidate.format_reject_mask,
                relation_anchor=candidate.relation_anchor,
                archive_input=candidate.archive_input,
                relation_kind=candidate.relation_kind,
                is_split=candidate.is_split,
                is_sfx=candidate.is_sfx,
                relation_family=candidate.relation_family,
                relation_index=candidate.relation_index,
            )
        result, _ = self.discovery.discover([routed])
        tasks = self.tasks_from_inputs(result.resolved_inputs)
        return tasks[0] if tasks else None

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
