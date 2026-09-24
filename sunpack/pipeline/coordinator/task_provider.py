"""Public archive discovery facade and extraction-task boundary."""

from typing import Any

from sunpack.core.contracts.discovery import DiscoveryCandidate, StageResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.discovery import ArchiveDiscoveryPipeline
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.target_scan import build_candidates_for_targets
from sunpack.pipeline.discovery.detection.scheduler import DetectionScheduler
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.pipeline.discovery.relations.scheduler import RelationsScheduler


class ArchiveTaskProvider:
    def __init__(
        self,
        config: dict[str, Any],
        detection_options: EmbeddedOptions | None = None,
    ):
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
        scan_session: DiscoveryScanSession | None = None,
        is_recursive_scan: bool = False,
    ) -> StageResult:
        session = scan_session or DiscoveryScanSession(config=self.config)
        candidates = build_candidates_for_targets(
            scan_roots,
            session=session,
            config=self.config,
        )
        result = self.discovery.discover(
            candidates,
            is_recursive_scan=is_recursive_scan,
        )
        self._record_discovery_failures(result)
        return result

    def scan_targets(
        self,
        scan_roots: list[str],
        processed_keys: set[str] | None = None,
        scan_session: DiscoveryScanSession | None = None,
        *,
        is_recursive_scan: bool = False,
    ) -> list[ArchiveTask]:
        self.failed_candidates = []
        self.failed_candidate_failures = []
        discovered = self.discover_targets(
            scan_roots,
            scan_session=scan_session,
            is_recursive_scan=is_recursive_scan,
        )
        return self.filter_processed_tasks(
            discovered.resolved_tasks,
            processed_keys=processed_keys,
        )

    def filter_processed_tasks(
        self,
        tasks: list[ArchiveTask],
        *,
        processed_keys: set[str] | None = None,
    ) -> list[ArchiveTask]:
        processed = processed_keys or set()
        return [task for task in tasks if task.key not in processed]

    def _record_discovery_failures(self, result: StageResult) -> None:
        mapping = {
            "embedded_password_required": (
                FailureKind.PASSWORD_REQUIRED,
                "failure.password_required",
                "Embedded archive requires a password",
                "request_password",
            ),
            "embedded_wrong_password": (
                FailureKind.WRONG_PASSWORD,
                "failure.wrong_password",
                "Embedded archive password is wrong",
                "request_password",
            ),
            "embedded_truncated": (
                FailureKind.DAMAGED,
                "failure.damaged",
                "Embedded archive is truncated before its terminal boundary",
                "",
            ),
        }
        for trace in result.traces:
            failure = mapping.get(trace.reason)
            if failure is None:
                continue
            kind, message_key, message, user_action = failure
            if trace.entry_path not in self.failed_candidates:
                self.failed_candidates.append(trace.entry_path)
            info = FailureInfo(
                kind=kind,
                stage="embedded_boundary",
                message=message,
                message_key=message_key,
                user_action=user_action,
                details={
                    "path": trace.entry_path,
                    "reason": trace.reason,
                },
            )
            if info not in self.failed_candidate_failures:
                self.failed_candidate_failures.append(info)

    def task_from_candidate(self, candidate: DiscoveryCandidate) -> ArchiveTask | None:
        result = self.discovery.discover([candidate])
        self._record_discovery_failures(result)
        tasks = self.filter_processed_tasks(result.resolved_tasks)
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
