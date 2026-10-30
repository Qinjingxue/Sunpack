import os
from typing import Any

from sunpack_native import classify_scan_targets, relations_logical_name

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.discovery import StageResult
from sunpack.core.contracts.run_state import RunState
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import TargetRunResult, OutcomeKind
from sunpack.core.i18n import I18nContext
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.pipeline.discovery.relations.internal.group_builder import RelationsGroupBuilder
from sunpack.pipeline.discovery.relations.internal.archive_input import archive_input_for_group
from sunpack.core.support.path_keys import path_key


class ArchiveTaskScanner:
    def __init__(
        self,
        config: dict[str, Any],
        context: RunState,
        detection_options: EmbeddedOptions | None = None,
    ):
        self.context = context
        self.provider = ArchiveTaskProvider(config, detection_options=detection_options)
        self.config = self.provider.config
        self.last_scan_session: DiscoveryScanSession | None = None

    def scan_root(self, scan_root: str) -> list[ArchiveTask]:
        return self.scan_targets([scan_root])

    def scan_targets(
        self,
        scan_roots: list[str],
        *,
        scan_session: DiscoveryScanSession | None = None,
        is_recursive_scan: bool = False,
    ) -> list[ArchiveTask]:
        scan_session = scan_session or DiscoveryScanSession(config=self.config)
        self.last_scan_session = scan_session
        tasks = self.provider.scan_targets(
            scan_roots,
            processed_keys=self.context.processed_keys,
            scan_session=scan_session,
            is_recursive_scan=is_recursive_scan,
        )
        self._record_provider_failures()
        self.record_scan_errors(scan_session)
        return tasks

    def scan_stage_result(
        self,
        scan_roots: list[str],
        *,
        scan_session: DiscoveryScanSession | None = None,
        is_recursive_scan: bool = False,
    ) -> StageResult:
        """Return discovery facts for reporting without changing extraction semantics."""

        self.provider.failed_candidate_failures = []
        scan_session = scan_session or DiscoveryScanSession(config=self.config)
        self.last_scan_session = scan_session
        result = self.provider.discover_targets(
            scan_roots,
            scan_session=scan_session,
            is_recursive_scan=is_recursive_scan,
            include_details=True,
        )
        self._record_provider_failures()
        self.record_scan_errors(scan_session)
        return result

    def discover_targets(
        self,
        scan_roots: list[str],
        *,
        scan_session: DiscoveryScanSession | None = None,
        is_recursive_scan: bool = False,
    ) -> list[ArchiveTask]:
        scan_session = scan_session or DiscoveryScanSession(config=self.config)
        self.last_scan_session = scan_session
        result = self.provider.discover_targets(
            scan_roots,
            scan_session=scan_session,
            is_recursive_scan=is_recursive_scan,
            include_details=False,
        )
        self._record_provider_failures()
        self.record_scan_errors(scan_session)
        return result.tasks

    def record_scan_errors(self, session: DiscoveryScanSession | None) -> None:
        if session is not None:
            self.context.record_scan_errors(
                session.take_scan_errors(), self.config.get("cli", {}).get("language", "en"),
            )

    def filter_processed_tasks(self, tasks: list[ArchiveTask]) -> list[ArchiveTask]:
        return self.provider.filter_processed_tasks(
            tasks,
            processed_keys=self.context.processed_keys,
        )

    def _record_provider_failures(self) -> None:
        self.context.record_failures(
            self.provider.failed_candidate_failures, self.config.get("cli", {}).get("language", "en"),
        )

    def direct_file_tasks(self, file_paths: list[str]) -> list[ArchiveTask]:
        tasks: list[ArchiveTask] = []
        paths = [os.path.abspath(os.path.normpath(path)) for path in file_paths]
        kinds, errors = classify_scan_targets(paths)
        self.context.record_scan_errors(errors, self.config.get("cli", {}).get("language", "en"))
        normalized_paths = [path for path, kind in zip(paths, kinds) if kind == 1]
        i18n = None
        for path, kind in zip(paths, kinds):
            if kind not in {0, 1}:
                i18n = i18n or I18nContext(self.config.get("cli", {}).get("language", "en"))
                key = "failure.direct_file_required"
                failure = FailureInfo(FailureKind.INVALID_INPUT, "input", i18n.t(key, path=path),
                                      message_key=key, message_params={"path": path}, details={"path": path})
                self.context.add_target_result(TargetRunResult(
                    path, OutcomeKind.FAILURE, failure=failure, error=failure.message, failure_message=failure.message,
                ))

        session = DiscoveryScanSession(config=self.config)
        discovered = self.provider.discover_targets(normalized_paths, scan_session=session)
        self._record_provider_failures()
        self.record_scan_errors(session)
        covered = set(discovered.claimed_paths | discovered.blocked_paths)
        tasks.extend(self.provider.filter_processed_tasks(
            discovered.tasks,
            processed_keys=self.context.processed_keys,
        ))
        for path in normalized_paths:
            if path_key(path) in covered:
                continue
            task = direct_file_task(path)
            if task.key in self.context.processed_keys:
                continue
            tasks.append(task)
        return tasks


def direct_file_task(path: str, all_parts: list[str] | None = None) -> ArchiveTask:
    path = os.path.abspath(os.path.normpath(path))
    name = os.path.basename(path)
    logical_name = relations_logical_name(name, True) or name
    parts = [
        os.path.abspath(os.path.normpath(item))
        for item in (all_parts or [path])
    ]
    group = None
    if len(parts) > 1:
        builder = RelationsGroupBuilder()
        group = builder.resolve_volume_once([path], parts)
        descriptor = archive_input_for_group(group) if group is not None else None
        if descriptor is None:
            raise ValueError(
                "explicit multi-volume input could not be represented structurally"
            )
    else:
        descriptor = ArchiveInputDescriptor.from_parts(
            archive_path=path,
            part_paths=[path],
            logical_name=logical_name,
        )
    return ArchiveTask.from_archive_input(
        descriptor,
        discovery_source="direct",
        discovery_reason="cli_direct_file",
        carrier_path=group.carrier_path if group is not None else path,
        cleanup_paths=group.owned_paths if group is not None else (),
        discovery_evidence=group.head_metadata if group is not None else None,
    )
