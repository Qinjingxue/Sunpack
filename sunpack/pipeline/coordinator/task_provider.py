"""Public archive discovery facade and extraction-task boundary."""

from typing import Any

from sunpack.core.config.detection_view import discovery_run_config

from sunpack.core.contracts.discovery import StageResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.discovery import ArchiveDiscoveryPipeline
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.target_scan import build_native_table_for_targets
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.pipeline.discovery.relations.scheduler import RelationsScheduler
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner


class ArchiveTaskProvider:
    def __init__(
        self,
        config: dict[str, Any],
        detection_options: EmbeddedOptions | None = None,
    ):
        options = detection_options or EmbeddedOptions()
        config = discovery_run_config(config, deep_detect=options.force_scan)
        self.config = config
        self.discovery = ArchiveDiscoveryPipeline(
            config,
            options,
        )
        self._relations = RelationsScheduler(config)
        self._retry_scan_options = None
        self.failed_candidate_failures: list[FailureInfo] = []

    def discover_targets(
        self,
        scan_roots: list[str],
        *,
        scan_session: DiscoveryScanSession | None = None,
        is_recursive_scan: bool = False,
        include_details: bool = True,
    ) -> StageResult:
        session = scan_session or DiscoveryScanSession(config=self.config)
        roots = list(dict.fromkeys(str(root) for root in scan_roots if str(root)))
        if is_recursive_scan and len(roots) > 1:
            result = StageResult()
            for root in roots:
                table = build_native_table_for_targets(
                    [root],
                    session=session,
                    config=self.config,
                )
                partial = self.discovery.discover_native(
                    table,
                    session,
                    is_recursive_scan=True,
                    include_details=include_details,
                )
                result.tasks.extend(partial.tasks)
                result.findings.extend(partial.findings)
                result.claimed_paths.update(partial.claimed_paths)
                result.blocked_paths.update(partial.blocked_paths)
                result.residual_paths.update(partial.residual_paths)
                result.traces.extend(partial.traces)
            result.validate()
        else:
            table = build_native_table_for_targets(
                roots,
                session=session,
                config=self.config,
            )
            result = self.discovery.discover_native(
                table,
                session,
                is_recursive_scan=is_recursive_scan,
                include_details=include_details,
            )
        for task in result.tasks:
            task.runtime["discovery_scope"] = session.scope_for(task.main_path)
            task.runtime["discovery_catalog"] = session.catalog
            task.runtime["discovery_snapshot"] = session.snapshot_for_directory(session.scope_for(task.main_path).root)
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
        self.failed_candidate_failures = []
        discovered = self.discover_targets(
            scan_roots,
            scan_session=scan_session,
            is_recursive_scan=is_recursive_scan,
            include_details=False,
        )
        return self.filter_processed_tasks(
            discovered.tasks,
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
        for trace in result.traces:
            if trace.reason != "embedded_scan_io_error":
                continue
            info = FailureInfo(
                FailureKind.FILESYSTEM_ERROR, "embedded_boundary",
                trace.error or "Unable to read archive input",
                details={"path": trace.entry_path, "reason": trace.reason},
            )
            if info not in self.failed_candidate_failures:
                self.failed_candidate_failures.append(info)

    def resolve_volume_once(self, current_paths: list[str], scope, *, format_hint: str = "", catalog=None, snapshot=None):
        from sunpack.core.contracts.filesystem import DirectorySnapshot
        from pathlib import Path
        if not current_paths:
            return None
        state = None
        if catalog is not None:
            state, options, _ = catalog
            if snapshot is None:
                filtered, raw = options.catalog_snapshot(state, scope.native, current_paths[0])
                snapshot = DirectorySnapshot.from_native(Path(scope.root), filtered, raw)
        else:
            if self._retry_scan_options is None:
                self._retry_scan_options = DirectoryScanner.compile_scan_options(self.config)
            options = self._retry_scan_options
        if snapshot is None:
            raise ValueError("Volume retry requires the original discovery snapshot")
        filtered, raw = options.refresh_relation_bucket(
            scope.native, current_paths[0], snapshot.raw_native_snapshot, state,
        )
        snapshot = DirectorySnapshot.from_native(Path(scope.root), filtered, raw)
        groups = self._relations.build_candidate_groups(snapshot)
        required = set(current_paths)
        for group in groups:
            metadata = group.head_metadata or {}
            # Blocked groups also own unresolved paths; containment alone does
            # not prove that their head and volumes form a usable replacement.
            if (
                group.is_split_candidate
                and metadata.get("relation_confirmed")
                and not metadata.get("relation_failure_reason")
                and (not format_hint or metadata.get("format") == format_hint)
                and required.issubset(set(group.input_paths))
            ):
                return group
        return None
