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
                result.resolved_tasks.extend(partial.resolved_tasks)
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
        for task in result.resolved_tasks:
            task.runtime["discovery_scope"] = session.scope_for(task.main_path)
            task.runtime["discovery_catalog"] = session.catalog
            if session.catalog is None:
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

    def resolve_volume_once(self, current_paths: list[str], scope, *, format_hint: str = "", catalog=None, snapshot=None):
        from sunpack.core.contracts.filesystem import DirectorySnapshot
        from pathlib import Path
        if catalog is not None:
            state, options, _ = catalog
            filtered, raw = options.catalog_snapshot(state, scope.native, current_paths[0])
        else:
            if snapshot is None:
                raise ValueError("Volume retry requires the original discovery snapshot")
            filtered = snapshot.native_snapshot.relation_bucket(current_paths[0])
            raw = snapshot.raw_native_snapshot.relation_bucket(current_paths[0])
        snapshot = DirectorySnapshot.from_native(Path(scope.root), filtered, raw)
        groups = self._relations.build_candidate_groups(snapshot)
        required = set(current_paths)
        for group in groups:
            if required.issubset(set(group.input_paths)) and group.is_split_candidate:
                return group
        return None
