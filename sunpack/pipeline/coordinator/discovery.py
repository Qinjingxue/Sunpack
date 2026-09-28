"""Project native discovery decisions into tasks and sparse diagnostics."""

from sunpack.core.contracts.discovery import DiscoveryTrace, StageResult
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.embedded.discovery import EmbeddedDiscovery
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions


class ArchiveDiscoveryPipeline:
    def __init__(self, config: dict, options: EmbeddedOptions):
        self.config = config
        self.embedded = EmbeddedDiscovery(config, options)

    def discover_native(
        self,
        table,
        session: DiscoveryScanSession,
        *,
        is_recursive_scan: bool = False,
        include_details: bool = True,
    ) -> StageResult:
        routes = table.resolve(
            self.config.get("detection", {}).get("enabled", True),
            include_residual_details=include_details,
        )
        result = StageResult()
        for index, status in routes.relation_events:
            if status == 1:
                candidate = session.project_native_candidate(table, index)
                result.add_resolved(
                    ArchiveTask.from_archive_input(
                        candidate.archive_input,
                        discovery_source="relations",
                        carrier_path=candidate.carrier_path,
                        cleanup_paths=candidate.cleanup_paths,
                        discovery_evidence=dict(candidate.relation_anchor),
                    ),
                    reason="Relations confirmed native archive identity",
                )
            else:
                entry_path, format_hint = table.summary(index)
                if status == 2:
                    result.blocked_paths.update(table.path_keys(index))
                result.traces.append(DiscoveryTrace(
                    entry_path=entry_path,
                    source="relations",
                    status="blocked" if status == 2 else "residual",
                    format=format_hint,
                    reason=(
                        "Relations requires password or additional volume evidence"
                        if status == 2 else ""
                    ),
                ))

        detection_enabled = self.config.get("detection", {}).get("enabled", True)
        for index, status in routes.detection_events:
            if status == 1:
                candidate = session.project_native_candidate(table, index)
                result.add_resolved(
                    ArchiveTask.from_archive_input(
                        candidate.archive_input,
                        discovery_source="detection",
                        carrier_path=candidate.carrier_path,
                        cleanup_paths=candidate.cleanup_paths,
                        discovery_evidence={"format": candidate.format_hint},
                    ),
                    reason=f"Confirmed {candidate.format_hint} structure",
                )
            else:
                entry_path, format_hint = table.summary(index)
                result.traces.append(DiscoveryTrace(
                    entry_path=entry_path,
                    source="detection",
                    status="residual",
                    format=format_hint,
                    reason="" if detection_enabled else "detection_disabled",
                ))

        embedded_result = self.embedded.discover_native(
            table,
            routes,
            session,
            is_recursive_scan=is_recursive_scan,
            include_details=include_details,
        )
        result.resolved_tasks.extend(embedded_result.resolved_tasks)
        result.findings.extend(embedded_result.findings)
        result.claimed_paths.update(embedded_result.claimed_paths)
        result.blocked_paths.update(embedded_result.blocked_paths)
        result.residual_paths.update(embedded_result.residual_paths)
        result.traces.extend(embedded_result.traces)
        result.validate()
        return result
