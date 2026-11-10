"""Project native discovery decisions into tasks and sparse diagnostics."""

from sunpack.core.contracts.discovery import StageResult
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.discovery.embedded.discovery import EmbeddedDiscovery
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.core.support.path_keys import path_key


class ArchiveDiscoveryPipeline:
    def __init__(self, config: dict, options: EmbeddedOptions):
        self.embedded = EmbeddedDiscovery(config, options)

    def discover_native(
        self,
        table,
        session: DiscoveryScanSession,
        *,
        is_recursive_scan: bool = False,
    ) -> StageResult:
        return self.discover_many_native(
            [table], session, is_recursive_scan=is_recursive_scan,
        )[0]

    def discover_many_native(self, tables, session, *, is_recursive_scan=False) -> list[StageResult]:
        scans = []
        results = []
        for table in tables:
            routes = table.resolve()
            results.append(self._project_primary(table, routes, session))
            scans.append((table, self.embedded.prepare_native(
                table, routes, is_recursive_scan=is_recursive_scan,
            )))
            del routes
        embedded = self.embedded.discover_many_native(scans, session)
        for result, embedded_result in zip(results, embedded):
            self._merge_embedded(result, embedded_result)
        return results

    @staticmethod
    def _project_primary(table, routes, session) -> StageResult:
        result = StageResult()
        for index, status in routes.relation_events:
            if status in {1, 2}:
                candidate = session.project_native_candidate(table, index)
                failure_reason = candidate.relation_anchor.get("relation_failure_reason")
                if failure_reason:
                    result.add_blocked(candidate, source="relations", reason=str(failure_reason))
                    continue
                result.add_resolved(
                    ArchiveTask.from_archive_input(
                        candidate.archive_input,
                        discovery_source="relations",
                        carrier_path=candidate.carrier_path,
                        cleanup_paths=candidate.cleanup_paths,
                        discovery_evidence=dict(candidate.relation_anchor),
                    ),
                )

        for index, status in routes.detection_events:
            if status == 1:
                candidate = session.project_native_candidate(table, index)
                candidate.archive_input.analysis.update(routes.primary_analysis(index) or {})
                result.add_resolved(
                    ArchiveTask.from_archive_input(
                        candidate.archive_input,
                        discovery_source="detection",
                        carrier_path=candidate.carrier_path,
                        cleanup_paths=candidate.cleanup_paths,
                        discovery_evidence={"format": candidate.format_hint},
                    ),
                )

        return result

    @staticmethod
    def _merge_embedded(result, embedded_result) -> None:
        replaced = embedded_result.claimed_paths | embedded_result.blocked_paths
        shared_candidates = False
        if replaced:
            retained = []
            for task in result.tasks:
                has_attempts = False
                for node in task.inputs:
                    if node.descriptor.volume_attempts is not None:
                        has_attempts = True
                        if shared_candidates or any(path_key(path) in replaced for path in node.source_paths):
                            shared_candidates = True
                            break
                if has_attempts or not any(path_key(path) in replaced for path in task.cleanup_parts):
                    retained.append(task)
            result.tasks = retained
            result.claimed_paths.difference_update(replaced)
            result.blocked_paths.difference_update(replaced)
        result.tasks.extend(embedded_result.tasks)
        result.claimed_paths.update(embedded_result.claimed_paths)
        result.blocked_paths.update(embedded_result.blocked_paths)
        result.scan_failures.extend(embedded_result.scan_failures)
        if shared_candidates:
            EmbeddedDiscovery._combine_shared_inputs(result)
        result.validate()
