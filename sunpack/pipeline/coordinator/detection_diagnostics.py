from sunpack.core.contracts.discovery_scope import DiscoveryScope
"""Read-only typed discovery diagnostics for the CLI inspect command."""

from dataclasses import dataclass, field
from typing import Any

from sunpack.core.contracts.run_state import RunState
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.core.support.path_keys import path_key


@dataclass(frozen=True)
class DiscoveryDiagnostic:
    path: str
    status: str
    format: str
    source: str
    reason: str
    archive_input: dict | None = None
    task: ArchiveTask | None = field(default=None, repr=False, compare=False)

    @property
    def should_extract(self) -> bool:
        return self.status == "resolved"


class DetectionDiagnostics:
    def __init__(
        self,
        config: dict[str, Any],
        detection_options: EmbeddedOptions | None = None,
    ):
        self.provider = ArchiveTaskProvider(
            config,
            detection_options=detection_options,
        )
        self.context = RunState()

    @property
    def errors(self) -> list[str]:
        return [failure.display_message for failure in self.context.scan_failures]

    def collect(self, paths: list[str], *, recursive: bool = False) -> list[DiscoveryDiagnostic]:
        session = DiscoveryScanSession(config=self.provider.config, scopes=DiscoveryScope.for_targets(paths, recursive=recursive))
        result = self.provider.discover_targets(paths, scan_session=session)
        self.context.record_scan_errors(
            session.take_scan_errors(), self.provider.config.get("cli", {}).get("language", "en"),
        )
        resolved = {
            path_key(item.main_path): item
            for item in result.resolved_tasks
        }
        return [
            DiscoveryDiagnostic(
                path=trace.entry_path,
                status=trace.status,
                format=trace.format,
                source=trace.source,
                reason=trace.reason,
                archive_input=(
                    resolved[path_key(trace.entry_path)].archive_input().to_dict()
                    if path_key(trace.entry_path) in resolved
                    else None
                ),
                task=resolved.get(path_key(trace.entry_path)),
            )
            for trace in result.traces
        ]
