"""Read-only typed discovery diagnostics for the CLI inspect command."""

from dataclasses import dataclass
from typing import Any

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

    def collect(self, paths: list[str]) -> list[DiscoveryDiagnostic]:
        result = self.provider.discover_targets(paths)
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
            )
            for trace in result.traces
        ]
