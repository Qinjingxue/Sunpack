"""Read-only typed discovery diagnostics for the CLI inspect command."""

from dataclasses import dataclass
from typing import Any

from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.embedded.options import EmbeddedOptions


@dataclass(frozen=True)
class DiscoveryDiagnostic:
    path: str
    status: str
    format: str
    source: str
    reason: str

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
        return [
            DiscoveryDiagnostic(
                path=trace.entry_path,
                status=trace.status,
                format=trace.format,
                source=trace.source,
                reason=trace.reason,
            )
            for trace in result.traces
        ]
