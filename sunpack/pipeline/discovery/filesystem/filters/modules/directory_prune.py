from dataclasses import dataclass
from typing import Any

from sunpack.pipeline.discovery.filesystem.filters import register_filter
from sunpack.pipeline.discovery.filesystem.filters.base import ScanCandidate, ScanDecision, keep


def prune_dir_globs(config: dict[str, Any] | None = None) -> list[str]:
    globs = (config or {}).get("prune_dir_globs")
    if not isinstance(globs, list):
        return []
    return [str(item) for item in globs if isinstance(item, str) and item.strip()]


def path_globs(config: dict[str, Any] | None = None) -> list[str]:
    globs = (config or {}).get("path_globs")
    if not isinstance(globs, list):
        return []
    return [str(item) for item in globs if isinstance(item, str) and item.strip()]


@dataclass
class DirectoryPruneScanFilter:
    """Carries directory-pruning rules compiled into the native scanner."""

    name = "directory_prune"
    stage = "path"
    config: dict[str, Any]

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(config=dict(config))

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        # DirectoryScanner skips this native-only filter during Python passes.
        return keep()


register_filter(DirectoryPruneScanFilter.name, DirectoryPruneScanFilter)
