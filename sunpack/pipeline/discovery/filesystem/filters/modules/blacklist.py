from typing import Any

from sunpack.pipeline.discovery.filesystem.filters.path_rule import PathRuleScanFilter


class BlacklistScanFilter(PathRuleScanFilter):
    name = "blacklist"
    whitelist = False

    def __init__(self, blocked_extensions=None, blocked_files=None, path_globs=None):
        super().__init__(path_globs, blocked_files, blocked_extensions)

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(
            blocked_extensions=config.get("blocked_extensions") or [],
            blocked_files=config.get("blocked_files") or [],
            path_globs=config.get("path_globs") or [],
        )
