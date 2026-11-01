from typing import Any

from sunpack.pipeline.discovery.filesystem.filters.path_rule import PathRuleScanFilter


class WhitelistScanFilter(PathRuleScanFilter):
    name = "whitelist"
    whitelist = True

    def __init__(self, allowed_extensions=None, allowed_files=None, path_globs=None):
        super().__init__(path_globs, allowed_files, allowed_extensions)

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(
            allowed_extensions=config.get("allowed_extensions") or [],
            allowed_files=config.get("allowed_files") or [],
            path_globs=config.get("path_globs") or [],
        )
