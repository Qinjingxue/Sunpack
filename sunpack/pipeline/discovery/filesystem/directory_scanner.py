from sunpack_native import NativeDirectoryScanOptions

from sunpack.core.config.detection_view import scan_filters_config
from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.core.contracts.filesystem import DirectorySnapshot
from sunpack.pipeline.discovery.filesystem.filters.modules.mtime_range import time_bounds
from sunpack.pipeline.discovery.filesystem.filters.modules.size_range import size_bounds
from sunpack.pipeline.discovery.filesystem.filters.path_rule import compile_path_rule


def native_filter_options(config: dict | None) -> dict:
    options = {
        "blacklist_rules": [],
        "size_ranges": [],
        "mtime_ranges": [],
        "whitelist_rules": [],
    }
    for item in scan_filters_config(config) if config else ():
        if not item["enabled"]:
            continue
        name = item["name"]
        if name in ("blacklist", "whitelist"):
            options[f"{name}_rules"].append(compile_path_rule(item))
        elif name == "size_range":
            options["size_ranges"].append(size_bounds(item))
        elif name == "mtime_range":
            options["mtime_ranges"].append(time_bounds(item))
        else:
            raise ValueError(f"Unknown filesystem scan filter: {name}")
    return options


class DirectoryScanner:
    def __init__(
        self, root_path: str, *, config: dict | None = None,
        scope: DiscoveryScope | None = None, scan_options: NativeDirectoryScanOptions | None = None,
    ):
        self.scope = scope or DiscoveryScope(root_path)
        self._scan_options = scan_options if scan_options is not None else self.compile_scan_options(config)

    def scan(self) -> DirectorySnapshot:
        return DirectorySnapshot(*self._scan_options.scan_scope(self.scope.native))

    @staticmethod
    def compile_scan_options(config: dict | None = None) -> NativeDirectoryScanOptions:
        return NativeDirectoryScanOptions(**native_filter_options(config))

    @staticmethod
    def snapshot_from_output_inventory(
        inventory, *, scan_options: NativeDirectoryScanOptions,
    ) -> DirectorySnapshot:
        return DirectorySnapshot(*inventory.build_directory_snapshots(scan_options))
