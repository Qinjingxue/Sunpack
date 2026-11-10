from typing import Any

def filesystem_config(config: dict[str, Any]) -> dict[str, Any]:
    return config["filesystem"]


def discovery_run_config(config: dict[str, Any], *, deep_detect: bool) -> dict[str, Any]:
    """Apply detection policy to one request without changing its config source."""
    if not deep_detect or not scan_filters_enabled(config):
        return config
    return {
        **config,
        "filesystem": {**filesystem_config(config), "scan_filters_enabled": False},
    }


def scan_filters_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    if not scan_filters_enabled(config):
        return []
    return filesystem_config(config)["scan_filters"]


def scan_filters_enabled(config: dict[str, Any]) -> bool:
    return filesystem_config(config)["scan_filters_enabled"]
