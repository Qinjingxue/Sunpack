from copy import deepcopy
from typing import Any

from sunpack.core.config.schema import normalize_config


def make_config(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the internal config contract from a small test input payload.

    Small archive fixtures bypass default size filters; tests of filtering
    supply their own scan_filters explicitly. Normalize only at this boundary.
    """
    config = deepcopy(payload or {})
    config.setdefault("cli", {}).setdefault("language", "en")
    config.setdefault("verification", {})
    config.setdefault("filesystem", {}).setdefault("scan_filters", [])
    return normalize_config(config)


CONFIGS: dict[str, dict[str, Any]] = {
    "minimal": {
        "detection": {"enabled": True},
        "filesystem": {"scan_filters": [{"name": "size_range", "enabled": True, "gte": 0}]},
    },
    "embedded_archive_loose": {
        "detection": {"enabled": True},
        "embedded_scan": {"enabled": True, "recursive_candidate_ratio": 1e-9},
    },
    "embedded_archive_carrier_tail": {
        "detection": {"enabled": True},
        "embedded_scan": {"enabled": True, "recursive_candidate_ratio": 1e-9},
    },
    "archive_scan_full": {
        "detection": {"enabled": True},
        "embedded_scan": {"enabled": True},
    },
    "archive_scan_deep_embedded": {
        "detection": {"enabled": True},
        "embedded_scan": {"enabled": True, "recursive_candidate_ratio": 1e-9},
    },
}

def get_config(name: str = "minimal", overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    config = deepcopy(CONFIGS[name])
    if overrides:
        deep_merge(config, overrides)
    return make_config(config)


def deep_merge(target: dict[str, Any], source: dict[str, Any]):
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_merge(target[key], value)
        else:
            target[key] = deepcopy(value)
