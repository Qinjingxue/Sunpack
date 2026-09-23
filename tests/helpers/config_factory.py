from copy import deepcopy
from typing import Any



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
    return config


def deep_merge(target: dict[str, Any], source: dict[str, Any]):
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_merge(target[key], value)
        else:
            target[key] = deepcopy(value)
