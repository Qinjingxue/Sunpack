from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value


DEFAULT_ANALYSIS_CONFIG = advanced_config_value(("analysis",))


def analysis_config(config: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict((config or {}).get("analysis") or {})
    return _merge(DEFAULT_ANALYSIS_CONFIG, payload)


def _merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result
