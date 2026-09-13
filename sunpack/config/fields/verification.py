from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.schema import ConfigField


REQUIRED_VERIFICATION_KEYS = (
    "enabled",
    "max_retries",
    "cleanup_failed_output",
    "complete_accept_threshold",
    "partial_accept_threshold",
    "retry_on_verification_failure",
    "methods",
)

VERIFICATION_DEFAULTS = advanced_config_value(("verification",))


def normalize_verification_config(value: Any) -> dict[str, Any]:
    if value is None:
        raise ValueError("Missing required config object: verification")
    if not isinstance(value, dict):
        raise ValueError("verification must be an object")
    config = {**VERIFICATION_DEFAULTS, **dict(value)}
    config["enabled"] = bool(config["enabled"])
    config["max_retries"] = max(0, _int_field(config, "max_retries"))
    config["cleanup_failed_output"] = bool(config["cleanup_failed_output"])
    config.pop("accept_partial_when_source_damaged", None)
    config.pop("partial_min_completeness", None)
    config["complete_accept_threshold"] = _float_field(config, "complete_accept_threshold")
    config["partial_accept_threshold"] = _float_field(config, "partial_accept_threshold")
    config["retry_on_verification_failure"] = bool(config["retry_on_verification_failure"])
    config["methods"] = _normalize_methods(config.get("methods"))
    return config


def _int_field(config: dict[str, Any], name: str) -> int:
    try:
        return int(config[name])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"verification.{name} must be an integer") from exc


def _float_field(config: dict[str, Any], name: str) -> float:
    try:
        return float(config[name])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"verification.{name} must be a number") from exc


def _normalize_methods(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("verification.methods must be a list")
    methods = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"verification.methods[{index}] must be an object")
        name = str(item.get("name") or "").strip()
        if not name:
            raise ValueError(f"verification.methods[{index}].name must not be empty")
        normalized = dict(item)
        normalized["name"] = name
        normalized["enabled"] = bool(item.get("enabled", True))
        methods.append(normalized)
    return methods


CONFIG_FIELDS = (
    ConfigField(
        path=("verification",),
        default=None,
        normalize=normalize_verification_config,
        owner=__name__,
    ),
)
