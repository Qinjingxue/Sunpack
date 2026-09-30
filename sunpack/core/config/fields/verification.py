from typing import Any

from sunpack.core.config.advanced_defaults import advanced_config_value
from sunpack.core.config.schema import ConfigField, require_boolean


VERIFICATION_DEFAULTS = advanced_config_value(("verification",))
METHOD_DEFAULTS = {item["name"]: item for item in VERIFICATION_DEFAULTS["methods"]}


def normalize_verification_config(value: Any) -> dict[str, Any]:
    if value is None:
        raise ValueError("Missing required config object: verification")
    if not isinstance(value, dict):
        raise ValueError("verification must be an object")
    unknown = set(value) - set(VERIFICATION_DEFAULTS)
    if unknown:
        raise ValueError(
            f"verification has unknown fields: {', '.join(sorted(unknown))}"
        )
    config = {**VERIFICATION_DEFAULTS, **dict(value)}
    config["enabled"] = require_boolean(config["enabled"], "verification.enabled")
    config["max_retries"] = max(0, _int_field(config, "max_retries"))
    config["cleanup_failed_output"] = require_boolean(
        config["cleanup_failed_output"],
        "verification.cleanup_failed_output",
    )
    config["complete_accept_threshold"] = min(1.0, max(0.0, _float_field(config, "complete_accept_threshold")))
    config["partial_accept_threshold"] = min(1.0, max(0.0, _float_field(config, "partial_accept_threshold")))
    config["retry_on_verification_failure"] = require_boolean(
        config["retry_on_verification_failure"],
        "verification.retry_on_verification_failure",
    )
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
        defaults = METHOD_DEFAULTS.get(name, {})
        normalized = {**defaults, **item}
        normalized["name"] = name
        normalized["enabled"] = require_boolean(
            item.get("enabled", True),
            f"verification.methods[{index}].enabled",
        )
        for key, default in defaults.items():
            if type(default) in (int, float):
                try:
                    normalized[key] = max(0, type(default)(normalized[key]))
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"verification.methods[{index}].{key} must be a number") from exc
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
