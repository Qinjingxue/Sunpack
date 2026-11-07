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
    # Accept old settings harmlessly; they no longer affect execution.
    retired = {
        "max_retries", "cleanup_failed_output", "retry_on_verification_failure",
        "complete_accept_threshold", "partial_accept_threshold",
    }
    unknown = set(value) - set(VERIFICATION_DEFAULTS) - retired
    if unknown:
        raise ValueError(
            f"verification has unknown fields: {', '.join(sorted(unknown))}"
        )
    config = {**VERIFICATION_DEFAULTS, **{key: item for key, item in value.items() if key not in retired}}
    config["enabled"] = require_boolean(config["enabled"], "verification.enabled")
    config["methods"] = _normalize_methods(config.get("methods"))
    return config


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
        retired = {
            "manifest_size_match": {
                "file_count_abs_tolerance", "file_count_ratio_tolerance",
                "size_abs_tolerance_bytes", "size_ratio_tolerance",
            },
            "archive_test_crc": {"max_reported_items"},
        }.get(name, ())
        normalized = {**defaults, **{key: value for key, value in item.items() if key not in retired}}
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
