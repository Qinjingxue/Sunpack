import math
from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.schema import ConfigField


def normalize_recursive_extract(value: Any) -> dict[str, Any]:
    raw = str(value).strip().lower()
    if raw == "*":
        return {"mode": "infinite"}
    if raw == "?":
        return {"mode": "prompt"}
    try:
        rounds = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError('recursive_extract must be "*", "?", or a positive integer') from exc
    if rounds <= 0:
        raise ValueError('recursive_extract must be "*", "?", or a positive integer')
    return {"mode": "fixed", "max_rounds": rounds}


DEFAULT_NESTED_EXTRACTION_POLICY = advanced_config_value(("nested_extraction_policy",))


def normalize_nested_extraction_policy(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("nested_extraction_policy must be an object")
    unknown_fields = set(value) - set(DEFAULT_NESTED_EXTRACTION_POLICY)
    if unknown_fields:
        names = ", ".join(sorted(unknown_fields))
        raise ValueError(f"nested_extraction_policy has unknown fields: {names}")
    config = {**DEFAULT_NESTED_EXTRACTION_POLICY, **value}
    if not isinstance(config.get("enabled"), bool):
        raise ValueError("nested_extraction_policy.enabled must be boolean")
    try:
        byte_ratio_exponent = float(config["byte_ratio_exponent"])
        project_ratio_exponent = float(config["project_ratio_exponent"])
        authorization_bias = float(config["authorization_bias"])
        minimum_score = float(config["minimum_authorization_score"])
        minimum_ratio = float(config["minimum_archive_byte_ratio"])
    except (TypeError, ValueError) as exc:
        raise ValueError("nested_extraction_policy thresholds must be numeric") from exc
    hard_maximum = config["hard_maximum_other_projects"]
    if isinstance(hard_maximum, bool) or not isinstance(hard_maximum, int):
        raise ValueError(
            "nested_extraction_policy.hard_maximum_other_projects must be an integer"
        )
    if not math.isfinite(byte_ratio_exponent) or byte_ratio_exponent <= 0.0:
        raise ValueError(
            "nested_extraction_policy.byte_ratio_exponent must be positive"
        )
    if not math.isfinite(project_ratio_exponent) or project_ratio_exponent <= 0.0:
        raise ValueError(
            "nested_extraction_policy.project_ratio_exponent must be positive"
        )
    if not math.isfinite(authorization_bias):
        raise ValueError("nested_extraction_policy.authorization_bias must be finite")
    if not math.isfinite(minimum_score) or not 0.0 <= minimum_score <= 1.0:
        raise ValueError(
            "nested_extraction_policy.minimum_authorization_score must be between 0 and 1"
        )
    if not math.isfinite(minimum_ratio) or not 0.0 <= minimum_ratio <= 1.0:
        raise ValueError(
            "nested_extraction_policy.minimum_archive_byte_ratio must be between 0 and 1"
        )
    if hard_maximum < 0:
        raise ValueError(
            "nested_extraction_policy.hard_maximum_other_projects must be non-negative"
        )
    config["byte_ratio_exponent"] = byte_ratio_exponent
    config["project_ratio_exponent"] = project_ratio_exponent
    config["authorization_bias"] = authorization_bias
    config["minimum_authorization_score"] = minimum_score
    config["minimum_archive_byte_ratio"] = minimum_ratio
    config["hard_maximum_other_projects"] = hard_maximum
    return config


CONFIG_FIELDS = (
    ConfigField(
        path=("recursive_extract",),
        default=advanced_config_value(("recursive_extract",)),
        normalize=normalize_recursive_extract,
        owner=__name__,
    ),
    ConfigField(
        path=("nested_extraction_policy",),
        default=DEFAULT_NESTED_EXTRACTION_POLICY,
        normalize=normalize_nested_extraction_policy,
        owner=__name__,
    ),
)
