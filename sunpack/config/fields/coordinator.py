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


DEFAULT_RECURSIVE_AUTHORIZATION = advanced_config_value(("recursive_authorization",))


def normalize_recursive_authorization(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("recursive_authorization must be an object")
    unknown_fields = set(value) - set(DEFAULT_RECURSIVE_AUTHORIZATION)
    if unknown_fields:
        names = ", ".join(sorted(unknown_fields))
        raise ValueError(f"recursive_authorization has unknown fields: {names}")
    config = {**DEFAULT_RECURSIVE_AUTHORIZATION, **value}
    if not isinstance(config.get("enabled"), bool):
        raise ValueError("recursive_authorization.enabled must be boolean")
    try:
        byte_ratio_exponent = float(config["byte_ratio_exponent"])
        project_ratio_exponent = float(config["project_ratio_exponent"])
        authorization_bias = float(config["authorization_bias"])
        minimum_score = float(config["minimum_authorization_score"])
        minimum_ratio = float(config["minimum_archive_byte_ratio"])
    except (TypeError, ValueError) as exc:
        raise ValueError("recursive_authorization thresholds must be numeric") from exc
    hard_maximum = config["hard_maximum_other_projects"]
    if isinstance(hard_maximum, bool) or not isinstance(hard_maximum, int):
        raise ValueError(
            "recursive_authorization.hard_maximum_other_projects must be an integer"
        )
    if not math.isfinite(byte_ratio_exponent) or byte_ratio_exponent <= 0.0:
        raise ValueError(
            "recursive_authorization.byte_ratio_exponent must be positive"
        )
    if not math.isfinite(project_ratio_exponent) or project_ratio_exponent <= 0.0:
        raise ValueError(
            "recursive_authorization.project_ratio_exponent must be positive"
        )
    if not math.isfinite(authorization_bias):
        raise ValueError("recursive_authorization.authorization_bias must be finite")
    if not math.isfinite(minimum_score) or not 0.0 <= minimum_score <= 1.0:
        raise ValueError(
            "recursive_authorization.minimum_authorization_score must be between 0 and 1"
        )
    if not math.isfinite(minimum_ratio) or not 0.0 <= minimum_ratio <= 1.0:
        raise ValueError(
            "recursive_authorization.minimum_archive_byte_ratio must be between 0 and 1"
        )
    if hard_maximum < 0:
        raise ValueError(
            "recursive_authorization.hard_maximum_other_projects must be non-negative"
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
        path=("recursive_authorization",),
        default=DEFAULT_RECURSIVE_AUTHORIZATION,
        normalize=normalize_recursive_authorization,
        owner=__name__,
    ),
)
