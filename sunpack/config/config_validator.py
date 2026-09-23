from typing import Any

from sunpack.config.schema import get_config_value, normalize_config_value
from sunpack.config.schema import validate_external_config
from sunpack.detection import validate_detection_contracts
from sunpack.verification.registry import registered_verification_methods


def _validate_verification_methods(payload: dict) -> tuple[list[str], list[str]]:
    errors = []
    try:
        methods = normalize_config_value(("verification",), get_config_value(payload, ("verification",))).get("methods", [])
        available_methods = sorted(registered_verification_methods())
    except Exception as exc:
        return [f"Unable to load verification methods: {exc}"], []

    available = set(available_methods)
    for index, method in enumerate(methods):
        name = method["name"]
        if name not in available:
            errors.append(f"Unknown verification method at verification.methods[{index}]: {name}")
    return errors, available_methods


def validate_config_payload(payload: dict) -> dict[str, Any]:
    detection_result = validate_detection_contracts(payload)
    errors = list(detection_result["errors"])
    errors.extend(validate_external_config(payload))
    verification_errors, available_verification_methods = _validate_verification_methods(payload)
    errors.extend(verification_errors)
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": detection_result["warnings"],
        "available_verification_methods": available_verification_methods,
    }
