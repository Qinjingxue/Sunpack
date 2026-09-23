"""Validate the fixed single-file detection contract."""

from typing import Any


def validate_detection_contracts(payload: dict) -> dict[str, Any]:
    detection = payload.get("detection", {})
    errors = []
    if not isinstance(detection, dict):
        errors.append("detection must be an object")
    elif unknown := set(detection) - {"enabled"}:
        errors.append(f"Unknown detection field(s): {', '.join(sorted(unknown))}")
    elif not isinstance(detection.get("enabled", True), bool):
        errors.append("detection.enabled must be boolean")
    return {
        "errors": errors,
        "warnings": [],
    }
