from typing import Any

from sunpack.pipeline.verification.registry import registered_verification_methods


def validate_config_payload(config: dict) -> dict[str, Any]:
    """Check registered methods in an already normalized configuration."""
    available = registered_verification_methods()
    errors = []
    for index, method in enumerate(config["verification"]["methods"]):
        if method["name"] not in available:
            errors.append(f"Unknown verification method at verification.methods[{index}]: {method['name']}")
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": [],
        "available_verification_methods": sorted(available),
    }
