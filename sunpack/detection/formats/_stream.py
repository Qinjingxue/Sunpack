"""Conditions shared by independent compression-stream plugins."""


def confirmed_stream(observation: dict, expected_format: str) -> bool:
    return bool(
        observation.get("plausible")
        and observation.get("structure_validation_complete")
        and observation.get("boundary_exact")
        and observation.get("structure_status") == "complete"
        and observation.get("confidence") == "strong"
        and not observation.get("damage_flags")
        and not observation.get("archive.trailing_data")
        and observation.get("format") == expected_format
    )
