from __future__ import annotations

from typing import Any

from sunpack_native import executable_runtime_bundle_profile, inspect_pe_overlay_structure


def inspect_runtime_bundle(path: str, size: int, *, max_probe_bytes: int = 8 * 1024 * 1024) -> Any | None:
    """Return a validated executable runtime-bundle profile, if present."""
    overlay = dict(inspect_pe_overlay_structure(path, int(size), b""))
    if not overlay.get("is_pe"):
        return None
    profile = executable_runtime_bundle_profile(
        path,
        int(max_probe_bytes),
        int(overlay.get("overlay_offset") or 0),
        int(overlay.get("pck_section_offset") or 0),
    )
    return profile or None
