from __future__ import annotations

from dataclasses import dataclass

from sunpack.core.analysis.observation import FormatObservation


DEFAULT_MAX_BLOCKS_TO_WALK = 4096
DEFAULT_DETECTION_BLOCKS_TO_WALK = 2

_TRUNCATION_ERRORS = {
    "rar4_block_header_out_of_range",
    "rar4_block_size_out_of_range",
    "rar4_block_payload_out_of_range",
    "rar4_block_add_size_missing",
    "rar5_block_header_out_of_range",
    "rar5_header_size_out_of_range",
    "rar5_block_payload_out_of_range",
}


@dataclass(frozen=True, slots=True)
class RarProbeOptions:
    start_offset: int = 0
    max_blocks_to_walk: int = DEFAULT_MAX_BLOCKS_TO_WALK
    accept_validated_prefix: bool = False

    def __post_init__(self) -> None:
        if self.start_offset < 0:
            raise ValueError("RAR probe start_offset must be non-negative")
        if self.max_blocks_to_walk <= 0:
            raise ValueError("RAR block-walk budget must be positive")


def probe_rar_view(view, options: RarProbeOptions | None = None) -> FormatObservation:
    """Run the shared RAR block probe and preserve both detection and analysis evidence."""
    options = options or RarProbeOptions()
    start = int(options.start_offset)
    raw = dict(view.probe_rar(
        start_offset=start,
        max_blocks_to_walk=int(options.max_blocks_to_walk),
    ) or {})
    magic_matched = bool(raw.get("magic_matched"))

    checked = int(raw.get("blocks_checked") or 0)
    header_crc_checked = bool(raw.get("header_crc_checked", magic_matched and checked >= 1))
    first_header_ok = bool(raw.get("header_crc_ok", magic_matched and checked >= 1))
    second_block_checked = bool(raw.get("second_block_checked", checked >= 2))
    second_block_ok = bool(raw.get("second_block_ok", checked >= 2))
    validated_prefix = second_block_checked and second_block_ok
    walk_limit = str(raw.get("error") or "") in {
        "rar4_block_walk_limit_reached",
        "rar5_block_walk_limit_reached",
    }
    accept_prefix = bool(options.accept_validated_prefix and validated_prefix and walk_limit)
    raw.update({
        "format": "rar" if magic_matched else "",
        "detected_ext": ".rar" if magic_matched else "",
        "archive_offset": int(raw.get("archive_offset") or start),
        "plausible": bool(raw.get("plausible") or first_header_ok),
        "header_crc_checked": header_crc_checked,
        "header_crc_ok": first_header_ok,
        "second_block_checked": second_block_checked,
        "second_block_ok": second_block_ok,
        "block_walk_ok": bool(raw.get("block_walk_ok") or raw.get("end_block_found") or accept_prefix),
        "validated_prefix": validated_prefix,
        "strong_accept": bool(raw.get("strong_accept") or accept_prefix),
        "confidence": "strong" if first_header_ok else "none",
    })
    if accept_prefix:
        raw["walk_limit_reached"] = True
        raw["error"] = ""

    error = str(raw.get("error") or "")
    damage_flags = list(raw.get("damage_flags") or [])
    if error and not walk_limit:
        damage_flags.append(error)
    if checked > 0 and error in _TRUNCATION_ERRORS:
        damage_flags.append("probably_truncated")
    damage_flags = sorted(set(str(item) for item in damage_flags if item))
    if raw.get("end_block_found"):
        boundary_confidence = "high"
    elif raw.get("header_encrypted") or error:
        boundary_confidence = "low"
    elif validated_prefix:
        boundary_confidence = "medium"
    else:
        boundary_confidence = "unknown"
    if first_header_ok:
        integrity_confidence = "high"
    elif magic_matched:
        integrity_confidence = "low"
    else:
        integrity_confidence = "unknown"
    raw.setdefault("boundary_confidence", boundary_confidence)
    raw.setdefault("integrity_confidence", integrity_confidence)
    raw["damage_flags"] = damage_flags
    return FormatObservation(
        format="rar",
        start_offset=start,
        raw=raw,
        capabilities=frozenset({"rar_first_header", "rar_block_walk"}),
        damage_flags=tuple(damage_flags),
        boundary_confidence=boundary_confidence,
        integrity_confidence=integrity_confidence,
    )
