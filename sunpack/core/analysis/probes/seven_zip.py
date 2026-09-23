from __future__ import annotations

from dataclasses import dataclass

from sunpack.core.analysis.observation import FormatObservation


DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class SevenZipProbeOptions:
    start_offset: int = 0
    max_next_header_check_bytes: int = DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES

    def __post_init__(self) -> None:
        if self.start_offset < 0:
            raise ValueError("7z probe start_offset must be non-negative")
        if self.max_next_header_check_bytes < 0:
            raise ValueError("7z next-header check budget must be non-negative")


def probe_seven_zip_view(view, options: SevenZipProbeOptions | None = None) -> FormatObservation:
    options = options or SevenZipProbeOptions()
    start = int(options.start_offset)
    raw = dict(view.probe_seven_zip(
        start_offset=start,
        max_next_header_check_bytes=int(options.max_next_header_check_bytes),
    ) or {})
    header = view.read_at(start, 32)
    magic_matched = bool(raw.get("magic_matched"))
    version_major = header[6] if len(header) >= 8 and magic_matched else 0
    version_minor = header[7] if len(header) >= 8 and magic_matched else 0
    raw.update({
        "format": "7z" if magic_matched else str(raw.get("format") or "7z"),
        "detected_ext": ".7z" if magic_matched else "",
        "archive_offset": int(raw.get("archive_offset") or start),
        "version_major": version_major,
        "version_minor": version_minor,
        "next_header_semantic_ok": bool(
            raw.get("next_header_crc_ok") and raw.get("next_header_nid_valid")
        ),
        "confidence": "strong" if raw.get("plausible") else "none",
    })
    if magic_matched and version_major != 0:
        raw.update({
            "plausible": False,
            "strong_accept": False,
            "error": "unsupported_version",
            "confidence": "none",
        })

    error = str(raw.get("error") or "")
    damage_flags = list(raw.get("damage_flags") or [])
    if error:
        damage_flags.append(error)
    damage_flags = sorted(set(str(item) for item in damage_flags if item))
    if error in {"start_header_crc_mismatch", "next_header_out_of_range", "invalid_next_header_range"}:
        boundary_confidence = "none"
    elif raw.get("segment_end"):
        boundary_confidence = "high" if raw.get("strong_accept") else "medium"
    else:
        boundary_confidence = "unknown"
    if raw.get("next_header_crc_checked"):
        integrity_confidence = "high" if raw.get("next_header_crc_ok") else "low"
    else:
        integrity_confidence = "unknown"
    raw.setdefault("boundary_confidence", boundary_confidence)
    raw.setdefault("integrity_confidence", integrity_confidence)
    raw.setdefault("damage_flags", damage_flags)
    return FormatObservation(
        format="7z",
        start_offset=start,
        raw=raw,
        capabilities=frozenset({"seven_zip_start_header", "seven_zip_next_header"}),
        damage_flags=tuple(damage_flags),
        boundary_confidence=boundary_confidence,
        integrity_confidence=integrity_confidence,
    )

