from __future__ import annotations

from dataclasses import dataclass

from sunpack.core.analysis.observation import FormatObservation


DEFAULT_MAX_ENTRIES_TO_WALK = 64
DEFAULT_DETECTION_ENTRIES_TO_WALK = 8


@dataclass(frozen=True, slots=True)
class TarProbeOptions:
    start_offset: int = 0
    max_entries_to_walk: int = DEFAULT_MAX_ENTRIES_TO_WALK

    def __post_init__(self) -> None:
        if self.start_offset < 0:
            raise ValueError("TAR probe start_offset must be non-negative")
        if self.max_entries_to_walk <= 0:
            raise ValueError("TAR entry-walk budget must be positive")


def probe_tar_view(view, options: TarProbeOptions | None = None) -> FormatObservation:
    options = options or TarProbeOptions()
    start = int(options.start_offset)
    raw = dict(view.probe_tar(
        start_offset=start,
        max_entries_to_walk=int(options.max_entries_to_walk),
    ) or {})
    raw.setdefault("archive_offset", start)
    raw.setdefault("detected_ext", ".tar" if raw.get("plausible") else "")

    error = str(raw.get("error") or "")
    damage_flags = list(raw.get("damage_flags") or [])
    if error and error not in {"tar_end_zero_blocks_not_found", "tar_walk_budget_exhausted"}:
        damage_flags.append(error)
    damage_flags = sorted(set(str(item) for item in damage_flags if item))
    boundary_confidence = str(raw.get("boundary_confidence") or "unknown")
    if raw.get("stored_checksum"):
        integrity_confidence = (
            "high"
            if raw.get("stored_checksum") == raw.get("computed_checksum")
            else "low"
        )
    else:
        integrity_confidence = "unknown"
    raw["integrity_confidence"] = integrity_confidence
    raw["damage_flags"] = damage_flags
    return FormatObservation(
        format="tar",
        start_offset=start,
        raw=raw,
        capabilities=frozenset({"tar_header", "tar_entry_walk"}),
        damage_flags=tuple(damage_flags),
        boundary_confidence=boundary_confidence,
        integrity_confidence=integrity_confidence,
    )
