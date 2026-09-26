from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sunpack_native import (
    inspect_zip_directory_consistency as _native_zip_directory_consistency,
    inspect_zip_structure_graph as _native_zip_structure_graph,
)

from sunpack.core.analysis.observation import FormatObservation
from sunpack.core.support.global_cache_manager import cached_value, file_identity


DEFAULT_MAX_CD_ENTRIES_TO_WALK = 16
DEFAULT_MAX_DEEP_ENTRIES = 128
@dataclass(frozen=True, slots=True)
class ZipEocdProbeOptions:
    max_cd_entries_to_walk: int = DEFAULT_MAX_CD_ENTRIES_TO_WALK
    eocd_offset: int | None = None

    def __post_init__(self) -> None:
        if self.max_cd_entries_to_walk <= 0:
            raise ValueError("ZIP central-directory walk budget must be positive")
        if self.eocd_offset is not None and self.eocd_offset < 0:
            raise ValueError("ZIP EOCD offset must be non-negative")


@dataclass(frozen=True, slots=True)
class ZipDeepProbeOptions:
    max_entries: int = DEFAULT_MAX_DEEP_ENTRIES

    def __post_init__(self) -> None:
        if self.max_entries <= 0:
            raise ValueError("ZIP deep-analysis entry budget must be positive")


def _zip_observation(raw: dict[str, Any], capability: str, *, start_offset: int = 0) -> FormatObservation:
    error = str(raw.get("error") or "")
    damage_flags = sorted(set(str(item) for item in (raw.get("damage_flags") or []) if item))
    if raw.get("plausible") and not error:
        boundary_confidence = "high"
    elif raw.get("magic_matched"):
        boundary_confidence = "low"
    else:
        boundary_confidence = "none"
    if raw.get("content_integrity_warning") or damage_flags:
        integrity_confidence = "low"
    elif raw.get("local_header_links_ok") or raw.get("plausible"):
        integrity_confidence = "medium"
    else:
        integrity_confidence = "unknown"
    raw.setdefault("boundary_confidence", boundary_confidence)
    raw.setdefault("integrity_confidence", integrity_confidence)
    raw.setdefault("damage_flags", damage_flags)
    return FormatObservation(
        format="zip",
        start_offset=start_offset,
        raw=raw,
        capabilities=frozenset({capability}),
        damage_flags=tuple(damage_flags),
        boundary_confidence=boundary_confidence,
        integrity_confidence=integrity_confidence,
    )


def probe_zip_local_header_view(view, offset: int = 0) -> FormatObservation:
    offset = max(0, int(offset))
    raw = dict(view.probe_zip_local_header(offset=offset) or {})
    return _zip_observation(raw, "zip_local_header", start_offset=offset)


def find_zip_eocd(view) -> tuple[int | None, dict[str, Any]]:
    candidate = dict(view.locate_zip_eocd() or {})
    if not candidate.get("eocd_candidate_found"):
        return None, candidate
    return int(candidate.get("eocd_candidate_offset") or 0), candidate


def probe_zip_eocd_view(view, options: ZipEocdProbeOptions | None = None) -> FormatObservation:
    options = options or ZipEocdProbeOptions()
    if options.eocd_offset is None:
        eocd_offset, candidate = find_zip_eocd(view)
    else:
        candidate = dict(view.locate_zip_eocd(eocd_offset=int(options.eocd_offset)) or {})
        eocd_offset = (
            int(candidate.get("eocd_candidate_offset") or 0)
            if candidate.get("eocd_candidate_found")
            else None
        )
    if eocd_offset is None:
        return _zip_observation(
            {"plausible": False, "magic_matched": False, "error": "eocd_not_found", **candidate},
            "zip_eocd",
        )
    raw = dict(view.probe_zip(
        eocd_offset=eocd_offset,
        max_cd_entries_to_walk=min(256, int(options.max_cd_entries_to_walk)),
    ) or {})
    raw.update(candidate)
    raw.setdefault("comment_length", int(candidate.get("eocd_candidate_comment_length") or 0))
    raw.setdefault("declared_central_directory_offset", int(candidate.get("eocd_candidate_cd_offset") or 0))
    raw.setdefault("declared_central_directory_size", int(candidate.get("eocd_candidate_cd_size") or 0))
    raw.setdefault("declared_total_entries", int(raw.get("total_entries") or 0))
    raw.setdefault("trailing_bytes_after_eocd", max(0, int(view.size) - int(raw.get("segment_end") or view.size)))
    physical_cd = int(raw.get("central_directory_offset") or 0)
    declared_cd = int(raw.get("declared_central_directory_offset") or 0)
    raw.setdefault("physical_central_directory_offset", physical_cd)
    raw.setdefault("inferred_central_directory_offset", physical_cd)
    raw.setdefault("inferred_central_directory_size", int(raw.get("central_directory_size") or 0))
    raw.setdefault("central_directory_offset_delta", physical_cd - declared_cd)
    raw.setdefault("central_directory_size_delta", 0)
    raw.setdefault("entry_count_delta", 0)
    links = int(raw.get("local_header_links_checked") or 0)
    raw.setdefault("local_header_links_ok_count", links if raw.get("local_header_links_ok") else 0)
    raw.setdefault("local_header_links_error_count", 0 if raw.get("local_header_links_ok") else 1)
    return _zip_observation(raw, "zip_eocd", start_offset=int(raw.get("archive_offset") or 0))


def probe_zip_directory_consistency_path(
    path: str,
    options: ZipDeepProbeOptions | None = None,
    *,
    identity: tuple[Any, ...] | None = None,
) -> FormatObservation:
    options = options or ZipDeepProbeOptions()
    cache_identity = identity or file_identity(path)
    raw = cached_value(
        "analysis_zip_directory_consistency",
        (cache_identity, int(options.max_entries)),
        lambda: dict(_native_zip_directory_consistency(path, int(options.max_entries))),
    )
    return _zip_observation(dict(raw), "zip_directory_consistency")


def probe_zip_structure_graph_path(
    path: str,
    options: ZipDeepProbeOptions | None = None,
    *,
    identity: tuple[Any, ...] | None = None,
) -> FormatObservation:
    options = options or ZipDeepProbeOptions()
    cache_identity = identity or file_identity(path)
    raw = cached_value(
        "analysis_zip_structure_graph",
        (cache_identity, int(options.max_entries)),
        lambda: dict(_native_zip_structure_graph(path, int(options.max_entries))),
    )
    return _zip_observation(dict(raw), "zip_structure_graph")
