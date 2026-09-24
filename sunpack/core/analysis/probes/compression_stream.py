from __future__ import annotations

from dataclasses import dataclass

from sunpack_native import (
    inspect_compression_stream_identity as _native_inspect_compression_identity,
    inspect_compression_stream_structure as _native_inspect_compression_stream,
)

from sunpack.core.analysis.observation import FormatObservation
from sunpack.core.analysis.view import SharedBinaryView
from sunpack.core.support.global_cache_manager import cached_value, file_identity


SUPPORTED_COMPRESSION_FORMATS = frozenset({"gzip", "bzip2", "xz", "zstd"})


@dataclass(frozen=True, slots=True)
class CompressionStreamProbeOptions:
    format: str = ""
    identity_only: bool = False

    def __post_init__(self) -> None:
        if self.format and self.format not in SUPPORTED_COMPRESSION_FORMATS:
            raise ValueError(f"unsupported compression format: {self.format}")


def _observation(raw: dict, requested_format: str = "") -> FormatObservation:
    actual_format = str(raw.get("format") or "")
    if requested_format and actual_format != requested_format:
        raw = {
            "format": requested_format,
            "actual_format": actual_format,
            "magic_matched": False,
            "plausible": False,
            "structure_status": "invalid",
            "structure_validation_complete": False,
            "integrity_status": "failed",
            "integrity_validation_complete": True,
            "boundary_exact": False,
            "error": f"{requested_format}_magic_not_found",
            "damage_flags": [],
            "evidence": [],
        }
        actual_format = requested_format
    structure_complete = bool(raw.get("structure_validation_complete"))
    integrity_status = str(raw.get("integrity_status") or "")
    if not integrity_status:
        integrity_status = "deferred"
    raw.setdefault("structure_status", "complete" if structure_complete else "incomplete")
    raw.setdefault("structure_validation_complete", structure_complete)
    raw.setdefault("boundary_exact", structure_complete)
    raw.setdefault("integrity_status", integrity_status)
    raw.setdefault("integrity_validation_complete", integrity_status in {"verified", "failed"})
    trailing = int(raw.get("archive.trailing_data") or 0)
    damage_flags = sorted(set(str(item) for item in (raw.get("damage_flags") or []) if item))
    error = str(raw.get("error") or "")
    if structure_complete and raw.get("boundary_exact") and not damage_flags and trailing == 0:
        boundary_confidence = "high"
        integrity_confidence = "high" if integrity_status == "verified" else "unknown"
    elif damage_flags or error:
        boundary_confidence = "low"
        integrity_confidence = "low"
    elif raw.get("plausible"):
        boundary_confidence = "medium"
        integrity_confidence = "unknown"
    else:
        boundary_confidence = "none"
        integrity_confidence = "unknown"
    file_size = int(raw.get("file_size") or 0)
    raw.setdefault("segment_end", file_size - trailing if structure_complete and file_size >= trailing else None)
    raw["boundary_confidence"] = boundary_confidence
    raw["integrity_confidence"] = integrity_confidence
    raw.setdefault("damage_flags", damage_flags)
    capabilities = {"compression_header"}
    if structure_complete:
        capabilities.add("compression_structure_validation")
    if integrity_status == "verified":
        capabilities.add("compression_integrity_validation")
    return FormatObservation(
        format=actual_format or requested_format,
        start_offset=0,
        raw=raw,
        capabilities=frozenset(capabilities),
        damage_flags=tuple(damage_flags),
        boundary_confidence=boundary_confidence,
        integrity_confidence=integrity_confidence,
    )


def probe_compression_stream_path(
    path: str,
    options: CompressionStreamProbeOptions | None = None,
) -> FormatObservation:
    options = options or CompressionStreamProbeOptions()
    identity = file_identity(path)
    namespace = "analysis_compression_stream_identity" if options.identity_only else "analysis_compression_stream"
    probe = _native_inspect_compression_identity if options.identity_only else _native_inspect_compression_stream
    raw = cached_value(
        namespace,
        (identity,),
        lambda: dict(probe(path)),
    )
    return _observation(dict(raw), options.format)


def probe_compression_stream_view(
    view,
    options: CompressionStreamProbeOptions,
) -> FormatObservation:
    if isinstance(view, SharedBinaryView):
        return probe_compression_stream_path(view.path, options)
    raw = dict(view.probe_compression_stream(format=options.format) or {})
    raw.setdefault("validation_scope", "header_only")
    raw.setdefault("structure_status", "incomplete")
    raw.setdefault("structure_validation_complete", False)
    raw.setdefault("boundary_exact", False)
    raw.setdefault("integrity_status", "deferred")
    raw.setdefault("integrity_validation_complete", False)
    raw.setdefault("file_size", int(view.size))
    return _observation(raw, options.format)
