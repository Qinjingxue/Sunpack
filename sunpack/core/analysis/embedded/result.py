from __future__ import annotations

from typing import Any


_HIT_FORMATS = {
    "zip_local": "zip",
    "zip_eocd": "zip",
    "rar4": "rar",
    "rar5": "rar",
    "7z": "7z",
    "gzip": "gzip",
    "bzip2": "bzip2",
    "xz": "xz",
    "zstd": "zstd",
    "lz4": "lz4",
    "lz4_skippable": "lz4",
    "tar_ustar": "tar",
}


def embedded_scan_prepass(scan: dict[str, Any]) -> dict[str, Any]:
    """Project canonical scan rows without rebuilding candidate dictionaries."""
    formats = {item["format"] for item in scan["candidates"]}
    return {
        "hits": [item for item in scan["hits"] if _HIT_FORMATS.get(item["name"]) in formats],
        "formats": sorted(formats),
        "full_scan_bytes": scan["read_bytes"],
        "full_scan_complete": scan["complete"],
        "logical_resolution_complete": scan["logical_resolution_complete"],
        "raw_hit_count": scan["raw_hit_count"],
        "embedded_scan_budget_exhausted": scan["budget_exhausted"],
        "source": "embedded_scan",
        "embedded_candidates": scan["candidates"],
    }


def embedded_candidate_requires_password(format_hint: str, validation: str) -> bool:
    return format_hint == "rar" and validation.startswith((
        "rar4_header_encrypted_main_header_crc",
        "rar5_encryption_header_crc",
    ))
