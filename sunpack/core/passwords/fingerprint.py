from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArchiveFingerprint:
    key: str
    archive_path: str
    part_paths: tuple[str, ...] = ()


def _archive_input_scope(archive_input: Any) -> str:
    """Serialize the logical input boundary for password-cache isolation."""
    if archive_input is None:
        return ""
    if hasattr(archive_input, "to_dict"):
        archive_input = archive_input.to_dict()
    if not isinstance(archive_input, dict) or not archive_input:
        return ""
    mode = str(archive_input.get("open_mode") or archive_input.get("kind") or "")
    parts = archive_input.get("parts") or []
    ranges = archive_input.get("ranges") or []
    segment = archive_input.get("segment")
    has_explicit_range = (
        mode in {"file_range", "concat_ranges"}
        or bool(ranges)
        or isinstance(segment, dict)
        or any(
            isinstance(item, dict)
            and (item.get("start") is not None or item.get("end") is not None
                 or item.get("start_offset") is not None or item.get("end_offset") is not None)
            for item in parts
        )
    )
    if not has_explicit_range:
        return ""

    def range_payload(item: Any) -> dict[str, Any]:
        if not isinstance(item, dict):
            return {}
        return {
            "path": str(item.get("path") or ""),
            "start": int(item.get("start", item.get("start_offset", 0)) or 0),
            "end": item.get("end", item.get("end_offset")),
        }

    normalized_parts = []
    for item in parts:
        if not isinstance(item, dict):
            continue
        payload = range_payload(item)
        payload.update({
            "role": str(item.get("role") or ""),
            "volume_number": item.get("volume_number"),
            "canonical_name": str(item.get("canonical_name") or ""),
        })
        normalized_parts.append(payload)
    normalized_ranges = [range_payload(item) for item in ranges]
    segment_payload = range_payload(segment) if isinstance(segment, dict) else {}
    return json.dumps({
        "entry_path": str(archive_input.get("entry_path") or archive_input.get("path") or ""),
        "open_mode": str(archive_input.get("open_mode") or archive_input.get("kind") or ""),
        "format_hint": str(archive_input.get("format_hint") or archive_input.get("format") or ""),
        "logical_name": str(archive_input.get("logical_name") or ""),
        "parts": normalized_parts,
        "ranges": normalized_ranges,
        "segment": segment_payload,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_archive_fingerprint(
    archive_path: str,
    part_paths: list[str] | None = None,
    archive_input: Any = None,
) -> ArchiveFingerprint:
    normalized_archive = str(Path(archive_path).resolve())
    normalized_parts = tuple(str(Path(path).resolve()) for path in part_paths or [])
    digest = hashlib.sha256()
    for path in (normalized_archive, *normalized_parts):
        digest.update(path.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
        try:
            stat = Path(path).stat()
        except OSError:
            digest.update(b"missing")
            continue
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(b":")
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
        digest.update(b"\0")
    scope = _archive_input_scope(archive_input)
    if scope:
        digest.update(b"logical-input\0")
        digest.update(scope.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
    return ArchiveFingerprint(
        key=digest.hexdigest(),
        archive_path=normalized_archive,
        part_paths=normalized_parts,
    )
