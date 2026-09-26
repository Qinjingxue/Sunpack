from __future__ import annotations

import threading
from typing import Any

from sunpack.core.analysis.embedded.result import EmbeddedCandidate, EmbeddedScanResult, SignatureHit
from sunpack.core.support.archive_sessions import get_archive_session
from sunpack.core.support.global_cache_manager import GLOBAL_CACHE, file_identity


_CACHE_NAMESPACE = "embedded_archive_scan_v4"
GLOBAL_CACHE.register_immutable_namespace(_CACHE_NAMESPACE)
_SCAN_LOCKS = tuple(threading.Lock() for _ in range(32))

_RESULT_FIELDS = frozenset({
    "complete",
    "signature_scan_complete",
    "logical_resolution_complete",
    "raw_hit_count",
    "budget_exhausted",
    "candidates",
    "hits",
    "read_bytes",
    "file_size",
})
_CANDIDATE_FIELDS = frozenset({
    "format",
    "offset",
    "end_offset",
    "confidence",
    "validation",
    "candidate_kind",
    "boundary_kind",
    "extractable",
})
_HIT_FIELDS = frozenset({"name", "offset"})


def _require_fields(value: dict[str, Any], required: frozenset[str], context: str) -> None:
    missing = sorted(required.difference(value))
    if missing:
        raise TypeError(f"{context} missing required fields: {', '.join(missing)}")


def scan_embedded_archives(
    path: str,
    *,
    expected_size: int = 0,
    identity: tuple[str, int, int] | None = None,
) -> EmbeddedScanResult:
    """Run the canonical native full-stream embedded scan at most once per file identity."""
    cache_key = identity or file_identity(path)
    result = GLOBAL_CACHE.get(_CACHE_NAMESPACE, cache_key)
    if result is None:
        lock = _SCAN_LOCKS[hash(cache_key) % len(_SCAN_LOCKS)]
        with lock:
            result = GLOBAL_CACHE.get(_CACHE_NAMESPACE, cache_key)
            if result is None:
                session = get_archive_session(path)
                native_result = session.scan_embedded_archives()
                result = _normalize_native_result(
                    native_result,
                    expected_size,
                )
                GLOBAL_CACHE.set(_CACHE_NAMESPACE, cache_key, result)
    return result


def _normalize_native_result(value: Any, expected_size: int) -> EmbeddedScanResult:
    if not isinstance(value, dict):
        raise TypeError("Native scan_embedded_archives returned a non-dict result")
    _require_fields(value, _RESULT_FIELDS, "Native scan_embedded_archives result")
    rows = value["candidates"]
    if not isinstance(rows, list):
        raise TypeError("Native scan_embedded_archives returned invalid candidates")

    candidates = []
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("Native scan_embedded_archives returned a non-dict candidate")
        _require_fields(row, _CANDIDATE_FIELDS, "Native scan_embedded_archives candidate")
        archive_format = str(row["format"] or "")
        offset = int(row["offset"])
        if not archive_format or offset < 0:
            raise TypeError("Native scan_embedded_archives returned an invalid candidate")
        end_offset = row["end_offset"]
        candidates.append(EmbeddedCandidate(
            format=archive_format,
            offset=offset,
            end_offset=None if end_offset is None else int(end_offset),
            confidence=float(row["confidence"]),
            validation=str(row["validation"]),
            candidate_kind=str(row["candidate_kind"]),
            boundary_kind=str(row["boundary_kind"]),
            extractable=bool(row["extractable"]),
        ))

    raw_hits = value["hits"]
    if not isinstance(raw_hits, list):
        raise TypeError("Native scan_embedded_archives returned invalid hits")
    validated_formats = {item.format for item in candidates}
    hit_formats = {
        "zip_local": "zip", "zip_eocd": "zip", "rar4": "rar", "rar5": "rar",
        "7z": "7z", "gzip": "gzip", "bzip2": "bzip2", "xz": "xz",
        "zstd": "zstd", "tar_ustar": "tar",
    }
    hits = []
    for row in raw_hits:
        if not isinstance(row, dict):
            raise TypeError("Native scan_embedded_archives returned a non-dict hit")
        _require_fields(row, _HIT_FIELDS, "Native scan_embedded_archives hit")
        name = str(row["name"] or "")
        offset = int(row["offset"])
        if name and offset >= 0 and hit_formats.get(name) in validated_formats:
            hits.append(SignatureHit(name=name, offset=offset))

    file_size = int(value["file_size"])
    if expected_size and file_size != int(expected_size):
        raise ValueError(
            f"Native scan_embedded_archives file_size mismatch: expected {expected_size}, got {file_size}"
        )

    return EmbeddedScanResult(
        complete=bool(value["complete"]),
        candidates=tuple(sorted(candidates, key=lambda item: (item.offset, item.format))),
        hits=tuple(sorted(hits, key=lambda item: (item.offset, item.name))),
        read_bytes=int(value["read_bytes"]),
        file_size=file_size,
        logical_resolution_complete=bool(value["logical_resolution_complete"]),
        raw_hit_count=int(value["raw_hit_count"]),
        budget_exhausted=bool(value["budget_exhausted"]),
    )


def embedded_result_from_dict(value: dict[str, Any]) -> EmbeddedScanResult:
    _require_fields(value, _RESULT_FIELDS, "Embedded scan cache result")
    for item in value["candidates"]:
        if not isinstance(item, dict):
            raise TypeError("Embedded scan cache contains a non-dict candidate")
        _require_fields(item, _CANDIDATE_FIELDS, "Embedded scan cache candidate")
    for item in value["hits"]:
        if not isinstance(item, dict):
            raise TypeError("Embedded scan cache contains a non-dict hit")
        _require_fields(item, _HIT_FIELDS, "Embedded scan cache hit")
    return EmbeddedScanResult(
        complete=bool(value["complete"]),
        candidates=tuple(
            EmbeddedCandidate(
                format=str(item["format"]),
                offset=int(item["offset"]),
                end_offset=None if item["end_offset"] is None else int(item["end_offset"]),
                confidence=float(item["confidence"]),
                validation=str(item["validation"]),
                candidate_kind=str(item["candidate_kind"]),
                boundary_kind=str(item["boundary_kind"]),
                extractable=bool(item["extractable"]),
            )
            for item in value["candidates"]
        ),
        hits=tuple(
            SignatureHit(name=str(item["name"]), offset=int(item["offset"]))
            for item in value["hits"]
        ),
        read_bytes=int(value["read_bytes"]),
        file_size=int(value["file_size"]),
        logical_resolution_complete=bool(value["logical_resolution_complete"]),
        raw_hit_count=int(value["raw_hit_count"]),
        budget_exhausted=bool(value["budget_exhausted"]),
    )


def resolve_encrypted_rar_boundaries(
    path: str,
    offsets: list[int],
    passwords: list[str],
) -> dict[str, Any]:
    """Resolve header-encrypted RAR ends with the current password sources.

    Password-dependent work is deliberately uncached. A password-source change
    simply runs this bounded header walk again.
    """
    from sunpack_native import resolve_embedded_rar_boundaries

    value = resolve_embedded_rar_boundaries(
        str(path),
        [int(offset) for offset in offsets],
        [str(password) for password in passwords],
    )
    if not isinstance(value, dict):
        raise TypeError("Native encrypted RAR boundary resolver returned a non-dict result")
    return dict(value)
