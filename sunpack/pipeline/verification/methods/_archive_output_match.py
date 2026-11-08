from __future__ import annotations

from typing import Any

from sunpack.pipeline.verification.archive_input_manifest import ArchiveInputManifest
from sunpack.core.contracts.verification import FileVerificationObservation


def match_archive_output(
    manifest: ArchiveInputManifest,
    inventory,
    *,
    method: str,
    verify_crc: bool = False,
    names_only: bool = False,
    include_observations: bool = False,
) -> tuple[dict[str, Any], list[FileVerificationObservation]]:
    # Match straight from the complete Rust entry table.
    raw = inventory.verification_match(
        manifest.entries if manifest.entries is not None else [],
        verify_crc=verify_crc,
        names_only=names_only,
        include_observations=include_observations,
        detail_limit=min(manifest.retained_file_count, 128) if include_observations else 0,
    )
    return raw, [_native_inventory_observation(item, method) for item in raw["observations"]]


def _native_inventory_observation(
    raw: dict[str, Any],
    method: str,
) -> FileVerificationObservation:
    archive_path = str(raw.get("archive_path") or raw.get("path") or "")
    return FileVerificationObservation(
        path=str(raw.get("path") or archive_path),
        archive_path=archive_path,
        state=str(raw.get("state") or "unverified"),
        method=method,
        bytes_written=int(raw.get("bytes_written", 0) or 0),
        expected_size=_optional_int(raw.get("expected_size")),
        progress=_optional_float(raw.get("progress")),
        crc_expected=_optional_crc(raw.get("crc_expected")),
        crc_actual=_optional_crc(raw.get("crc_actual")),
        details=dict(raw.get("details") or {}),
    )


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_crc(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None
