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
    return raw, [_native_inventory_observation(item, method) for item in raw.pop("observations")]


def _native_inventory_observation(
    raw: dict[str, Any],
    method: str,
) -> FileVerificationObservation:
    archive_path = raw["archive_path"] or raw["path"]
    return FileVerificationObservation(
        path=raw["path"] or archive_path,
        archive_path=archive_path,
        state=raw["state"],
        method=method,
        bytes_written=raw["bytes_written"],
        expected_size=raw["expected_size"],
        progress=raw["progress"],
        crc_expected=raw["crc_expected"],
        crc_actual=raw["crc_actual"],
        details=raw["details"],
    )
