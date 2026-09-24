from __future__ import annotations

from pathlib import Path
from typing import Any

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, InputExtent


# These are real multi-volume container families: concatenating their files does
# not produce the byte stream seen by the archive handler.  They must be handed
# to the volume-aware 7z.dll verifier with their structured part metadata.
_VOLUME_CALLBACK_STYLES = {
    "rar_part",
    "rar_oldstyle",
    "rar_sfx_part",
    "sfx_numeric_suffix",
    "zip_spanned",
}


def structured_volume_input(
    archive_path: str,
    *,
    part_paths: list[str] | None = None,
    archive_input: dict[str, Any] | None = None,
) -> tuple[str, list[dict[str, Any]]] | None:
    if not archive_input:
        return None
    descriptor = ArchiveInputDescriptor.from_dict(
        archive_input,
        archive_path=archive_path,
        part_paths=part_paths,
    )
    if descriptor.open_mode not in {"native_volumes", "sfx_with_volumes"}:
        return None
    return descriptor.volume_style, [part.to_dict() for part in descriptor.parts]


def requires_volume_aware_verifier(
    archive_path: str,
    *,
    part_paths: list[str] | None = None,
    archive_input: dict[str, Any] | None = None,
) -> bool:
    if not archive_input:
        return bool(part_paths)
    descriptor = ArchiveInputDescriptor.from_dict(
        archive_input,
        archive_path=archive_path,
        part_paths=part_paths,
    )
    return (
        descriptor.open_mode == "sfx_with_volumes"
        or (
            descriptor.open_mode == "native_volumes"
            and descriptor.volume_style in _VOLUME_CALLBACK_STYLES
        )
    )


def verifier_input(
    archive_path: str,
    *,
    part_paths: list[str] | None = None,
    archive_input: dict[str, Any] | None = None,
) -> tuple[str, list[dict[str, Any]] | None]:
    if not archive_input:
        return archive_path, None

    descriptor = ArchiveInputDescriptor.from_dict(
        archive_input,
        archive_path=archive_path,
        part_paths=part_paths,
    )
    if descriptor.open_mode in {"file", "sfx_with_volumes"}:
        return descriptor.entry_path or archive_path, None

    if descriptor.open_mode == "native_volumes":
        if descriptor.volume_style in _VOLUME_CALLBACK_STYLES:
            return descriptor.entry_path or archive_path, None
        # Numeric .001/.002-style volumes are raw byte splits.  Present their
        # complete logical stream to format-specific bounded verifiers instead
        # of accidentally probing only the first physical file.
        ranges = [
            InputExtent(path=part.path, start=0, end=None)
            for part in descriptor.parts
        ]
        return descriptor.entry_path or archive_path, [item.to_dict() for item in ranges]

    ranges = _descriptor_ranges(descriptor)
    if not ranges:
        return descriptor.entry_path or archive_path, None
    if len(ranges) == 1 and _is_whole_file_range(ranges[0]):
        return ranges[0].path, None
    return descriptor.entry_path or archive_path, [item.to_dict() for item in ranges]


def _descriptor_ranges(descriptor: ArchiveInputDescriptor) -> list[InputExtent]:
    if descriptor.extents:
        return list(descriptor.extents)
    return [part.extent for part in descriptor.parts]


def _is_whole_file_range(item: InputExtent) -> bool:
    if int(item.start or 0) != 0:
        return False
    if item.end is None:
        return True
    try:
        return Path(item.path).stat().st_size == int(item.end)
    except OSError:
        return False
