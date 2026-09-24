from __future__ import annotations

from sunpack.core.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
    ArchiveInputSegment,
)
from sunpack.pipeline.discovery.relations.internal.models import CandidateGroup


def archive_input_for_group(group: CandidateGroup) -> ArchiveInputDescriptor | None:
    metadata = dict(group.head_metadata or {})
    format_hint = str(metadata.get("format") or "").lower().lstrip(".")

    if group.split_volumes:
        return ArchiveInputDescriptor.from_split_volumes(
            archive_path=group.entry_path,
            volumes=group.split_volumes,
            format_hint=format_hint,
            logical_name=group.logical_name,
        )

    if not metadata.get("relation_confirmed"):
        return None

    structure_offset = int(metadata.get("structure_offset") or 0)
    if structure_offset > 0 and bool(metadata.get("sfx")):
        range_end = (
            int(metadata["expected_logical_size"])
            if isinstance(metadata.get("expected_logical_size"), int)
            and int(metadata["expected_logical_size"]) > structure_offset
            else None
        )
        archive_range = ArchiveInputRange(
            path=group.entry_path,
            start=structure_offset,
            end=range_end,
        )
        return ArchiveInputDescriptor(
            entry_path=group.entry_path,
            open_mode="file_range",
            format_hint=format_hint,
            logical_name=group.logical_name,
            parts=[
                ArchiveInputPart(
                    path=group.entry_path,
                    role="main",
                    range=archive_range,
                )
            ],
            segment=ArchiveInputSegment(
                start=structure_offset,
                end=range_end,
                source="relations",
            ),
        )

    return ArchiveInputDescriptor.from_parts(
        archive_path=group.entry_path,
        part_paths=list(group.input_paths or [group.entry_path]),
        format_hint=format_hint,
        logical_name=group.logical_name,
    )
