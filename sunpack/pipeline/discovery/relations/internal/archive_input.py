from __future__ import annotations
from dataclasses import replace

from sunpack.core.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    InputExtent,
)
from sunpack.pipeline.discovery.relations.internal.models import CandidateGroup


def archive_input_for_group(group: CandidateGroup) -> ArchiveInputDescriptor | None:
    metadata = dict(group.head_metadata or {})
    format_hint = str(metadata.get("format") or "").lower().lstrip(".")
    zip_eocd = metadata.get("zip_eocd_offset") if format_hint == "zip" else None

    if group.split_volumes:
        descriptor = ArchiveInputDescriptor.from_split_volumes(
            archive_path=group.entry_path,
            volumes=group.split_volumes,
            format_hint=format_hint,
            logical_name=group.logical_name,
        )
        analysis = {"volume_completeness": "missing" if metadata.get("volume_set_incomplete") else (
            "unknown" if metadata.get("needs_password") else "complete")}
        if isinstance(zip_eocd, int):
            analysis["zip_eocd_offset"] = zip_eocd
        if metadata.get("volume_set_incomplete") and metadata.get("relation_failure_reason") == "missing_volume":
            # Preserve the Rust relation validator's conclusion for backend
            # failure classification, including runs with no password probe.
            analysis["execution"] = {"missing_volume_evidence": "relation_missing_volume"}
        return replace(descriptor, analysis=analysis) if analysis else descriptor

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
        extent = InputExtent(
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
                    extent=extent,
                    role="main",
                )
            ],
            analysis={"segment_source": "relations", **(
                {"zip_eocd_offset": zip_eocd - structure_offset}
                if isinstance(zip_eocd, int) and zip_eocd >= structure_offset else {}
            )},
        )

    descriptor = ArchiveInputDescriptor.from_parts(
        archive_path=group.entry_path,
        part_paths=list(group.input_paths or [group.entry_path]),
        format_hint=format_hint,
        logical_name=group.logical_name,
    )
    return replace(descriptor, analysis={"zip_eocd_offset": zip_eocd}) if isinstance(zip_eocd, int) else descriptor
