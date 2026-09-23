from __future__ import annotations

import os
from typing import List

from sunpack.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
    ArchiveInputSegment,
)
from sunpack.contracts.discovery import DiscoveryCandidate
from sunpack.contracts.filesystem import DirectorySnapshot
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.relations.scheduler import CandidateGroup, RelationsScheduler


def relation_group_to_candidate(group: CandidateGroup) -> DiscoveryCandidate:
    relation = group.relation
    input_paths = tuple(group.input_paths)
    carrier_path = group.carrier_path or group.head_path
    cleanup_paths = tuple(group.owned_paths)
    companion_paths = tuple(group.companion_paths or ())
    metadata = group.head_metadata if isinstance(group.head_metadata, dict) else {}
    relation_confirmed = bool(metadata.get("relation_confirmed"))
    password_pending = bool(metadata.get("needs_password"))
    format_hint = str(metadata.get("format") or "").lower().lstrip(".")
    descriptor = _archive_input_for_group(
        group,
        format_hint=format_hint,
        relation_confirmed=relation_confirmed,
    )
    size = (
        group.carrier_size
        if group.carrier_path and isinstance(group.carrier_size, int)
        else group.head_size
    )
    return DiscoveryCandidate(
        route="relations",
        entry_path=group.entry_path,
        member_paths=input_paths or (group.entry_path,),
        logical_name=group.logical_name,
        carrier_path=carrier_path,
        cleanup_paths=cleanup_paths or input_paths or (group.entry_path,),
        companion_paths=companion_paths,
        size=size if isinstance(size, int) else None,
        format_hint=format_hint,
        format_reject_mask=int(group.format_reject_mask or 0),
        relation_anchor=dict(metadata),
        archive_input=descriptor,
        relation_kind=group.kind,
        is_split=bool(group.is_split_candidate or relation.is_split_related or len(input_paths) > 1),
        is_sfx=bool(
            companion_paths
            or metadata.get("sfx")
            or descriptor is not None and descriptor.open_mode == "sfx_with_volumes"
        ),
        relation_family=str(relation.split_family or ""),
        relation_index=int(relation.split_index or 0),
    )


def _archive_input_for_group(
    group: CandidateGroup,
    *,
    format_hint: str,
    relation_confirmed: bool,
) -> ArchiveInputDescriptor | None:
    if group.split_volumes:
        return ArchiveInputDescriptor.from_split_volumes(
            archive_path=group.entry_path,
            volumes=group.split_volumes,
            format_hint=format_hint,
            logical_name=group.logical_name,
        )
    if not relation_confirmed:
        return None

    metadata = group.head_metadata if isinstance(group.head_metadata, dict) else {}
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


def build_discovery_candidates(
    directory: str,
    relations: RelationsScheduler | None = None,
) -> List[DiscoveryCandidate]:
    scheduler = relations or RelationsScheduler()
    snapshot = DirectoryScanner(directory, include_raw_snapshot=True).scan()
    return build_discovery_candidates_from_snapshot(snapshot, scheduler)


def build_discovery_candidates_from_snapshot(
    snapshot: DirectorySnapshot,
    relations: RelationsScheduler | None = None,
) -> List[DiscoveryCandidate]:
    scheduler = relations or RelationsScheduler()
    return [
        relation_group_to_candidate(group)
        for group in scheduler.build_candidate_groups(snapshot)
    ]
