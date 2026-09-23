from __future__ import annotations

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
    metadata = dict(group.head_metadata or {})
    input_paths = tuple(group.input_paths or [group.entry_path])
    carrier_path = str(group.carrier_path or group.head_path)
    cleanup_paths = tuple(group.owned_paths)
    format_hint = str(metadata.get("format") or "").lower().lstrip(".")
    confirmed = bool(metadata.get("relation_confirmed"))
    archive_input = _archive_input_for_group(group, metadata, format_hint) if confirmed or group.split_volumes else None

    relation_metadata = {
        "split_role": group.relation.split_role,
        "split_family": group.relation.split_family,
        "split_index": group.relation.split_index,
        "split_member_count": len(input_paths) if group.is_split_candidate else 0,
        "needs_password": bool(metadata.get("needs_password")),
        "multivolume": bool(metadata.get("multivolume") or group.is_split_candidate),
    }
    return DiscoveryCandidate(
        entry_path=group.entry_path,
        member_paths=input_paths,
        logical_name=group.logical_name,
        carrier_path=carrier_path,
        cleanup_paths=cleanup_paths,
        route="relations",
        format_hint=format_hint,
        size=(
            group.carrier_size
            if group.carrier_path and isinstance(group.carrier_size, int)
            else group.head_size
        ),
        format_reject_mask=int(group.format_reject_mask or 0),
        archive_input=archive_input,
        relation_anchor=metadata,
        relation_kind=group.kind,
        is_split=bool(group.is_split_candidate or group.relation.is_split_related),
        is_sfx=bool(
            metadata.get("sfx")
            or group.companion_paths
            or group.relation.has_split_companions
            or group.relation.is_split_exe_companion
            or group.relation.is_disguised_split_exe_companion
        ),
        companion_paths=tuple(group.companion_paths or ()),
        relation_metadata=relation_metadata,
    )


def filesystem_candidate(
    path: str,
    *,
    size: int | None,
    route: str,
    format_hint: str,
    reject_mask: int,
) -> DiscoveryCandidate:
    return DiscoveryCandidate(
        entry_path=path,
        member_paths=(path,),
        logical_name=path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1],
        carrier_path=path,
        cleanup_paths=(path,),
        route=route,
        format_hint=str(format_hint or "").lower(),
        size=size,
        format_reject_mask=int(reject_mask or 0),
    )


def build_candidates(
    directory: str,
    relations: RelationsScheduler | None = None,
) -> list[DiscoveryCandidate]:
    scheduler = relations or RelationsScheduler()
    snapshot = DirectoryScanner(directory, include_raw_snapshot=True).scan()
    return build_candidates_from_snapshot(snapshot, scheduler)


def build_candidates_from_snapshot(
    snapshot: DirectorySnapshot,
    relations: RelationsScheduler | None = None,
) -> list[DiscoveryCandidate]:
    scheduler = relations or RelationsScheduler()
    return [
        relation_group_to_candidate(group)
        for group in scheduler.build_candidate_groups(snapshot)
    ]


def _archive_input_for_group(
    group: CandidateGroup,
    metadata: dict,
    format_hint: str,
) -> ArchiveInputDescriptor | None:
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
