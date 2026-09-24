from __future__ import annotations

from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
from sunpack.core.contracts.filesystem import DirectorySnapshot
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.discovery.relations.scheduler import CandidateGroup, RelationsScheduler
from sunpack.pipeline.discovery.relations.internal.archive_input import archive_input_for_group


def relation_group_to_candidate(group: CandidateGroup) -> DiscoveryCandidate:
    metadata = dict(group.head_metadata or {})
    input_paths = tuple(group.input_paths or [group.entry_path])
    carrier_path = str(group.carrier_path or group.head_path)
    cleanup_paths = tuple(group.owned_paths)
    format_hint = str(metadata.get("format") or "").lower().lstrip(".")
    archive_input = archive_input_for_group(group) or ArchiveInputDescriptor(
        entry_path=group.entry_path,
        format_hint=format_hint,
        logical_name=group.logical_name,
        parts=[ArchiveInputPart(extent=InputExtent(path=path)) for path in input_paths],
    )

    relation_metadata = {
        "split_role": group.relation.split_role,
        "split_family": group.relation.split_family,
        "split_index": group.relation.split_index,
        "split_member_count": len(input_paths) if group.is_split_candidate else 0,
        "needs_password": bool(metadata.get("needs_password")),
        "multivolume": bool(metadata.get("multivolume") or group.is_split_candidate),
    }
    return DiscoveryCandidate(
        archive_input=archive_input,
        carrier_path=carrier_path,
        cleanup_paths=cleanup_paths,
        route="relations",
        size=(
            group.carrier_size
            if group.carrier_path and isinstance(group.carrier_size, int)
            else group.head_size
        ),
        format_reject_mask=int(group.format_reject_mask or 0),
        relation_anchor=metadata,
        is_split=bool(group.is_split_candidate or group.relation.is_split_related),
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
        archive_input=ArchiveInputDescriptor.from_parts(
            archive_path=path,
            part_paths=[path],
            logical_name=path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1],
            format_hint=str(format_hint or "").lower(),
        ),
        carrier_path=path,
        cleanup_paths=(path,),
        route=route,
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
