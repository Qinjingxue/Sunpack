import os
from typing import List

from sunpack.contracts.detection import FactBag
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.filesystem import DirectorySnapshot
from sunpack.relations.scheduler import CandidateGroup, RelationsScheduler
from sunpack.filesystem.directory_scanner import DirectoryScanner


def relation_group_to_fact_bag(group: CandidateGroup) -> FactBag:
    bag = FactBag()
    relation = group.relation
    input_paths = group.input_paths
    member_paths = [path for path in input_paths if path != group.head_path]
    carrier_path = group.carrier_path or group.head_path
    cleanup_paths = group.owned_paths
    bag.set("file.path", carrier_path)
    bag.set("file.logical_name", group.logical_name)
    bag.set("candidate.kind", group.kind)
    bag.set("candidate.entry_path", group.entry_path)
    bag.set("candidate.member_paths", input_paths)
    bag.set("candidate.logical_name", group.logical_name)
    bag.set("candidate.carrier_path", carrier_path)
    bag.set("candidate.companion_paths", list(group.companion_paths or []))
    bag.set("candidate.cleanup_paths", cleanup_paths)
    # A split SFX launcher is a companion to the real archive volumes, not
    # part of the archive input.  Preserve that carrier identity before
    # format prechecks run; the ordinary offset-zero format probe must be
    # allowed to accept the data volumes without entering embedded scanning.
    if (
        group.companion_paths
        and os.path.splitext(carrier_path)[1].casefold() == ".exe"
        and os.path.normcase(os.path.abspath(carrier_path))
        != os.path.normcase(os.path.abspath(group.head_path))
    ):
        bag.set("file.container_type", "pe")
    single_incomplete_volume = group.split_group_complete is False and len(group.split_volumes) == 1
    if group.split_volumes and not single_incomplete_volume:
        format_hint = _split_format_hint(
            relation.split_family,
            group.split_volumes[0].style,
            group.split_volumes[0].prefix,
        )
        source_descriptor = ArchiveInputDescriptor.from_split_volumes(
            archive_path=group.entry_path,
            volumes=group.split_volumes,
            format_hint=format_hint,
            logical_name=group.logical_name,
        )
        bag.set("relation.format_hint", format_hint)
        format_hint_is_exact = bool(format_hint) and group.split_group_complete is True and all(
            volume.source == "standard" for volume in group.split_volumes
        )
        bag.set(
            "relation.format_hint_confidence",
            "strong" if format_hint_is_exact else "weak" if format_hint else "none",
        )
    else:
        format_hint = (
            _split_format_hint(
                relation.split_family,
                group.split_volumes[0].style,
                group.split_volumes[0].prefix,
            )
            if group.split_volumes
            else ""
        )
        source_descriptor = ArchiveInputDescriptor.from_parts(
            archive_path=group.entry_path,
            format_hint=format_hint,
            logical_name=group.logical_name,
        )
        bag.set("relation.format_hint", format_hint)
        bag.set("relation.format_hint_confidence", "weak" if format_hint else "none")
    state = ArchiveState.from_archive_input(source_descriptor)
    bag.set("archive.input", source_descriptor.to_dict())
    bag.set("archive.state", state.to_dict())
    bag.set("archive.source", state.source.to_dict())
    file_size = group.carrier_size if group.carrier_path and isinstance(group.carrier_size, int) else group.head_size
    if isinstance(file_size, int):
        bag.set("file.size", file_size)
    bag.set("file.split_members", list(member_paths))
    bag.set("file.split_role", relation.split_role)
    bag.set("file.is_split_candidate", group.is_split_candidate or relation.is_split_related)
    bag.set("relation.is_split_related", group.is_split_candidate or relation.is_split_related)
    bag.set("relation.is_split_member", relation.is_split_member)
    bag.set("relation.has_split_companions", relation.has_split_companions or bool(group.companion_paths))
    bag.set("relation.is_split_exe_companion", relation.is_split_exe_companion)
    bag.set("relation.is_disguised_split_exe_companion", relation.is_disguised_split_exe_companion)
    bag.set("relation.has_generic_001_head", relation.has_generic_001_head)
    bag.set("relation.is_plain_numeric_member", relation.is_plain_numeric_member)
    bag.set("relation.match_rar_disguised", relation.match_rar_disguised)
    bag.set("relation.match_rar_head", relation.match_rar_head)
    bag.set("relation.match_001_head", relation.match_001_head)
    bag.set("relation.split_entry_path", group.head_path)
    bag.set("relation.split_member_count", len(input_paths) if group.is_split_candidate else 0)
    if group.split_group_complete is not None:
        bag.set("relation.split_group_complete", bool(group.split_group_complete))
    bag.set(
        "relation.split_group_status",
        "complete" if group.split_group_complete is True else "incomplete" if group.split_group_complete is False else "ambiguous",
    )
    if group.split_missing_reason:
        bag.set("relation.split_missing_reason", group.split_missing_reason)
    if group.split_missing_indices:
        bag.set("relation.split_missing_indices", list(group.split_missing_indices))
    if group.split_observed_missing_ranges:
        bag.set(
            "relation.split_observed_missing_ranges",
            [list(value) for value in group.split_observed_missing_ranges],
        )
    bag.set("relation.split_layout_status", group.split_layout_status)
    bag.set("relation.split_completeness_status", group.split_completeness_status)
    bag.set("relation.split_completeness_confidence", group.split_completeness_confidence)
    bag.set("relation.split_completeness_basis", list(group.split_completeness_basis or []))
    bag.set("relation.split_family", relation.split_family)
    bag.set("relation.split_index", relation.split_index)
    bag.set("relation.split_is_first", relation.split_role == "first")
    if group.split_volumes:
        bag.set("relation.split_volumes", [
            {
                "path": volume.path,
                "number": volume.number,
                "role": volume.role,
                "source": volume.source,
                "style": volume.style,
                "prefix": volume.prefix,
                "width": volume.width,
            }
            for volume in group.split_volumes
        ])
    if member_paths:
        bag.set("relation.member_paths", list(member_paths))
    if isinstance(group.head_metadata, dict) and group.head_metadata:
        bag.set("relation.volume_anchor", dict(group.head_metadata))
    return bag


def _split_format_hint(family: str, style: str, prefix: str = "") -> str:
    value = f"{family} {style} {prefix}".lower()
    if "rar" in value:
        return "rar"
    if "zip" in value:
        return "zip"
    if "7z" in value:
        return "7z"
    return ""


def build_candidate_fact_bags(directory: str, relations: RelationsScheduler | None = None) -> List[FactBag]:
    scheduler = relations or RelationsScheduler()
    snapshot = DirectoryScanner(directory).scan()
    return build_candidate_fact_bags_from_snapshot(snapshot, scheduler)


def build_candidate_fact_bags_from_snapshot(
    snapshot: DirectorySnapshot,
    relations: RelationsScheduler | None = None,
) -> List[FactBag]:
    scheduler = relations or RelationsScheduler()
    return [relation_group_to_fact_bag(group) for group in scheduler.build_candidate_groups(snapshot)]
