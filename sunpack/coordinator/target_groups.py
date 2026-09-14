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
    bag.update({
        "file.path": carrier_path,
        "file.logical_name": group.logical_name,
        "candidate.kind": group.kind,
        "candidate.entry_path": group.entry_path,
        "candidate.member_paths": input_paths,
        "candidate.logical_name": group.logical_name,
        "candidate.carrier_path": carrier_path,
        "candidate.companion_paths": list(group.companion_paths or []),
        "candidate.cleanup_paths": cleanup_paths,
        "candidate.format_reject_mask": int(group.format_reject_mask or 0),
    })
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
    needs_archive_metadata = bool(
        group.split_volumes
        or group.is_split_candidate
        or relation.is_split_related
        or group.companion_paths
        or group.carrier_path
    )
    password_pending = bool(
        isinstance(group.head_metadata, dict)
        and group.head_metadata.get("needs_password")
    )
    if group.split_volumes:
        format_hint = _split_format_hint(
            relation.split_family,
            group.split_volumes[0].style,
            group.split_volumes[0].prefix,
        )
        bag.update({
            "relation.format_hint": format_hint,
            "relation.format_hint_confidence": (
                "weak" if password_pending else "strong"
            ) if format_hint else "none",
        })
        source_descriptor = ArchiveInputDescriptor.from_split_volumes(
            archive_path=group.entry_path,
            volumes=group.split_volumes,
            format_hint=format_hint,
            logical_name=group.logical_name,
        )
    else:
        format_hint = ""
        bag.update({
            "relation.format_hint": format_hint,
            "relation.format_hint_confidence": "none",
        })

    if needs_archive_metadata:
        state = ArchiveState.from_archive_input(source_descriptor)
        bag.update({
            "archive.input": source_descriptor.to_dict(),
            "archive.state": state.to_dict(),
            "archive.source": state.source.to_dict(),
        })

    bag.update({
        "file.split_members": list(member_paths),
        "file.split_role": relation.split_role,
        "file.is_split_candidate": group.is_split_candidate or relation.is_split_related,
        "relation.is_split_related": group.is_split_candidate or relation.is_split_related,
        "relation.is_split_member": relation.is_split_member,
        "relation.has_split_companions": relation.has_split_companions or bool(group.companion_paths),
        "relation.is_split_exe_companion": relation.is_split_exe_companion,
        "relation.is_disguised_split_exe_companion": relation.is_disguised_split_exe_companion,
        "relation.has_generic_001_head": relation.has_generic_001_head,
        "relation.is_plain_numeric_member": relation.is_plain_numeric_member,
        "relation.match_rar_disguised": relation.match_rar_disguised,
        "relation.match_rar_head": relation.match_rar_head,
        "relation.match_001_head": relation.match_001_head,
        "relation.split_entry_path": group.head_path,
        "relation.split_member_count": len(input_paths) if group.is_split_candidate else 0,
        "relation.split_family": relation.split_family,
        "relation.split_index": relation.split_index,
        "relation.split_is_first": relation.split_role == "first",
    })
    if isinstance(file_size := (group.carrier_size if group.carrier_path and isinstance(group.carrier_size, int) else group.head_size), int):
        bag.set("file.size", file_size)
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
                "start": volume.start,
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
    # Relation proposals need the raw physical view so a member excluded only
    # by the soft size filter can still be validated and recovered.  The
    # filesystem scanner already computes the cheap relation evidence once for
    # that shared view.
    snapshot = DirectoryScanner(directory, include_raw_snapshot=True).scan()
    return build_candidate_fact_bags_from_snapshot(snapshot, scheduler)


def build_candidate_fact_bags_from_snapshot(
    snapshot: DirectorySnapshot,
    relations: RelationsScheduler | None = None,
) -> List[FactBag]:
    scheduler = relations or RelationsScheduler()
    return [relation_group_to_fact_bag(group) for group in scheduler.build_candidate_groups(snapshot)]
