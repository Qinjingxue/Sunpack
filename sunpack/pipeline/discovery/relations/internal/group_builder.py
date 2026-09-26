from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Set

from sunpack_native import (
    list_regular_files_in_directory as _native_list_regular_files_in_directory,
    relations_build_candidate_groups_from_snapshot as _native_build_candidate_groups,
    relations_detect_split_role as _native_detect_split_role,
    relations_logical_name as _native_logical_name,
    relations_parse_numbered_volume as _native_parse_numbered_volume,
    relations_resolve_volume_once as _native_resolve_volume_once,
    relations_split_sort_key as _native_split_sort_key,
)

from sunpack.core.contracts.filesystem import DirectorySnapshot
from sunpack.core.passwords.internal.local_files import discover_directory_passwords_for_archive
from sunpack.core.passwords.internal.store import PasswordStore
from sunpack.core.passwords.relation_prober import RelationsPasswordProber
from sunpack.pipeline.discovery.relations.internal.models import CandidateGroup, FileRelation, SplitVolumeEntry
from sunpack.pipeline.discovery.relations.internal.archive_input import archive_input_for_group
from sunpack.core.support.path_keys import path_key


class RelationsGroupBuilder:
    """Thin Python contract over the native evidence-first Relations engine."""

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.password_store = PasswordStore.from_sources(
            cli_passwords=list(self.config.get("user_passwords") or []),
            builtin_passwords=list(self.config.get("builtin_passwords") or []),
        )
        self.password_prober = RelationsPasswordProber(self.password_store)

    def set_password_callback(self, callback) -> None:
        """Register a listener for passwords discovered during relation scans."""
        self.password_prober.set_password_callback(callback)

    def refresh_password_sources(self) -> None:
        """Synchronize the prober's store with live watch scheduler sources."""
        self.password_store.replace_sources(
            user_passwords=list(self.config.get("user_passwords") or []),
            builtin_passwords=list(self.config.get("builtin_passwords") or []),
        )

    def build_candidate_groups(
        self,
        snapshot: DirectorySnapshot,
        path_passwords: dict[str, str] | None = None,
    ) -> List[CandidateGroup]:
        groups = self.build_candidate_groups_without_discovery(snapshot, path_passwords)
        if path_passwords is None:
            discovered = self._discover_directory_passwords(groups)
            if discovered:
                groups = self.build_candidate_groups_without_discovery(snapshot, discovered)
        return groups

    def _discover_directory_passwords(
        self,
        groups: List[CandidateGroup],
    ) -> dict[str, str] | None:
        """Second-pass password discovery for header-encrypted RAR5 files.

        The first native pass reports every encrypted file that could not be
        structurally resolved (each one surfaces as an encrypted-unresolved
        head or member).  Probing those files with the same-directory password
        list lets the next native pass decrypt the main headers and follow the
        exact unencrypted path: real multivolume state and volume numbers.
        """
        encrypted_groups: list[tuple[list[str], list[str], dict | None]] = []
        for group in groups:
            metadata = group.head_metadata if isinstance(group.head_metadata, dict) else {}
            if (
                str(metadata.get("format") or "").lower() != "rar"
                or not bool(metadata.get("needs_password"))
            ):
                continue
            proposal_paths: set[str] = set()
            proposal_paths.add(os.path.abspath(str(group.head_path or "")))
            for member in group.input_paths:
                proposal_paths.add(os.path.abspath(str(member)))
            for member in metadata.get("proposal_paths") or []:
                proposal_paths.add(os.path.abspath(str(member)))
            proposal_paths.discard("")
            if proposal_paths:
                part_paths = list(dict.fromkeys(
                    os.path.abspath(str(member))
                    for member in group.input_paths
                    if member
                ))
                descriptor = archive_input_for_group(group)
                archive_input = descriptor.to_dict() if descriptor is not None else None
                encrypted_groups.append((sorted(proposal_paths), part_paths, archive_input))
        if not encrypted_groups:
            return None

        found: dict[str, str] = {}
        for proposal_paths, part_paths, archive_input in encrypted_groups:
            probe_path = next((path for path in part_paths if path in proposal_paths), proposal_paths[0])
            directory_passwords = discover_directory_passwords_for_archive(probe_path, self.config)
            password = self.password_prober.resolve_file(
                probe_path,
                directory_passwords=directory_passwords,
                part_paths=part_paths or proposal_paths,
                archive_input=archive_input,
            )
            if not password:
                continue
            # A password belongs to the proposal, not just to the head path
            # that happened to make the bounded verifier succeed.  The native
            # validator then rechecks every member in the original path union
            # with that one password.
            for proposal_path in proposal_paths:
                found[proposal_path] = password
        return found or None

    def build_candidate_groups_without_discovery(
        self,
        snapshot: DirectorySnapshot,
        path_passwords: dict[str, str] | None = None,
    ) -> List[CandidateGroup]:
        native_groups = _native_build_candidate_groups(
            snapshot.raw_native_snapshot,
            snapshot.native_snapshot,
            _native_password_pairs(path_passwords),
        )
        if not isinstance(native_groups, list):
            raise ValueError("native relations returned invalid groups")
        groups: List[CandidateGroup] = []
        for raw in native_groups:
            if not isinstance(raw, dict):
                raise ValueError("native relations returned a non-object group")
            group = self._candidate_group_from_native(raw)
            if group is None:
                raise ValueError("native relations returned an invalid group")
            groups.append(group)
        return groups

    def resolve_volume_once(
        self,
        current_paths: list[str],
        candidate_paths: list[str],
        *,
        format_hint: str = "",
        path_passwords: dict[str, str] | None = None,
    ) -> CandidateGroup | None:
        raw = _native_resolve_volume_once(
            current_paths,
            candidate_paths,
            format_hint,
            _native_password_pairs(path_passwords),
        )
        return self._candidate_group_from_native(raw) if isinstance(raw, dict) else None

    def resolve_volume_once_in_directory(
        self,
        current_paths: list[str],
        *,
        format_hint: str = "",
    ) -> CandidateGroup | None:
        directories = {
            os.path.normcase(os.path.abspath(os.path.dirname(path) or os.getcwd()))
            for path in current_paths
            if path
        }
        if len(directories) != 1:
            return None
        rows = _native_list_regular_files_in_directory(next(iter(directories)))
        candidates = [
            str(row.get("path"))
            for row in rows
            if isinstance(row, dict) and row.get("path")
        ]
        return self.resolve_volume_once(current_paths, candidates, format_hint=format_hint)

    def detect_split_role(self, filename: str) -> Optional[str]:
        return _native_detect_split_role(filename)

    def get_logical_name(self, filename: str, is_archive: bool = False) -> str:
        return str(_native_logical_name(filename, bool(is_archive)))

    def parse_numbered_volume(self, path: str):
        return _native_parse_numbered_volume(path)

    def split_sort_key(self, path: str) -> tuple[int, int, str]:
        return tuple(_native_split_sort_key(path))

    def select_first_volume(self, paths: List[str]) -> str:
        if not paths:
            return ""
        parsed = [(path, self.parse_numbered_volume(path)) for path in paths]
        first = next((path for path, value in parsed if value and int(value["number"]) == 1), None)
        return first or min(paths, key=self.split_sort_key)

    def should_scan_split_siblings(
        self,
        archive: str,
        *,
        is_split: bool = False,
        is_sfx_stub: bool = False,
    ) -> bool:
        del is_sfx_stub
        return bool(is_split or self.parse_numbered_volume(archive))

    def find_standard_split_siblings(self, archive: str) -> List[str]:
        parsed = self.parse_numbered_volume(archive)
        if not parsed:
            return []
        directory = os.path.dirname(os.path.abspath(archive)) or os.getcwd()
        matches: list[str] = []
        for row in _native_list_regular_files_in_directory(directory):
            if not isinstance(row, dict) or not row.get("path"):
                continue
            candidate = str(row["path"])
            other = self.parse_numbered_volume(candidate)
            if not other:
                continue
            if self._same_standard_family(parsed, other):
                matches.append(candidate)
        return sorted(dict.fromkeys(matches), key=self.split_sort_key)

    def build_split_volume_entries(
        self,
        archive: str,
        all_parts: List[str],
        directory_index=None,
    ) -> tuple[List[SplitVolumeEntry], Optional[bool], str, List[int]]:
        del directory_index
        paths = list(dict.fromkeys(str(path) for path in all_parts if path))
        parsed_rows = [(path, self.parse_numbered_volume(path)) for path in paths]
        parsed_rows = [(path, parsed) for path, parsed in parsed_rows if parsed]
        if not parsed_rows:
            return [], None, "", []
        anchor = next((parsed for path, parsed in parsed_rows if path_key(path) == path_key(archive)), parsed_rows[0][1])
        members = [
            (path, parsed)
            for path, parsed in parsed_rows
            if self._same_standard_family(anchor, parsed)
        ]
        by_number: dict[int, tuple[str, dict]] = {}
        for path, parsed in members:
            number = int(parsed["number"])
            if number > 0:
                by_number.setdefault(number, (path, parsed))
        if not by_number:
            return [], None, "", []
        volumes = [
            SplitVolumeEntry(
                path=path,
                number=number,
                role="first" if number == 1 else "member",
                source="standard",
                style=str(anchor.get("style") or ""),
                prefix=str(anchor.get("prefix") or ""),
                width=int(anchor.get("width") or 3),
            )
            for number, (path, parsed) in sorted(by_number.items())
        ]
        highest = max(by_number)
        missing = [number for number in range(1, highest + 1) if number not in by_number]
        if 1 in missing:
            reason = "missing_head"
        elif missing:
            reason = "missing_middle"
        else:
            reason = ""
        return volumes, not missing, reason, missing

    def build_file_relation(self, filename: str, sibling_names: Set[str]) -> FileRelation:
        del sibling_names
        parsed = self.parse_numbered_volume(filename)
        if not parsed:
            return FileRelation(filename=filename, logical_name=self.get_logical_name(filename))
        number = int(parsed["number"])
        family = str(parsed.get("style") or "")
        return FileRelation(
            filename=filename,
            logical_name=self.get_logical_name(filename),
            split_role="first" if number == 1 else "member",
            is_split_member=True,
            is_split_related=True,
            split_family=family,
            split_index=number,
        )

    @staticmethod
    def _same_standard_family(left: dict, right: dict) -> bool:
        left_style = str(left.get("style") or "")
        right_style = str(right.get("style") or "")
        compatible_styles = left_style == right_style or {
            left_style,
            right_style,
        } <= {"rar_part", "rar_sfx_part"}
        return bool(
            compatible_styles
            and os.path.normcase(os.path.abspath(str(left.get("prefix") or "")))
            == os.path.normcase(os.path.abspath(str(right.get("prefix") or "")))
        )

    def _candidate_group_from_native(self, raw: dict) -> CandidateGroup | None:
        relation_payload = raw.get("relation")
        if not isinstance(relation_payload, dict):
            return None
        try:
            relation = FileRelation(**relation_payload)
            head_path = str(raw.get("head_path") or "")
            all_parts = [str(path) for path in (raw.get("all_parts") or [])]
            if not head_path or not all_parts:
                return None
            split_volumes = [
                SplitVolumeEntry(**payload)
                for payload in (raw.get("split_volumes") or [])
                if isinstance(payload, dict)
            ]
            first = next((volume for volume in split_volumes if volume.number == 1), None)
            if first:
                head_path = first.path
            return CandidateGroup(
                head_path=head_path,
                logical_name=str(raw.get("logical_name") or relation.logical_name),
                relation=relation,
                input_paths=all_parts,
                is_split_candidate=bool(raw.get("is_split_candidate")),
                head_size=raw.get("head_size"),
                logical_size=raw.get("logical_size"),
                split_volumes=split_volumes,
                head_metadata=dict(raw.get("head_metadata") or {}),
                companion_paths=[str(path) for path in (raw.get("companion_paths") or [])],
                carrier_path=str(raw.get("carrier_path") or ""),
                carrier_size=raw.get("carrier_size"),
                format_reject_mask=int(raw.get("format_reject_mask") or 0),
            )
        except (TypeError, ValueError):
            return None

def _native_password_pairs(path_passwords: dict[str, str] | None) -> list[tuple[str, str]] | None:
    if not path_passwords:
        return None
    return [(str(path), str(password)) for path, password in path_passwords.items() if str(password)]
