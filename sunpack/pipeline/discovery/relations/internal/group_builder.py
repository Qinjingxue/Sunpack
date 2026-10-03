from __future__ import annotations

import os
from typing import Iterable, List, Optional

from sunpack_native import (
    NativeCandidateTable,
    list_regular_files_in_directory as _native_list_regular_files_in_directory,
    relations_detect_split_role as _native_detect_split_role,
    relations_logical_name as _native_logical_name,
    relations_parse_numbered_volume as _native_parse_numbered_volume,
    relations_resolve_volume_once as _native_resolve_volume_once,
)

from sunpack.core.contracts.filesystem import DirectorySnapshot
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
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
        table = NativeCandidateTable()
        table.append_relations(
            snapshot.raw_native_snapshot,
            snapshot.native_snapshot,
            _native_password_pairs(path_passwords),
        )
        if path_passwords is None:
            encrypted_groups = self._groups_from_native(table.encrypted_rar_groups())
            discovered = self._discover_directory_passwords(encrypted_groups)
            if discovered:
                table.retry_relations(
                    snapshot.raw_native_snapshot,
                    snapshot.native_snapshot,
                    _native_password_pairs(discovered),
                )
        return self._groups_from_native(table.project(index)[1] for index in range(len(table)))

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
                if descriptor is None:
                    # Rust already located the encrypted RAR header. Probe its
                    # physical range without inventing a volume order first.
                    descriptor = ArchiveInputDescriptor(
                        entry_path=group.entry_path,
                        open_mode="file_range",
                        format_hint="rar",
                        parts=[ArchiveInputPart(InputExtent(
                            path=group.entry_path,
                            start=int(metadata.get("structure_offset") or 0),
                        ))],
                    )
                archive_input = descriptor.to_dict()
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
            # Upgrade encrypted facts for the proposal's physical paths. Native
            # retry preserves the unrelated structure and filename features.
            for proposal_path in proposal_paths:
                found[proposal_path] = password
        return found or None

    def _groups_from_native(self, native_groups: Iterable[dict]) -> List[CandidateGroup]:
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

    def should_scan_split_siblings(
        self,
        archive: str,
        *,
        is_split: bool = False,
        is_sfx_stub: bool = False,
    ) -> bool:
        del is_sfx_stub
        return bool(is_split or self.parse_numbered_volume(archive))

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
