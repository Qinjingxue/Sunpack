from __future__ import annotations

from typing import Any

from sunpack_native import NativeCandidateTable, NativeHeadFactCache

from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.core.contracts.filesystem import DirectorySnapshot, FILESYSTEM_ROUTE_RELATIONS
from sunpack.pipeline.coordinator.target_groups import filesystem_candidate, relation_group_to_candidate
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.discovery.relations import CandidateGroup, RelationsScheduler
from sunpack.core.support.path_keys import normalized_path, path_key, safe_relative_path


class DiscoveryScanSession:
    """Directory-scoped cache for filesystem discovery and Relations."""

    def __init__(
        self,
        relations: RelationsScheduler | None = None,
        config: dict | None = None,
        *,
        include_raw_snapshots: bool = True,
    ):
        self.config = config or {}
        self.relations = relations or RelationsScheduler(self.config)
        self.include_raw_snapshots = include_raw_snapshots
        self._snapshots: dict[str, DirectorySnapshot] = {}
        self._relation_groups: dict[str, list[CandidateGroup]] = {}
        self._relation_group_signatures: dict[str, str] = {}
        self._head_facts = NativeHeadFactCache()
        self._directory_identities: dict[str, tuple[str, int, str]] = {}
        self._scan_roots: list[str] = []

    def set_scan_roots(self, roots: list[str]) -> None:
        self._scan_roots = []
        seen: set[str] = set()
        for root in roots:
            raw_root = str(root or "")
            if not raw_root:
                continue
            normalized = normalized_path(raw_root)
            key = path_key(normalized)
            if not normalized or key in seen:
                continue
            seen.add(key)
            self._scan_roots.append(normalized)

    def prime_snapshot(self, directory: str, snapshot: DirectorySnapshot) -> None:
        self._snapshots[self._snapshot_key(directory, max_depth=None)] = snapshot

    def prime_output_inventory(self, inventory: Any) -> None:
        if inventory is None:
            return
        self._head_facts.prime_inventory(inventory._native)

    def is_within_scan_scope(self, path: str) -> bool:
        if not self._scan_roots:
            return True
        path = normalized_path(path)
        key = path_key(path)
        return any(
            key == path_key(root) or safe_relative_path(path, root) is not None
            for root in self._scan_roots
        )

    def snapshot_for_directory(self, directory: str) -> DirectorySnapshot:
        return self._snapshot_for_directory(directory, max_depth=None)

    def shallow_snapshot_for_directory(self, directory: str, max_depth: int) -> DirectorySnapshot:
        full_key = self._snapshot_key(directory, max_depth=None)
        if full_key in self._snapshots:
            return self._snapshots[full_key]
        return self._snapshot_for_directory(directory, max_depth=max_depth)

    def _snapshot_for_directory(self, directory: str, max_depth: int | None) -> DirectorySnapshot:
        key = self._snapshot_key(directory, max_depth)
        if key not in self._snapshots:
            self._snapshots[key] = DirectoryScanner(
                directory,
                max_depth=max_depth,
                config=self.config,
                include_raw_snapshot=self.include_raw_snapshots,
            ).scan()
        return self._snapshots[key]

    def relation_groups_for_directory(
        self,
        directory: str,
        path_passwords: dict[str, str] | None = None,
        *,
        refresh: bool = False,
        filesystem_routed: bool = False,
    ) -> list[CandidateGroup]:
        key = self._directory_key(directory)
        cache_key = f"{key}::relations" if filesystem_routed else key
        signature = _password_signature(path_passwords)
        cached_signature = self._relation_group_signatures.get(cache_key)
        if refresh or cache_key not in self._relation_groups or cached_signature != signature:
            snapshot = self.snapshot_for_directory(directory)
            if filesystem_routed:
                snapshot = snapshot.file_route_view(FILESYSTEM_ROUTE_RELATIONS)
                if len(snapshot) == 0:
                    self._relation_groups[cache_key] = []
                    self._relation_group_signatures[cache_key] = signature
                    return []
            groups = self.relations.build_candidate_groups(
                snapshot,
                path_passwords=path_passwords,
            )
            self._relation_groups[cache_key] = groups
            self._relation_group_signatures[cache_key] = signature
        return self._relation_groups[cache_key]

    def candidates_for_directory(self, directory: str) -> list[DiscoveryCandidate]:
        table = self.native_table_for_directory(directory)
        return [self.project_native_candidate(table, index) for index in range(len(table))]

    def native_table_for_directory(self, directory: str) -> NativeCandidateTable:
        snapshot = self.snapshot_for_directory(directory)
        table = NativeCandidateTable()
        table.append_directory(snapshot.raw_native_snapshot, snapshot.native_snapshot)
        encrypted = table.encrypted_rar_groups()
        if encrypted:
            builder = self.relations._builder
            groups = [builder._candidate_group_from_native(raw) for raw in encrypted]
            discovered = builder._discover_directory_passwords([group for group in groups if group is not None])
            if discovered:
                table.retry_relations(
                    snapshot.raw_native_snapshot,
                    snapshot.native_snapshot,
                    [(str(path), str(password)) for path, password in discovered.items()],
                )
        return table

    def project_native_candidate(self, table: NativeCandidateTable, index: int) -> DiscoveryCandidate:
        kind, raw = table.project(index)
        if kind == "file":
            path, size, route, format_hint, reject_mask, logical_name = raw
            return filesystem_candidate(
                path,
                size=size,
                route=route,
                format_hint=format_hint,
                reject_mask=reject_mask,
                logical_name=logical_name,
            )
        group = self.relations._builder._candidate_group_from_native(raw)
        if group is None:
            raise ValueError("native relations returned an invalid group")
        return relation_group_to_candidate(group)

    def logical_name_for_archive(self, filename: str) -> str:
        return self.relations.logical_name_for_archive(filename)

    def file_head_facts_for_paths(
        self,
        paths: list[str],
        *,
        magic_size: int = 16,
        paths_normalized: bool = False,
        copy_results: bool = True,
    ) -> dict[str, dict[str, Any]]:
        del copy_results
        requested = [str(path) if paths_normalized else normalized_path(path) for path in paths if path]
        rows = self._head_facts.facts_for_paths(requested, max(0, int(magic_size or 0)))
        return {path_key(row["path"]): row for row in rows}

    def file_head_facts_for_path(self, path: str, *, magic_size: int = 16) -> dict[str, Any]:
        return self.file_head_facts_for_paths([path], magic_size=magic_size).get(path_key(path), {})

    def file_identity_for_path(self, path: str) -> tuple[str, int, int]:
        key = path_key(path)
        facts = self.file_head_facts_for_path(path, magic_size=0)
        size = facts.get("size")
        mtime_ns = facts.get("mtime_ns")
        if isinstance(size, int) and isinstance(mtime_ns, int):
            return key, size, mtime_ns
        return key, 0, 0

    def directory_identity_for_path(self, directory: str) -> tuple[str, int, str]:
        key = self._directory_key(directory)
        if key not in self._directory_identities:
            snapshot = self.shallow_snapshot_for_directory(directory, max_depth=0)
            count, digest = snapshot.identity_digest()
            self._directory_identities[key] = (key, count, digest)
        return self._directory_identities[key]

    def _directory_key(self, directory: str) -> str:
        return path_key(directory)

    def _snapshot_key(self, directory: str, max_depth: int | None) -> str:
        return f"{self._directory_key(directory)}::{max_depth}"


def _password_signature(path_passwords: dict[str, str] | None) -> str:
    if not path_passwords:
        return ""
    return repr(sorted(
        (str(path).lower(), str(password))
        for path, password in path_passwords.items()
        if str(password)
    ))
