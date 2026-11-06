from __future__ import annotations

from collections.abc import Iterable

from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.core.support.path_keys import path_key
from sunpack_native import NativeCandidateTable

from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.core.contracts.filesystem import DirectorySnapshot
from sunpack.pipeline.coordinator.target_groups import filesystem_candidate, relation_group_to_candidate
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.discovery.relations import RelationsScheduler
from sunpack.core.support.filesystem_scan_errors import DirectoryErrorReport


class DiscoveryScanSession:
    """One scope and one native snapshot per discovery boundary."""

    def __init__(
        self,
        relations: RelationsScheduler | None = None,
        config: dict | None = None,
        *,
        catalog=None,
        scope: DiscoveryScope | None = None,
        scopes=(),
    ):
        self.config = config or {}
        self.scope = scope
        self.catalog = catalog
        self._scopes = {path_key(item.root): item for item in scopes}
        if scope is not None:
            self._scopes[path_key(scope.root)] = scope
        self.relations = relations or RelationsScheduler(self.config)
        self._snapshots: dict[str, DirectorySnapshot] = {}
        self._scan_errors: DirectoryErrorReport | None = None

    def add_scan_errors(self, errors: Iterable[tuple[str, str, str]]) -> None:
        if not errors:
            return
        if self._scan_errors is None:
            self._scan_errors = DirectoryErrorReport()
        self._scan_errors.extend(errors)

    def take_scan_errors(self) -> list[tuple[str, str, str]]:
        return self._scan_errors.take() if self._scan_errors is not None else []

    @property
    def has_scan_errors(self) -> bool:
        return bool(self._scan_errors)

    def set_scan_roots(self, roots: list[str]) -> None:
        if self.scope is not None:
            return
        for root in roots:
            if not any(scope.max_depth is None and scope.contains(root) for scope in self._scopes.values()):
                self._scopes.setdefault(path_key(root), DiscoveryScope(root))

    def prime_snapshot(self, directory: str, snapshot: DirectorySnapshot) -> None:
        self.add_scan_errors(snapshot.native_snapshot.scan_errors())
        self._snapshots[path_key(directory)] = snapshot
        self._scopes[path_key(directory)] = DiscoveryScope(directory, recursive=True)

    def is_within_scan_scope(self, path: str) -> bool:
        return not self._scopes or any(scope.contains(path) for scope in self._scopes.values())

    def scope_for(self, path: str) -> DiscoveryScope:
        if self.scope is not None:
            return self.scope
        matches = [scope for scope in self._scopes.values() if scope.contains(path)]
        if matches:
            return max(matches, key=lambda scope: len(scope.root))
        return self._scopes.setdefault(path_key(path), DiscoveryScope(path))

    def snapshot_for_directory(self, directory: str) -> DirectorySnapshot:
        scope = self.scope_for(directory)
        key = path_key(scope.root)
        if key not in self._snapshots and self.catalog is not None:
            state, options, seed = self.catalog
            filtered, raw = options.catalog_snapshot(state, self.scope.native, seed)
            from pathlib import Path
            self._snapshots[key] = DirectorySnapshot.from_native(Path(self.scope.root), filtered, raw)
        if key not in self._snapshots:
            self._snapshots[key] = DirectoryScanner(
                scope.root,
                config=self.config,
                scope=scope,
            ).scan()
            self.add_scan_errors(self._snapshots[key].native_snapshot.scan_errors())
        return self._snapshots[key]

    def native_table_for_directory(
        self, directory: str, *, targets: list[tuple[str, str]] | None = None,
    ) -> NativeCandidateTable:
        snapshot = self.snapshot_for_directory(directory)
        table = NativeCandidateTable()
        table.append_directory(snapshot.raw_native_snapshot, snapshot.native_snapshot, targets)
        self.relations._builder.probe_encrypted_groups(table, snapshot)
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
