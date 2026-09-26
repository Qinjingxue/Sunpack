from __future__ import annotations

from typing import Any

from sunpack_native import batch_file_head_facts as _native_batch_file_head_facts

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
        self._candidates: dict[str, list[DiscoveryCandidate]] = {}
        self._file_head_facts: dict[str, dict[str, Any]] = {}
        self._output_inventories: list[Any] = []
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
        self._output_inventories.append(inventory)

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
        key = self._directory_key(directory)
        if key not in self._candidates:
            snapshot = self.snapshot_for_directory(directory)
            groups = self.relation_groups_for_directory(
                directory,
                filesystem_routed=True,
            )
            candidates = [relation_group_to_candidate(group) for group in groups]
            candidates.extend(
                filesystem_candidate(
                    path,
                    size=size,
                    route=route,
                    format_hint=format_hint,
                    reject_mask=reject_mask,
                    logical_name=logical_name,
                )
                for path, size, route, format_hint, reject_mask, logical_name
                in snapshot.filesystem_candidate_specs()
            )
            self._candidates[key] = candidates
        return self._candidates[key]

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
        requested = [str(path) if paths_normalized else normalized_path(path) for path in paths if path]
        keyed = [(path, path_key(path)) for path in requested]
        missing = [
            path for path, key in keyed
            if self._file_head_fetch_needed_key(key, magic_size=magic_size)
        ]
        if missing:
            filesystem_paths = list(missing)
            for inventory in self._output_inventories:
                root = normalized_path(getattr(inventory, "root", ""))
                scoped = [
                    path for path in filesystem_paths
                    if root and (path_key(path) == path_key(root) or safe_relative_path(path, root) is not None)
                ]
                if not scoped:
                    continue
                rows = inventory.file_head_facts_for_paths(scoped, magic_size=magic_size)
                resolved = set()
                for row in rows:
                    if not isinstance(row, dict) or not row.get("path"):
                        continue
                    key = path_key(row["path"])
                    resolved.add(key)
                    self._file_head_facts[key] = {
                        "path": str(row["path"]),
                        "exists": bool(row.get("exists", True)),
                        "is_file": bool(row.get("is_file", True)),
                        "size": row.get("size"),
                        "mtime_ns": row.get("mtime_ns"),
                        "magic": row.get("magic") if isinstance(row.get("magic"), bytes) else b"",
                        "magic_complete": bool(row.get("magic_complete")),
                    }
                for path in scoped:
                    key = path_key(path)
                    if key not in resolved:
                        self._file_head_facts[key] = {
                            "path": path,
                            "exists": False,
                            "is_file": False,
                            "size": None,
                            "mtime_ns": None,
                            "magic": b"",
                            "magic_complete": True,
                        }
                scoped_keys = {path_key(path) for path in scoped}
                filesystem_paths = [path for path in filesystem_paths if path_key(path) not in scoped_keys]

            if filesystem_paths:
                rows = _native_batch_file_head_facts(filesystem_paths, max(0, int(magic_size or 0)))
                seen = set()
                for row in rows:
                    if not isinstance(row, dict) or not row.get("path"):
                        continue
                    key = path_key(row["path"])
                    seen.add(key)
                    existing = self._file_head_facts.get(key, {})
                    magic = row.get("magic") if isinstance(row.get("magic"), bytes) else b""
                    self._file_head_facts[key] = {
                        "path": str(row["path"]),
                        "exists": bool(row.get("exists")),
                        "is_file": bool(row.get("is_file")),
                        "size": row.get("size"),
                        "mtime_ns": row.get("mtime_ns"),
                        "magic": magic if magic_size > 0 else existing.get("magic", b""),
                        "magic_complete": bool(magic_size > 0) or bool(existing.get("magic_complete")),
                    }
                for path in filesystem_paths:
                    key = path_key(path)
                    if key not in seen:
                        self._file_head_facts[key] = {
                            "path": path,
                            "exists": False,
                            "is_file": False,
                            "size": None,
                            "mtime_ns": None,
                            "magic": b"",
                            "magic_complete": True,
                        }
        if copy_results:
            return {key: dict(self._file_head_facts.get(key, {})) for _path, key in keyed}
        return {key: self._file_head_facts.get(key, {}) for _path, key in keyed}

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

    def _file_head_fetch_needed_key(self, key: str, *, magic_size: int) -> bool:
        facts = self._file_head_facts.get(key)
        if facts is None:
            return True
        return bool(magic_size > 0 and facts.get("is_file") and not facts.get("magic_complete"))


def _password_signature(path_passwords: dict[str, str] | None) -> str:
    if not path_passwords:
        return ""
    return repr(sorted(
        (str(path).lower(), str(password))
        for path, password in path_passwords.items()
        if str(password)
    ))
