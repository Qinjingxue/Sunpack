import os
from typing import Any, List

from sunpack_native import batch_file_head_facts as _native_batch_file_head_facts

from sunpack.contracts.detection import FactBag
from sunpack.contracts.filesystem import DirectorySnapshot
from sunpack.coordinator.target_groups import relation_group_to_fact_bag
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.relations import CandidateGroup, RelationsScheduler
from sunpack.support.path_keys import normalized_path, path_key, safe_relative_path


class DetectionScanSession:
    """Directory-scoped cache for candidate construction."""

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
        self._relation_groups: dict[str, List[CandidateGroup]] = {}
        self._relation_group_signatures: dict[str, str] = {}
        self._fact_bags: dict[str, List[FactBag]] = {}
        self._file_head_facts: dict[str, dict[str, Any]] = {}
        self._directory_identities: dict[str, tuple[str, int, tuple]] = {}
        self._scan_roots: list[str] = []

    def set_scan_roots(self, roots: list[str]) -> None:
        self._scan_roots = []
        seen: set[str] = set()
        for root in roots:
            raw_root = str(root or "")
            if not raw_root:
                continue
            normalized = normalized_path(os.path.abspath(raw_root))
            key = path_key(normalized)
            if not normalized or key in seen:
                continue
            seen.add(key)
            self._scan_roots.append(normalized)

    def prime_snapshot(self, directory: str, snapshot: DirectorySnapshot) -> None:
        """Seed a complete recursive snapshot without touching the directory again."""
        self._snapshots[self._snapshot_key(directory, max_depth=None)] = snapshot

    def prime_file_head_columns(
        self,
        paths: list[str],
        sizes: list[int],
        mtimes_ns: list[int | None],
        magics: list[bytes],
    ) -> None:
        """Seed trusted worker inventory without reopening extracted files."""
        for path, size, mtime_ns, magic in zip(paths, sizes, mtimes_ns, magics):
            normalized = normalized_path(path)
            self._file_head_facts[path_key(normalized)] = {
                "path": normalized,
                "exists": True,
                "is_file": True,
                "size": int(size),
                "mtime_ns": int(mtime_ns) if mtime_ns is not None else None,
                "magic": bytes(magic),
                "magic_complete": True,
            }

    def is_within_scan_scope(self, path: str) -> bool:
        if not self._scan_roots:
            return True
        path = normalized_path(path)
        path_scope_key = path_key(path)
        for root in self._scan_roots:
            if path_scope_key == path_key(root) or safe_relative_path(path, root) is not None:
                return True
        return False

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
    ) -> List[CandidateGroup]:
        key = self._directory_key(directory)
        signature = _password_signature(path_passwords)
        cached_signature = self._relation_group_signatures.get(key)
        if refresh or key not in self._relation_groups or cached_signature != signature:
            snapshot = self.snapshot_for_directory(directory)
            groups = self.relations.build_candidate_groups(
                snapshot,
                path_passwords=path_passwords,
            )
            self._relation_groups[key] = groups
            self._relation_group_signatures[key] = signature
        return self._relation_groups[key]

    def fact_bags_for_directory(self, directory: str) -> List[FactBag]:
        key = self._directory_key(directory)
        if key not in self._fact_bags:
            self._fact_bags[key] = [
                relation_group_to_fact_bag(group)
                for group in self.relation_groups_for_directory(directory)
            ]
        return self._fact_bags[key]

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
        missing = [path for path, key in keyed if self._file_head_fetch_needed_key(key, magic_size=magic_size)]
        if missing:
            rows = _native_batch_file_head_facts(missing, max(0, int(magic_size or 0)))
            seen = set()
            for row in rows:
                if not isinstance(row, dict) or not row.get("path"):
                    continue
                key = path_key(row.get("path"))
                seen.add(key)
                existing = self._file_head_facts.get(key, {})
                magic = row.get("magic") if isinstance(row.get("magic"), bytes) else b""
                self._file_head_facts[key] = {
                    "path": str(row.get("path") or ""),
                    "exists": bool(row.get("exists")),
                    "is_file": bool(row.get("is_file")),
                    "size": row.get("size"),
                    "mtime_ns": row.get("mtime_ns"),
                    "magic": magic if magic_size > 0 else existing.get("magic", b""),
                    "magic_complete": bool(magic_size > 0) or bool(existing.get("magic_complete")),
                }
            for path in missing:
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

    def directory_identity_for_path(self, directory: str) -> tuple[str, int, tuple]:
        key = self._directory_key(directory)
        if key not in self._directory_identities:
            snapshot = self.shallow_snapshot_for_directory(directory, max_depth=0)
            entries = snapshot.identity_rows()
            self._directory_identities[key] = (key, len(entries), tuple(sorted(entries)))
        return self._directory_identities[key]

    def _directory_key(self, directory: str) -> str:
        return path_key(directory)

    def _snapshot_key(self, directory: str, max_depth: int | None) -> str:
        return f"{self._directory_key(directory)}::{max_depth}"

    def _file_head_fetch_needed(self, path: str, *, magic_size: int) -> bool:
        return self._file_head_fetch_needed_key(path_key(path), magic_size=magic_size)

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
