from dataclasses import dataclass
from collections.abc import Iterator
from pathlib import Path
from typing import Any


FILESYSTEM_ROUTE_RELATIONS = 1
FILESYSTEM_ROUTE_DETECTION = 2
FILESYSTEM_ROUTE_RESIDUAL = 3

_FILESYSTEM_ROUTE_NAMES = {
    FILESYSTEM_ROUTE_RELATIONS: "relations",
    FILESYSTEM_ROUTE_DETECTION: "detection",
    FILESYSTEM_ROUTE_RESIDUAL: "residual",
}

@dataclass
class FileEntry:
    path: Path
    is_dir: bool
    size: int | None = None
    mtime_ns: int | None = None
    metadata: dict[str, Any] | None = None
    # True for filtered rows and for rows excluded only by a soft size rule.
    # Hard path/prune/whitelist exclusions must remain False so relation
    # recovery cannot resurrect them.
    relation_member_eligible: bool | None = None


@dataclass
class DirectorySnapshot:
    root_path: Path
    _native_snapshot: Any
    _raw_native_snapshot: Any

    @classmethod
    def from_native(
        cls,
        root_path: Path,
        native_snapshot: Any,
        raw_native_snapshot: Any,
    ) -> "DirectorySnapshot":
        return cls(
            root_path=root_path,
            _native_snapshot=native_snapshot,
            _raw_native_snapshot=raw_native_snapshot,
        )

    @classmethod
    def from_entries(
        cls,
        root_path: Path,
        entries: list[FileEntry],
        raw_entries: list[FileEntry] | None = None,
    ) -> "DirectorySnapshot":
        from sunpack_native import directory_snapshot_from_columns

        def build(rows: list[FileEntry]):
            return directory_snapshot_from_columns(
                [str(entry.path) for entry in rows],
                [bool(entry.is_dir) for entry in rows],
                [entry.size for entry in rows],
                [entry.mtime_ns for entry in rows],
                [
                    True if entry.relation_member_eligible is None else bool(entry.relation_member_eligible)
                    for entry in rows
                ],
            )

        native_snapshot = build(entries)
        raw_native_snapshot = build(entries if raw_entries is None else raw_entries)
        return cls.from_native(root_path, native_snapshot, raw_native_snapshot)

    def __len__(self) -> int:
        return len(self._native_snapshot)

    def __bool__(self) -> bool:
        return len(self) > 0

    @property
    def native_snapshot(self) -> Any:
        return self._native_snapshot

    @property
    def raw_native_snapshot(self) -> Any:
        return self._raw_native_snapshot

    @property
    def has_files(self) -> bool:
        return bool(self._native_snapshot.has_files())

    def iter_columns(
        self,
    ) -> Iterator[tuple[str, bool, int | None, int | None]]:
        paths, is_dirs, sizes, mtimes_ns = self._native_snapshot.materialize_columns()
        return iter(zip(paths, is_dirs, sizes, mtimes_ns))

    def iter_file_columns(self) -> Iterator[tuple[str, int | None, int | None]]:
        paths, sizes, mtimes_ns = self._native_snapshot.file_columns()
        return iter(zip(paths, sizes, mtimes_ns))

    def parent_directories(self) -> list[str]:
        return self._native_snapshot.parent_directories()

    def filesystem_candidate_specs(
        self,
    ) -> list[tuple[str, int | None, str, str, int, str]]:
        return self._native_snapshot.filesystem_candidate_specs()

    def file_entries_for_directories(self, directories: set[str]) -> list[FileEntry]:
        if not directories:
            return []
        paths, sizes, mtimes_ns = (
            self._native_snapshot.file_columns_for_directories(list(directories))
        )
        return [
            FileEntry(path=Path(path), is_dir=False, size=size, mtime_ns=mtime_ns)
            for path, size, mtime_ns in zip(paths, sizes, mtimes_ns)
        ]

    def file_route_view(self, route: int) -> "DirectorySnapshot":
        return DirectorySnapshot.from_native(
            self.root_path,
            self._native_snapshot.file_route_view(int(route)),
            self._raw_native_snapshot,
        )

    def non_relation_file_routing_rows(self) -> Iterator[tuple[str, int | None, str, str, int]]:
        paths, sizes, routes, formats, reject_masks = self._native_snapshot.non_relation_file_routing_columns()
        return iter(zip(
            paths,
            sizes,
            (_FILESYSTEM_ROUTE_NAMES.get(int(route), "residual") for route in routes),
            formats,
            reject_masks,
        ))

    def iter_relation_anchor_rows(self) -> Iterator[tuple[str, int | None, dict]]:
        return iter(self._native_snapshot.relation_anchor_rows())

    def identity_digest(self) -> tuple[int, str]:
        count, digest = self._native_snapshot.identity_digest()
        return int(count), str(digest)

    def identity_rows(self) -> list[tuple[str, bool, int, int]]:
        return list(self._native_snapshot.identity_rows())
