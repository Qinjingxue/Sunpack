from dataclasses import dataclass
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sunpack.support.path_keys import path_key

@dataclass
class FileEntry:
    path: Path
    is_dir: bool
    size: int | None = None
    mtime_ns: int | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class DirectorySnapshot:
    root_path: Path
    _native_snapshot: Any
    _raw_native_snapshot: Any
    _format_reject_masks: dict[str, int] | None = None

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
            _format_reject_masks={},
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
    def format_reject_masks(self) -> dict[str, int]:
        return self._format_reject_masks or {}

    def set_format_reject_masks(self, paths: list[str], masks: list[int]) -> None:
        self._format_reject_masks = {
            path_key(path): int(mask)
            for path, mask in zip(paths, masks)
            if path
        }

    def format_reject_masks_for_paths(self, paths: list[str]) -> dict[str, int]:
        cached = self._format_reject_masks or {}
        return {
            path_key(path): cached[path_key(path)]
            for path in paths
            if path_key(path) in cached
        }

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

    def identity_rows(self) -> list[tuple[str, bool, int, int]]:
        return list(self._native_snapshot.identity_rows())
