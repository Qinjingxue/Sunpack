from dataclasses import dataclass
from pathlib import Path

from sunpack_native import directory_snapshot_from_columns

from sunpack.core.contracts.filesystem import DirectorySnapshot


@dataclass
class FileEntry:
    path: str | Path
    is_dir: bool
    size: int | None = None
    mtime_ns: int | None = None


def make_snapshot(entries: list[FileEntry]) -> DirectorySnapshot:
    native = directory_snapshot_from_columns(
        [str(entry.path) for entry in entries],
        [entry.is_dir for entry in entries],
        [entry.size for entry in entries],
        [entry.mtime_ns for entry in entries],
        [True] * len(entries),
    )
    return DirectorySnapshot(native, native)


def snapshot_rows(snapshot: DirectorySnapshot):
    return zip(*snapshot.native_snapshot.materialize_columns())
