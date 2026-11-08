from dataclasses import dataclass

from sunpack_native import NativeDirectorySnapshot


@dataclass(slots=True)
class DirectorySnapshot:
    native_snapshot: NativeDirectorySnapshot
    raw_native_snapshot: NativeDirectorySnapshot

    @property
    def has_files(self) -> bool:
        return self.native_snapshot.has_files()
