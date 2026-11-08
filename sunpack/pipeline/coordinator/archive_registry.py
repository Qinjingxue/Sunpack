from __future__ import annotations

import os
from dataclasses import InitVar, dataclass, field
from typing import Iterable

from sunpack.core.support.resource_lifecycle import FileIdentity


@dataclass(frozen=True)
class ArchiveConflict:
    owner: str
    origin: str
    paths: tuple[str, ...]


@dataclass(slots=True)
class _Lease:
    origin: str
    identities: InitVar[Iterable[FileIdentity]]
    physical: set[tuple[int, int]] = field(init=False, default_factory=set)
    paths: dict[str, None] = field(init=False, default_factory=dict)
    unidentified: set[str] = field(init=False, default_factory=set)
    directories: set[str] = field(init=False, default_factory=set)

    def __post_init__(self, identities: Iterable[FileIdentity]) -> None:
        for identity in identities:
            self.paths[identity.path] = None
            if identity.device is not None and identity.file_id is not None:
                self.physical.add((identity.device, identity.file_id))
            else:
                self.unidentified.add(identity.path)
            if identity.is_directory:
                self.directories.add(identity.path)

    def overlaps(self, other: "_Lease") -> bool:
        return (
            not self.physical.isdisjoint(other.physical)
            or not other.paths.keys().isdisjoint(self.unidentified)
            or not self.paths.keys().isdisjoint(other.unidentified)
            or _contains_paths(self.directories, other.paths)
            or _contains_paths(other.directories, self.paths)
        )


def _contains_paths(directories: set[str], paths: Iterable[str]) -> bool:
    if not directories:
        return False
    # Shared parents need one walk, regardless of the number of selected files.
    visited: set[str] = set()
    for path in paths:
        while path not in visited:
            if path in directories:
                return True
            visited.add(path)
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
    return False


class ActiveArchiveRegistry:
    """RuntimeHost-owned, event-loop-confined archive ownership registry."""

    def __init__(self) -> None:
        self._leases: dict[str, _Lease] = {}

    def reserve(self, owner: str, origin: str, paths: Iterable[str]) -> ArchiveConflict | None:
        normalized_origin = "watch" if str(origin).lower() == "watch" else "foreground"
        lease = _Lease(normalized_origin, (
            FileIdentity.from_path(path)
            for path in dict.fromkeys(os.path.abspath(os.path.normpath(str(path))) for path in paths if path)
        ))
        for current_owner, current in self._leases.items():
            if current_owner != owner and lease.overlaps(current):
                return ArchiveConflict(current_owner, current.origin, tuple(current.paths))
        self._leases[owner] = lease
        return None

    def release(self, owner: str) -> None:
        self._leases.pop(owner, None)
