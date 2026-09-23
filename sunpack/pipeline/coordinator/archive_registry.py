from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable

from sunpack.core.support.resource_lifecycle import FileIdentity


@dataclass(frozen=True)
class ArchiveConflict:
    owner: str
    origin: str
    paths: tuple[str, ...]


@dataclass
class _Lease:
    owner: str
    origin: str
    identities: tuple[FileIdentity, ...]


class ActiveArchiveRegistry:
    """RuntimeHost-owned, event-loop-confined archive ownership registry."""

    def __init__(self) -> None:
        self._leases: dict[str, _Lease] = {}

    def reserve(self, owner: str, origin: str, paths: Iterable[str]) -> ArchiveConflict | None:
        normalized_origin = "watch" if str(origin).lower() == "watch" else "foreground"
        identities = tuple(
            FileIdentity.from_path(path)
            for path in dict.fromkeys(os.path.abspath(os.path.normpath(str(path))) for path in paths if path)
        )
        conflict = self._find_conflict(owner, identities)
        if conflict is not None:
            return conflict
        self._leases[owner] = _Lease(owner, normalized_origin, identities)
        return None

    def release(self, owner: str) -> None:
        self._leases.pop(owner, None)

    def watch_conflict(self, paths: Iterable[str]) -> ArchiveConflict | None:
        identities = tuple(FileIdentity.from_path(path) for path in paths if path)
        for lease in self._leases.values():
            if lease.origin != "watch":
                continue
            if self._overlaps(identities, lease.identities):
                return ArchiveConflict(lease.owner, lease.origin, tuple(item.path for item in lease.identities))
        return None

    def _find_conflict(self, owner: str, identities: tuple[FileIdentity, ...]) -> ArchiveConflict | None:
        for current_owner, lease in self._leases.items():
            if current_owner == owner:
                continue
            if self._overlaps(identities, lease.identities):
                return ArchiveConflict(lease.owner, lease.origin, tuple(item.path for item in lease.identities))
        return None

    @classmethod
    def _overlaps(
        cls,
        left: tuple[FileIdentity, ...],
        right: tuple[FileIdentity, ...],
    ) -> bool:
        return any(cls._identity_overlaps(a, b) for a in left for b in right)

    @staticmethod
    def _identity_overlaps(left: FileIdentity, right: FileIdentity) -> bool:
        if left.same_file(right):
            return True
        if left.is_directory and _is_under(right.path, left.path):
            return True
        return right.is_directory and _is_under(left.path, right.path)


def _is_under(candidate: str, root: str) -> bool:
    try:
        return os.path.commonpath((candidate, root)) == root
    except ValueError:
        return False
