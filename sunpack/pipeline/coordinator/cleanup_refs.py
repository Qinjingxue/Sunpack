from __future__ import annotations

from dataclasses import dataclass, field

from sunpack.core.contracts.results import ArchiveCleanupResult
from sunpack.core.support.path_keys import absolute_path_key


@dataclass(frozen=True)
class ReleaseRequest:
    task_key: str
    #: All paths that lost their last owner, including paths to preserve.
    paths: tuple[str, ...] = ()
    #: Only released paths whose owners requested cleanup.
    cleanup_paths: tuple[str, ...] = ()

    @property
    def should_clean(self) -> bool:
        return bool(self.cleanup_paths)


@dataclass
class CleanupScopeResult:
    """What one release or sweep actually did."""

    released: tuple[str, ...] = ()
    deleted: tuple[str, ...] = ()
    failed: tuple[ArchiveCleanupResult, ...] = field(default_factory=tuple)
    error: str = ""


@dataclass(frozen=True)
class ReleaseOutcome:
    """Result of one task leaving (or being swept out of) the reference table."""

    task_key: str = ""
    #: Paths that lost their last owner in this release.
    released: tuple[str, ...] = ()
    #: Paths actually deleted while serving this release.
    deleted: tuple[str, ...] = ()
    #: Cleanup failures, forwarded to ``summary.cleanup_results`` so the
    #: request-level retry pass can pick them up.
    failed: tuple[ArchiveCleanupResult, ...] = ()
    #: Orchestration error, for example a promotion barrier timeout.
    error: str = ""


def cleanup_paths_for(task) -> list[str]:
    candidates = getattr(task, "cleanup_parts", None) or getattr(task, "all_parts", None) or []
    unique: dict[str, str] = {}
    for path in candidates:
        if path:
            unique.setdefault(absolute_path_key(path), str(path))
    return list(unique.values())


class CleanupRefTable:
    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._paths: dict[str, str] = {}
        self._owned: dict[int, tuple[object, str, tuple[str, ...], bool]] = {}
        #: Paths at least one owner asked to remove once it is the last one.
        self._wanted: dict[str, int] = {}

    def register(self, task) -> None:
        """Register or reconcile the task's current physical cleanup paths."""
        owner = id(task)
        task_key = str(getattr(task, "key", "") or getattr(task, "main_path", "") or "")
        paths = tuple(cleanup_paths_for(task))
        previous = self._owned.get(owner)
        if previous is not None and previous[1:3] == (task_key, paths):
            return
        eligible = previous[3] if previous is not None else False
        old = {absolute_path_key(path) for path in previous[2]} if previous else set()
        new = {absolute_path_key(path): path for path in paths}
        # A replacement detection plan may add volumes or reject old candidates.
        # Rejected paths are released without authorizing their deletion.
        for key in old - new.keys():
            self._counts[key] -= 1
            if eligible:
                self._wanted[key] -= 1
            if not self._counts[key]:
                self._counts.pop(key)
                self._paths.pop(key, None)
                self._wanted.pop(key, None)
        for key in new.keys() - old:
            path = new[key]
            self._paths.setdefault(key, path)
            self._counts[key] = self._counts.get(key, 0) + 1
            if eligible:
                self._wanted[key] = self._wanted.get(key, 0) + 1
        self._owned[owner] = (task, task_key, paths, eligible)

    def register_all(self, tasks) -> None:
        for task in tasks:
            self.register(task)

    def refresh(self, task) -> None:
        if id(task) in self._owned:
            self.register(task)

    def mark_cleanup_eligible(self, task) -> None:
        """Declare that this owner wants its paths removed once it is the last one."""

        entry = self._owned.get(id(task))
        if entry is None or entry[3]:
            return
        self._owned[id(task)] = (entry[0], entry[1], entry[2], True)
        for path in entry[2]:
            key = absolute_path_key(path)
            self._wanted[key] = self._wanted.get(key, 0) + 1

    def release(self, task) -> ReleaseRequest:
        return self._pop(id(task))

    def sweep(self) -> list[ReleaseRequest]:
        """Release every owner that never reported, in registration order."""

        requests: list[ReleaseRequest] = []
        for owner in list(self._owned):
            requests.append(self._pop(owner))
        return requests

    def _pop(self, owner: int) -> ReleaseRequest:
        entry = self._owned.pop(owner, None)
        if entry is None:
            return ReleaseRequest(task_key="")
        _task, task_key, paths, eligible = entry
        zeroed: list[str] = []
        cleanup_paths: list[str] = []
        for path in paths:
            key = absolute_path_key(path)
            remaining = self._counts.get(key, 0) - 1
            if remaining > 0:
                self._counts[key] = remaining
                continue
            self._counts.pop(key, None)
            self._paths.pop(key, None)
            wanted = self._wanted.pop(key, 0)
            zeroed.append(path)
            # Whoever takes the count to zero performs the deletion; an ineligible owner must not
            # delete, but an eligible owner sharing the path already asked for it to go.
            if eligible or wanted > 0:
                cleanup_paths.append(path)
        return ReleaseRequest(
            task_key=task_key,
            paths=tuple(zeroed),
            cleanup_paths=tuple(cleanup_paths),
        )

    def count(self, path: str) -> int:
        return self._counts.get(absolute_path_key(path), 0)

    def pending_tasks(self) -> tuple[object, ...]:
        return tuple(entry[0] for entry in self._owned.values())


__all__ = [
    "CleanupRefTable",
    "CleanupScopeResult",
    "ReleaseOutcome",
    "ReleaseRequest",
    "cleanup_paths_for",
]
