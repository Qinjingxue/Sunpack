import os
import threading
from collections.abc import Callable

from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.support.output_paths import OutputPathAllocator
from sunpack.core.support.path_keys import resolved_path_key, path_key_is_under, case_key
from sunpack.core.support.path_map import PathMap


class _ReservedSubtrees:
    def __init__(self):
        self.paths = PathMap()

    def __contains__(self, key):
        return self.paths.has_under(key)


class OutputReservationRegistry:
    """Atomically reserve new or continued output paths across requests."""

    def __init__(self):
        self._lock = threading.Lock()
        self._reserved = _ReservedSubtrees()
        self._owner_paths: dict[str, set[str]] = {}
        self._allocator = OutputPathAllocator()
        self.watch_outputs = None

    def reserve(self, default_path: str, owner: str, local_reserved: set[str], *, reuse_existing: bool = False,
                input_path: str = "") -> str:
        input_key = resolved_path_key(input_path) if input_path else ""
        with self._lock:
            path = os.path.normpath(default_path)
            if reuse_existing:
                key = resolved_path_key(path)
                physical_parent = os.path.dirname(key)
            else:
                physical_parent = resolved_path_key(os.path.dirname(path) or os.curdir)
                key = os.path.join(physical_parent, case_key(os.path.basename(path)))
            # Only recursive work on this owner's generated input may enter an
            # existing reservation. Independent jobs in one request conflict too.
            for ancestor, ancestor_owner in self._reserved.paths.ancestors(physical_parent):
                if input_key and ancestor_owner == owner and path_key_is_under(input_key, ancestor):
                    continue
                if reuse_existing:
                    raise FileExistsError(f"output directory overlaps a reserved output: {path}")
                tail = os.path.relpath(key, ancestor)
                base = self._ancestor_spelling(path, tail)
                suffix = os.path.relpath(path, base)
                base = self._allocator.next_available(base, self._reserved, local_reserved, is_directory=True)
                path = os.path.join(base, suffix)
                physical_parent = resolved_path_key(os.path.dirname(path) or os.curdir)
                break
            if not reuse_existing:
                path = self._allocator.next_available(
                    path, self._reserved, local_reserved, is_directory=True, physical_parent=physical_parent,
                )
                key = os.path.join(physical_parent, case_key(os.path.basename(path)))
            if reuse_existing and (key in self._reserved or key in local_reserved):
                raise FileExistsError(f"output directory is already reserved: {path}")
            self._reserved.paths[key] = owner
            self._owner_paths.setdefault(owner, set()).add(key)
            local_reserved.add(key)
            return path

    @staticmethod
    def _ancestor_spelling(path: str, tail: str) -> str:
        for _ in tail.split(os.sep):
            path = os.path.dirname(path)
        return path

    def register_watch_output(self, path: str) -> None:
        outputs = self.watch_outputs
        if outputs is not None:
            outputs.register(path)

    def contains(self, path: str) -> bool:
        key = resolved_path_key(path)
        with self._lock:
            return next(self._reserved.paths.ancestors(key), None) is not None

    def release(self, owner: str) -> None:
        with self._lock:
            for path in self._owner_paths.pop(owner, ()):
                del self._reserved.paths[path]
                # A rebase may have searched a numbered ancestor. Retire its
                # search hints too; live descendant reservations are rechecked.
                while path:
                    self._allocator.release(path)
                    parent = os.path.dirname(path)
                    if parent == path:
                        break
                    path = parent

    def clear_idle_cache(self) -> dict[str, int | bool]:
        """Drop search history only when no request owns a reservation."""
        with self._lock:
            if self._reserved.paths or self._owner_paths:
                return {"skipped": True}
            return self._allocator.clear_cache()


def build_output_dir_resolver(
    tasks: list[ArchiveTask],
    default_output_dir_for_task: Callable[[ArchiveTask], str],
    *,
    reservation_registry: OutputReservationRegistry | None = None,
    owner: str = "",
    nested: bool = False,
) -> Callable[[ArchiveTask], str]:
    """Resolve one collision-free output path for every task in a batch."""
    resolved_dirs: dict[int, str] = {}
    reserved: set[str] = set()
    reservation_registry = reservation_registry or OutputReservationRegistry()
    for task in tasks:
        continued_dir = task.runtime.get("retry_output_dir")
        default_dir = continued_dir or default_output_dir_for_task(task)
        resolved_dirs[id(task)] = reservation_registry.reserve(
            default_dir, owner, reserved, reuse_existing=bool(continued_dir),
            input_path=task.main_path if nested else "",
        )
    return lambda task: resolved_dirs[id(task)]
