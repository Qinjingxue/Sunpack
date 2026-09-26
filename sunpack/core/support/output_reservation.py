import threading
from collections.abc import Callable

from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.support.output_paths import OutputPathAllocator
from sunpack.core.support.path_keys import absolute_path_key


class OutputReservationRegistry:
    """Atomically reserve not-yet-created output paths across requests."""

    def __init__(self):
        self._lock = threading.Lock()
        self._reserved: set[str] = set()
        self._owner_paths: dict[str, set[str]] = {}
        self._allocator = OutputPathAllocator()

    def reserve(self, default_path: str, owner: str, local_reserved: set[str]) -> str:
        with self._lock:
            path = self._allocator.next_available(default_path, self._reserved, local_reserved)
            key = absolute_path_key(path)
            self._reserved.add(key)
            self._owner_paths.setdefault(owner, set()).add(key)
            local_reserved.add(key)
            return path

    def release(self, owner: str) -> None:
        with self._lock:
            for path in self._owner_paths.pop(owner, ()):
                self._reserved.remove(path)
                self._allocator.release(path)


def build_output_dir_resolver(
    tasks: list[ArchiveTask],
    default_output_dir_for_task: Callable[[ArchiveTask], str],
    *,
    reservation_registry: OutputReservationRegistry | None = None,
    owner: str = "",
) -> Callable[[ArchiveTask], str]:
    """Resolve one collision-free output path for every task in a batch."""
    resolved_dirs: dict[int, str] = {}
    reserved: set[str] = set()
    allocator = OutputPathAllocator() if reservation_registry is None else None
    for task in tasks:
        default_dir = default_output_dir_for_task(task)
        if reservation_registry is None:
            path = allocator.next_available(default_dir, reserved)
            reserved.add(absolute_path_key(path))
            resolved_dirs[id(task)] = path
        else:
            resolved_dirs[id(task)] = reservation_registry.reserve(default_dir, owner, reserved)
    return lambda task: resolved_dirs[id(task)]
