import os
import threading
from collections.abc import Callable

from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.output_paths import next_available_path


class OutputReservationRegistry:
    """Atomically reserve not-yet-created output paths across requests."""

    def __init__(self):
        self._lock = threading.Lock()
        self._reserved: dict[str, str] = {}

    def reserve(self, default_path: str, owner: str, local_reserved: set[str]) -> str:
        with self._lock:
            occupied = {*self._reserved, *local_reserved}
            path = next_available_path(default_path, occupied)
            key = os.path.normcase(os.path.abspath(path))
            self._reserved[key] = owner
            local_reserved.add(key)
            return path

    def release(self, owner: str) -> None:
        with self._lock:
            stale = [path for path, current_owner in self._reserved.items() if current_owner == owner]
            for path in stale:
                self._reserved.pop(path, None)


def build_output_dir_resolver(
    tasks: list[ArchiveTask],
    default_output_dir_for_task: Callable[[ArchiveTask], str],
    *,
    reservation_registry: OutputReservationRegistry | None = None,
    owner: str = "",
) -> Callable[[ArchiveTask], str]:
    """Resolve one collision-free output path for every task in a batch."""
    resolved_dirs: dict[int, str] = {}
    reserved: set[str] = {}
    for task in tasks:
        default_dir = default_output_dir_for_task(task)
        if reservation_registry is None:
            resolved_dirs[id(task)] = next_available_path(default_dir, reserved)
        else:
            resolved_dirs[id(task)] = reservation_registry.reserve(default_dir, owner, reserved)
    return lambda task: resolved_dirs[id(task)]
