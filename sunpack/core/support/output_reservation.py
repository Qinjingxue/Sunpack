import os
import threading
from collections.abc import Callable

from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.support.output_paths import OutputPathAllocator
from sunpack.core.support.path_keys import resolved_path_key


class OutputReservationRegistry:
    """Atomically reserve new or continued output paths across requests."""

    def __init__(self):
        self._lock = threading.Lock()
        self._reserved: set[str] = set()
        self._owner_paths: dict[str, set[str]] = {}
        self._allocator = OutputPathAllocator()
        self.watch_outputs = None

    def reserve(self, default_path: str, owner: str, local_reserved: set[str], *, reuse_existing: bool = False) -> str:
        with self._lock:
            path = (os.path.normpath(default_path) if reuse_existing else
                    self._allocator.next_available(default_path, self._reserved, local_reserved, is_directory=True))
            key = resolved_path_key(path)
            if reuse_existing and (key in self._reserved or key in local_reserved):
                raise FileExistsError(f"output directory is already reserved: {path}")
            self._reserved.add(key)
            self._owner_paths.setdefault(owner, set()).add(key)
            local_reserved.add(key)
            return path

    def register_watch_output(self, path: str) -> None:
        outputs = self.watch_outputs
        if outputs is not None:
            outputs.register(path)

    def contains(self, path: str) -> bool:
        key = resolved_path_key(path)
        with self._lock:
            while key:
                if key in self._reserved:
                    return True
                parent = os.path.dirname(key)
                if parent == key:
                    break
                key = parent
        return False

    def release(self, owner: str) -> None:
        with self._lock:
            for path in self._owner_paths.pop(owner, ()):
                self._reserved.remove(path)
                self._allocator.release(path)

    def clear_idle_cache(self) -> dict[str, int | bool]:
        """Drop search history only when no request owns a reservation."""
        with self._lock:
            if self._reserved or self._owner_paths:
                return {"skipped": True}
            return self._allocator.clear_cache()


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
        continued_dir = task.runtime.get("retry_output_dir")
        default_dir = continued_dir or default_output_dir_for_task(task)
        if reservation_registry is None:
            path = default_dir if continued_dir else allocator.next_available(default_dir, reserved, is_directory=True)
            reserved.add(resolved_path_key(path))
            resolved_dirs[id(task)] = path
        else:
            resolved_dirs[id(task)] = reservation_registry.reserve(default_dir, owner, reserved, reuse_existing=bool(continued_dir))
    return lambda task: resolved_dirs[id(task)]
