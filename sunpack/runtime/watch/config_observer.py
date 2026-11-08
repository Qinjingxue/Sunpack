from __future__ import annotations

import asyncio
import threading
import weakref
from pathlib import Path
from typing import Callable, Iterable

from sunpack_native import NativeConfigChanges


class _ConfigWatch(threading.Thread):
    def __init__(self, directory: Path, owner: ConfigFileObserver) -> None:
        super().__init__(name="sunpack-config-watch", daemon=True)
        self._directory = directory
        self._owner = weakref.ref(owner)
        # Arm the first OS request before the reader thread starts.
        self._changes = NativeConfigChanges(directory)

    def run(self) -> None:
        changes = self._changes
        try:
            while True:
                names = changes.read()
                if names == []:  # Native close interrupted the read.
                    return
                owner = self._owner()
                if owner is None:
                    return
                owner._notify(self._directory, names)
                del owner, names  # Release the batch before the next blocking read.
        finally:
            changes.close()
            self._changes = None

    def close(self) -> None:
        if changes := self._changes:
            changes.close()


class ConfigFileObserver:
    """Observe selected files and coalesce native batches before loop dispatch."""

    def __init__(
        self,
        directory: Path,
        filenames: Iterable[str],
        callback: Callable[[], None],
        *,
        loop: asyncio.AbstractEventLoop,
        additional_files=(),
    ) -> None:
        self._base_files = [(directory, tuple(filenames), callback), *additional_files]
        self._directories: dict[Path, dict[str, set[Callable[[], None]]]] = {}
        self._pending_callbacks: set[Callable[[], None]] = set()
        self._loop = loop
        self._scheduled_emit: asyncio.Handle | None = None
        self._lock = threading.Lock()
        self._started = False
        self._stopped = False
        self._watches: dict[Path, _ConfigWatch] = {}
        self.set_additional_files(())

    def set_additional_files(self, files) -> None:
        """Replace request-source subscriptions; evicted sources release watches."""
        directories = {}
        for directory, names, callback in [*self._base_files, *files]:
            selected = directories.setdefault(Path(directory).resolve(), {})
            for name in names:
                selected.setdefault(str(name).casefold(), set()).add(callback)
        with self._lock:
            if self._stopped:
                return
            self._directories = directories
        # The owner serializes start, stop and subscription changes. Joining a
        # reader must happen outside the lock it uses to publish notifications.
        if self._started:
            for directory in self._watches.keys() - directories.keys():
                watch = self._watches.pop(directory)
                watch.close()
                watch.join()
            for directory in directories.keys() - self._watches.keys():
                self._start_watch(directory)

    def _start_watch(self, directory: Path) -> None:
        watch = _ConfigWatch(directory, self)
        try:
            watch.start()
        except BaseException:
            watch.close()
            raise
        self._watches[directory] = watch

    def start(self) -> None:
        if self._started or self._stopped:
            return
        self._started = True
        try:
            for directory in self._directories:
                self._start_watch(directory)
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        with self._lock:
            self._stopped = True
            scheduled = self._scheduled_emit
            self._scheduled_emit = None
            self._pending_callbacks.clear()
            self._base_files.clear()
            self._directories.clear()
        if scheduled is not None:
            scheduled.cancel()
        for watch in self._watches.values():
            watch.close()
            watch.join()
        self._watches.clear()

    def _notify(self, directory: Path, names: list[str] | None) -> None:
        with self._lock:
            selected = self._directories.get(directory)
            if not selected:
                return
            if names is None:  # Overflow invalidates every subscription here.
                for callbacks in selected.values():
                    self._pending_callbacks.update(callbacks)
            else:
                for name in names:
                    callbacks = selected.get(name.casefold())
                    if callbacks is not None:
                        self._pending_callbacks.update(callbacks)
            if self._pending_callbacks and self._scheduled_emit is None:
                self._scheduled_emit = self._loop.call_soon_threadsafe(self._emit)

    def _emit(self) -> None:
        with self._lock:
            self._scheduled_emit = None
            if self._stopped:
                return
            callbacks = tuple(self._pending_callbacks)
            self._pending_callbacks.clear()
        for callback in callbacks:
            # A preceding callback can stop this shared observer.
            if self._stopped:
                break
            callback()
