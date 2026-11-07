from __future__ import annotations

import asyncio
import threading
import os
import weakref
from pathlib import Path
from typing import Callable, Iterable

from watchdog.events import DirModifiedEvent, FileModifiedEvent, FileSystemEvent, FileSystemEventHandler
from watchdog.observers.api import BaseObserver, EventEmitter


class _ConfigEmitter(EventEmitter):
    def on_thread_start(self) -> None:
        from sunpack_native import NativeConfigChanges
        # The first OS request is armed synchronously, before start() returns.
        self._changes = NativeConfigChanges(self.watch.path)

    def on_thread_stop(self) -> None:
        if changes := getattr(self, "_changes", None):
            changes.close()

    def queue_events(self, timeout: float) -> None:
        names = self._changes.read()
        if names is None:
            self.queue_event(DirModifiedEvent(self.watch.path))
        else:
            for name in names:
                self.queue_event(FileModifiedEvent(os.path.join(self.watch.path, name)))


def _config_observer():
    return BaseObserver(_ConfigEmitter)


class ConfigFileObserver:
    """Observe selected files and coalesce events before immediate loop dispatch."""

    def __init__(
        self,
        directory: Path,
        filenames: Iterable[str],
        callback: Callable[[], None],
        *,
        observer_factory=_config_observer,
        loop: asyncio.AbstractEventLoop,
        additional_files=(),
    ) -> None:
        self.directory = Path(directory).resolve()
        self.filenames = {str(name).casefold() for name in filenames}
        self.callback = callback
        self._base_files = [(self.directory, self.filenames, callback), *additional_files]
        self._files = {}
        self._directories = {}
        self._pending_callbacks = set()
        self._observer = observer_factory()
        self._handler = _ConfigEventHandler(self)
        self._loop = loop
        self._scheduled_emit: asyncio.Handle | None = None
        self._lock = threading.Lock()
        self._started = False
        self._stopped = False
        self._watches = {}
        self.set_additional_files(())

    def set_additional_files(self, files) -> None:
        """Replace request-source subscriptions; evicted sources release watches."""
        selected = {}
        directories = {}
        for directory, names, notify in [*self._base_files, *files]:
            directory = Path(directory).resolve()
            callbacks = directories.setdefault(directory, set())
            for name in names:
                selected.setdefault(str(directory / str(name)).casefold(), set()).add(notify)
                callbacks.add(notify)
        with self._lock:
            if self._stopped:
                return
            started = self._started
            previous = self._directories
            # Dispatch may start inside schedule(); publish filters first.
            self._files = selected
            self._directories = directories
        # Watchdog dispatch holds its own lock before calling our handler.
        # Never take that lock while holding the callback lock.
        if started:
            for directory in directories.keys() - previous.keys():
                self._watches[directory] = self._observer.schedule(self._handler, str(directory), recursive=False)
            for directory in previous.keys() - directories.keys():
                self._observer.unschedule(self._watches.pop(directory))

    def start(self) -> None:
        with self._lock:
            if self._started or self._stopped:
                return
            self._started = True
        try:
            for directory in self._directories:
                self._watches[directory] = self._observer.schedule(self._handler, str(directory), recursive=False)
            self._observer.start()
        except Exception:
            # An earlier emitter may already be running when a later one fails,
            # even though the dispatcher thread has not started yet.
            self._observer.stop()
            if bool(getattr(self._observer, "is_alive", lambda: False)()):
                self._observer.join()
            with self._lock:
                self._started = False
            self.stop()
            raise

    def stop(self) -> None:
        with self._lock:
            self._stopped = True
            scheduled = self._scheduled_emit
            self._scheduled_emit = None
            self._pending_callbacks.clear()
            self.callback = None
            self._base_files.clear()
            self._files.clear()
            self._directories.clear()
        if scheduled is not None:
            scheduled.cancel()
        if self._started:
            self._observer.stop()
            self._observer.join()
            self._started = False
        self._watches.clear()

    def notify_path_changed(self, path: str) -> None:
        key = str(Path(path).absolute()).casefold() if path else ""
        with self._lock:
            if self._stopped:
                return
            callbacks = self._files.get(key)
            if not callbacks:
                return
            self._schedule_callbacks_locked(callbacks)

    def notify_directory_changed(self, path: str) -> None:
        directory = Path(path).resolve()
        with self._lock:
            if self._stopped:
                return
            callbacks = self._directories.get(directory)
            if callbacks:
                self._schedule_callbacks_locked(callbacks)

    def _schedule_callbacks_locked(self, callbacks) -> None:
        self._pending_callbacks.update(callbacks)
        # Coalesce before crossing threads: a busy loop must not retain one
        # callback per filesystem event. No timer delays configuration updates.
        if self._scheduled_emit is None:
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


class _ConfigEventHandler(FileSystemEventHandler):
    def __init__(self, owner: ConfigFileObserver) -> None:
        self._owner = weakref.ref(owner)

    def on_any_event(self, event: FileSystemEvent) -> None:
        owner = self._owner()
        if owner is None:
            return
        if event.is_directory:
            if event.event_type == "modified":
                owner.notify_directory_changed(event.src_path)
        elif event.event_type in {"created", "modified", "deleted", "moved"}:
            owner.notify_path_changed(str(event.src_path))
            if event.event_type == "moved":
                owner.notify_path_changed(str(event.dest_path))
