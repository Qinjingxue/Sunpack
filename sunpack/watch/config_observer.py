from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path
from typing import Callable, Iterable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


class ConfigFileObserver:
    """Observe selected files in one directory and emit a debounced callback."""

    def __init__(
        self,
        directory: Path,
        filenames: Iterable[str],
        callback: Callable[[], None],
        *,
        debounce_seconds: float = 0.5,
        observer_factory=Observer,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self.directory = Path(directory).resolve()
        self.filenames = {str(name).casefold() for name in filenames}
        self.callback = callback
        self.debounce_seconds = max(0.0, float(debounce_seconds))
        self._observer = observer_factory()
        self._handler = _ConfigEventHandler(self)
        self._loop = loop
        self._timer: asyncio.TimerHandle | None = None
        self._lock = threading.Lock()
        self._started = False
        self._stopped = False

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
        try:
            self._observer.schedule(self._handler, str(self.directory), recursive=False)
            self._observer.start()
        except Exception:
            with self._lock:
                self._started = False
            if bool(getattr(self._observer, "is_alive", lambda: False)()):
                self._observer.stop()
                self._observer.join(timeout=1.0)
            raise

    def stop(self, *, timeout_seconds: float = 5.0) -> None:
        with self._lock:
            self._stopped = True
            timer = self._timer
            self._timer = None
        if timer is not None:
            timer.cancel()
        if not self._started:
            return
        self._observer.stop()
        self._observer.join(timeout=max(0.0, float(timeout_seconds)))
        self._started = False

    def notify_path_changed(self, path: str) -> None:
        if not path or Path(path).name.casefold() not in self.filenames:
            return
        with self._lock:
            if self._stopped:
                return
            self._loop.call_soon_threadsafe(self._schedule_emit)

    def _schedule_emit(self) -> None:
        with self._lock:
            if self._stopped:
                return
            if self._timer is not None:
                self._timer.cancel()
            self._timer = self._loop.call_later(self.debounce_seconds, self._emit)

    def _emit(self) -> None:
        with self._lock:
            if self._stopped:
                return
            self._timer = None
        self.callback()


class _ConfigEventHandler(FileSystemEventHandler):
    def __init__(self, owner: ConfigFileObserver) -> None:
        self.owner = owner

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._handle(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._handle(event)
        self.owner.notify_path_changed(str(getattr(event, "dest_path", "") or ""))

    def _handle(self, event: FileSystemEvent) -> None:
        if getattr(event, "is_directory", False):
            return
        self.owner.notify_path_changed(str(getattr(event, "src_path", "") or ""))
