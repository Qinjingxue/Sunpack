from __future__ import annotations

import json
import os
import threading
import time
import weakref
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sunpack.core.support.path_keys import case_key
from sunpack.core.support.resource_lifecycle import open_service_file


DEFAULT_EVENTS_MAX_BYTES = 1 * 1024 * 1024

_PATH_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: weakref.WeakValueDictionary[str, threading.Lock] = weakref.WeakValueDictionary()


def append_jsonl_record(
    path: str | Path,
    record: dict[str, Any],
    *,
    max_bytes: int = DEFAULT_EVENTS_MAX_BYTES,
) -> None:
    """Append a JSONL record, resetting the log if the next record exceeds its limit."""
    target = Path(path)
    encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    limit = max(1, int(max_bytes))
    lock = _path_lock(target)
    with lock:
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            current_size = target.stat().st_size
        except FileNotFoundError:
            current_size = 0
        mode = "wb" if current_size > 0 and current_size + len(encoded) > limit else "ab"
        with open_service_file(target, mode) as handle:
            handle.write(encoded)


def _path_lock(path: Path) -> threading.Lock:
    key = case_key(os.path.abspath(str(path)))
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
        return lock


class WatchLogStore:
    def __init__(
        self,
        path: str,
        *,
        max_bytes: int = DEFAULT_EVENTS_MAX_BYTES,
        wake_callback: Callable[[], None] | None = None,
    ):
        self.path = Path(path)
        self._path_lock = _path_lock(self.path)
        self.max_bytes = max(1, int(max_bytes))
        self._throttle_lock = threading.Lock()
        self._last_throttled_write: dict[tuple[str, str], tuple[float, float]] = {}
        self._next_throttle_expiry: float | None = None
        self._wake_callback = wake_callback

    @property
    def next_history_expiry(self) -> float | None:
        with self._throttle_lock:
            return self._next_throttle_expiry

    def clear_expired_history(self) -> None:
        with self._throttle_lock:
            self._clear_expired_history_locked(time.monotonic())

    def _clear_expired_history_locked(self, now: float) -> None:
        if self._next_throttle_expiry is None or now < self._next_throttle_expiry:
            return
        expired = [token for token, (_, expiry) in self._last_throttled_write.items() if expiry <= now]
        for token in expired:
            del self._last_throttled_write[token]
        if not self._last_throttled_write:
            self._last_throttled_write.clear()
        self._next_throttle_expiry = min(
            (expiry for _, expiry in self._last_throttled_write.values()), default=None,
        )

    def close(self) -> None:
        with self._throttle_lock:
            self._wake_callback = None
            self._last_throttled_write.clear()
            self._next_throttle_expiry = None

    def write(self, event: str, **payload: Any) -> None:
        record = {
            "ts": time.time(),
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **payload,
        }
        try:
            append_jsonl_record(
                self.path,
                record,
                max_bytes=self.max_bytes,
            )
        except Exception:
            return

    def write_throttled(
        self,
        event: str,
        *,
        throttle_key: str,
        interval_seconds: float,
        **payload: Any,
    ) -> None:
        token = (event, str(throttle_key))
        interval = max(0.0, float(interval_seconds))
        wake_callback = None
        with self._throttle_lock:
            now = time.monotonic()
            self._clear_expired_history_locked(now)
            previous = self._last_throttled_write.get(token)
            if previous is not None and now - previous[0] < interval:
                self._last_throttled_write[token] = (previous[0], max(previous[1], previous[0] + interval))
                return
            if interval > 0.0:
                expiry = now + interval
                self._last_throttled_write[token] = (now, expiry)
                if len(self._last_throttled_write) > 2048:
                    oldest = min(self._last_throttled_write, key=lambda key: self._last_throttled_write[key][0])
                    del self._last_throttled_write[oldest]
                if self._next_throttle_expiry is None or expiry < self._next_throttle_expiry:
                    self._next_throttle_expiry = expiry
                    wake_callback = self._wake_callback
            else:
                self._last_throttled_write.pop(token, None)
                if not self._last_throttled_write:
                    self._last_throttled_write.clear()
                    self._next_throttle_expiry = None
        if wake_callback is not None:
            wake_callback()
        self.write(event, **payload)
