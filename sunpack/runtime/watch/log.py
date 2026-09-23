from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sunpack.core.support.resource_lifecycle import open_service_file


DEFAULT_EVENTS_MAX_BYTES = 1 * 1024 * 1024
DEFAULT_EVENTS_BACKUP_COUNT = 1

_PATH_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.Lock] = {}


def append_jsonl_record(
    path: str | Path,
    record: dict[str, Any],
    *,
    max_bytes: int = DEFAULT_EVENTS_MAX_BYTES,
    backup_count: int = DEFAULT_EVENTS_BACKUP_COUNT,
) -> None:
    """Append one JSONL record, rotating the file before it exceeds its limit."""
    target = Path(path)
    encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    limit = max(1, int(max_bytes))
    backups = max(1, int(backup_count))
    lock = _path_lock(target)
    with lock:
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            current_size = target.stat().st_size
        except FileNotFoundError:
            current_size = 0
        if current_size > 0 and current_size + len(encoded) > limit:
            _rotate_jsonl(target, backups)
        with open_service_file(target, "ab") as handle:
            handle.write(encoded)


def _path_lock(path: Path) -> threading.Lock:
    key = os.path.normcase(os.path.abspath(str(path)))
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
        return lock


def _rotate_jsonl(path: Path, backup_count: int) -> None:
    for index in range(backup_count, 0, -1):
        source = path if index == 1 else path.with_name(f"{path.name}.{index - 1}")
        destination = path.with_name(f"{path.name}.{index}")
        if source.exists():
            os.replace(source, destination)


class WatchLogStore:
    def __init__(
        self,
        path: str,
        *,
        max_bytes: int = DEFAULT_EVENTS_MAX_BYTES,
        backup_count: int = DEFAULT_EVENTS_BACKUP_COUNT,
    ):
        self.path = Path(path)
        self.max_bytes = max(1, int(max_bytes))
        self.backup_count = max(1, int(backup_count))
        self._throttle_lock = threading.Lock()
        self._last_throttled_write: dict[tuple[str, str], float] = {}

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
                backup_count=self.backup_count,
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
        now = time.monotonic()
        token = (event, str(throttle_key))
        with self._throttle_lock:
            previous = self._last_throttled_write.get(token)
            if previous is not None and now - previous < max(0.0, interval_seconds):
                return
            self._last_throttled_write[token] = now
            if len(self._last_throttled_write) > 2048:
                oldest = min(self._last_throttled_write, key=self._last_throttled_write.get)
                self._last_throttled_write.pop(oldest, None)
        self.write(event, **payload)
