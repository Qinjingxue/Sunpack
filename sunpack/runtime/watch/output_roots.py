"""Persistent Watch exclusions; normal reservations own active output paths."""
from __future__ import annotations

import os
import threading

from sunpack_native import create_output_root, watch_path_identity
from sunpack.core.support.path_keys import path_key


class WatchOutputRoots:
    def __init__(self, state, scopes):
        self.state = state
        self.scopes = scopes
        self._lock = threading.RLock()
        self._closed = False
        for key in state._native.runtime_keys("owned|"):
            record = state._native.runtime_record(key)
            if not self._relevant(record["path"]) or not self._matches(record):
                state.commit_runtime([{"op": "runtime", "key": key}], durable=True)

    def _relevant(self, path):
        return any(scope.native.intersects_output(path) for scope in self.scopes)

    @staticmethod
    def _identity(path):
        volume, identity, _ = watch_path_identity(path)
        return f"{volume}|{identity}"

    def _matches(self, record):
        try:
            identity = self._identity(record["path"])
        except FileNotFoundError:
            return False
        except OSError:
            return True
        return identity in record.get("identities", ())

    def register(self, path):
        if not self._relevant(path):
            return
        with self._lock:
            if self._closed or self.protected(path):
                return
            # Reservations already exclude this root before mkdir emits events.
            # Only Watch-relevant outputs incur identity IO and a WAL record.
            # Exclusive creation must reject directories created by other processes.
            create_output_root(os.path.abspath(path))
            self._put(path)

    def _put(self, path):
        self.state.commit_runtime([{"op": "runtime", "key": "owned|" + path_key(path),
            "value": {"path": os.path.abspath(path), "identities": [self._identity(path)]}}], durable=True)

    def protected(self, path):
        with self._lock:
            root = self.state._native.owned_root(path)
            return root is not None

    def reconcile(self, path, *, recursive=False):
        normalized = path_key(path)
        with self._lock:
            if self._closed:
                return
            changes = []
            for key in self.state._native.runtime_keys("owned|" + normalized):
                root = key[len("owned|"):]
                if root != normalized and not (recursive and root.startswith(normalized + os.sep)):
                    continue
                record = self.state._native.runtime_record(key)
                if not self._matches(record):
                    changes.append({"op": "runtime", "key": key})
            self.state.commit_runtime(changes, durable=True)

    def replace(self, source, destination):
        with self._lock:
            if self._closed:
                return
            if self._relevant(destination) and os.path.isdir(destination):
                ancestor = self.state._native.owned_root(destination)
                if ancestor is None or ancestor == path_key(destination):
                    self._put(destination)
            self.reconcile(source, recursive=True)

    def close(self):
        with self._lock:
            self._closed = True
