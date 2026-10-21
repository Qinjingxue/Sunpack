from __future__ import annotations

import os
from threading import RLock
from sunpack.core.support.path_keys import absolute_path_key
from sunpack.core.passwords.internal.store import password_scope_key


class PasswordScopeContext:
    """Request-owned original input directories, including recursive outputs."""

    def __init__(self, scope_dir: str = ""):
        self.scope_dir = scope_dir
        self._outputs: dict[str, str] = {}
        self._lock = RLock()

    def __deepcopy__(self, memo):
        return self

    def for_path(self, archive_path: str) -> str:
        key = absolute_path_key(archive_path)
        with self._lock:
            while True:
                scope = self._outputs.get(key.rstrip("\\/"))
                if scope is not None:
                    return scope
                parent = os.path.dirname(key)
                if parent == key:
                    break
                key = parent
        return self.scope_dir or os.path.dirname(os.path.abspath(archive_path))

    def annotate(self, tasks) -> None:
        for task in tasks:
            task.runtime.setdefault("password_scope_dir", self.for_path(task.main_path))

    def remember(self, output_dir: str, task) -> None:
        if output_dir:
            with self._lock:
                self._outputs[password_scope_key(output_dir)] = task.runtime.get("password_scope_dir") or self.for_path(task.main_path)


def password_scope_for_path(config: dict, path: str) -> str:
    context = config.get("password_scope_context")
    return context.for_path(path) if context is not None else config.get("password_scope_dir") or os.path.dirname(os.path.abspath(path))
