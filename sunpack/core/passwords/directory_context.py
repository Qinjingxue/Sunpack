from __future__ import annotations

import os
from typing import Any

from sunpack.core.passwords.internal.lists import dedupe_passwords
from sunpack.core.passwords.internal.local_files import (
    DIRECTORY_PASSWORD_CONTEXT_KEY,
    discover_directory_passwords_for_archive,
)


class DirectoryPasswordContextStore:
    """Propagate directory password hints across recursive extraction outputs."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self._contexts: dict[str, list[str]] = {}

    def annotate(self, tasks: list[Any]) -> None:
        for task in tasks:
            inherited = self.inherited_for(task.main_path)
            local = discover_directory_passwords_for_archive(task.main_path, self.config)
            task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] = dedupe_passwords([*inherited, *local])

    def remember(self, output_dir: str, task: Any) -> None:
        if not output_dir:
            return
        values = task.runtime.get(DIRECTORY_PASSWORD_CONTEXT_KEY)
        if not isinstance(values, list):
            return
        context = dedupe_passwords([str(value) for value in values if isinstance(value, str)])
        self._contexts[os.path.normcase(os.path.abspath(output_dir))] = context

    def clear(self) -> None:
        """Release request-scoped recursion hints after a pipeline run."""
        self._contexts.clear()

    def inherited_for(self, archive_path: str) -> list[str]:
        if not archive_path:
            return []
        archive_key = os.path.normcase(os.path.abspath(archive_path))
        best_root = ""
        best_context: list[str] = []
        for root_key, context in self._contexts.items():
            if archive_key == root_key or archive_key.startswith(root_key + os.sep):
                if len(root_key) > len(best_root):
                    best_root = root_key
                    best_context = context
        return list(best_context)
