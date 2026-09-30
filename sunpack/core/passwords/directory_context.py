from __future__ import annotations

import os
from collections import OrderedDict
from concurrent.futures import Future
from threading import RLock
from typing import Any

from sunpack_native import file_generation_tokens

from sunpack.core.passwords.internal.lists import dedupe_passwords
from sunpack.core.passwords.internal.local_files import (
    DIRECTORY_PASSWORD_CONTEXT_KEY,
    DIRECTORY_PASSWORD_FILE_NAME,
    discover_directory_passwords_for_archive,
    is_directory_password_file,
)


class DirectoryPasswordContextStore:
    """Propagate directory password hints across recursive extraction outputs."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self._contexts: dict[str, list[str]] = {}
        self._local: OrderedDict[str, tuple[str | None, Future[list[str]]]] = OrderedDict()
        self._lock = RLock()

    def annotate(self, tasks: list[Any]) -> None:
        directories = dict.fromkeys(
            os.path.normcase(os.path.dirname(os.path.abspath(task.main_path)))
            for task in tasks
        )
        local_by_directory = {}
        if is_directory_password_file(DIRECTORY_PASSWORD_FILE_NAME, self.config):
            paths = [os.path.join(directory, DIRECTORY_PASSWORD_FILE_NAME) for directory in directories]
            for directory, generation in zip(directories, file_generation_tokens(paths)):
                local_by_directory[directory] = self._local_for(directory, generation)
        for task in tasks:
            inherited = self.inherited_for(task.main_path)
            directory = os.path.normcase(os.path.dirname(os.path.abspath(task.main_path)))
            local = local_by_directory.get(directory, [])
            task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] = dedupe_passwords([*inherited, *local])

    def _local_for(self, directory: str, generation: str | None) -> list[str]:
        with self._lock:
            cached = self._local.get(directory)
            owner = cached is None or cached[0] != generation
            if owner:
                future: Future[list[str]] = Future()
                self._local[directory] = (generation, future)
            else:
                future = cached[1]
            self._local.move_to_end(directory)
        if owner:
            try:
                values = (
                    discover_directory_passwords_for_archive(
                        os.path.join(directory, DIRECTORY_PASSWORD_FILE_NAME), self.config,
                    )
                    if generation is not None else []
                )
            except BaseException as exc:
                future.set_exception(exc)
                with self._lock:
                    if self._local.get(directory) == (generation, future):
                        self._local.pop(directory)
                raise
            else:
                future.set_result(values)
                with self._lock:
                    while len(self._local) > 512:
                        key, (_, oldest) = next(iter(self._local.items()))
                        if not oldest.done():
                            break
                        self._local.pop(key)
        return future.result()

    def remember(self, output_dir: str, task: Any) -> None:
        if not output_dir:
            return
        values = task.runtime.get(DIRECTORY_PASSWORD_CONTEXT_KEY)
        if not isinstance(values, list):
            return
        context = dedupe_passwords([str(value) for value in values if isinstance(value, str)])
        with self._lock:
            self._contexts[os.path.normcase(os.path.abspath(output_dir))] = context

    def inherited_for(self, archive_path: str) -> list[str]:
        if not archive_path:
            return []
        archive_key = os.path.normcase(os.path.abspath(archive_path))
        best_root = ""
        best_context: list[str] = []
        with self._lock:
            for root_key, context in self._contexts.items():
                if archive_key == root_key or archive_key.startswith(root_key + os.sep):
                    if len(root_key) > len(best_root):
                        best_root = root_key
                        best_context = context
        return list(best_context)
