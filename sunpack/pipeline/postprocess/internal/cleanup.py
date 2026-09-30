import os
import sys
from typing import Iterable

from send2trash import send2trash
from sunpack_native import prepare_file_cleanup, restore_staged_cleanup
from sunpack.core.contracts.results import ArchiveCleanupResult
from sunpack.core.i18n import I18nContext
from sunpack.core.support.path_keys import absolute_path_key


class ArchiveCleanup:
    def __init__(self, mode: str = "recycle", language: str = "en", *, stdout=None):
        self.mode = mode
        self.i18n = I18nContext(language)
        self.stdout = stdout if stdout is not None else sys.stdout

    def _print(self, value: str) -> None:
        print(value, file=self.stdout, flush=True)

    def cleanup_success_archives(
        self,
        archives_to_clean: Iterable[Iterable[str]],
        *,
        expected_generations: dict[str, str | None] | None = None,
    ) -> list[ArchiveCleanupResult]:
        unique_paths = {}
        for parts in archives_to_clean:
            for path in parts:
                unique_paths.setdefault(absolute_path_key(path), os.path.normpath(path))
        paths = list(unique_paths.values())
        self._print(self.i18n.t("cleanup.keep_done" if self.mode == "keep" else "cleanup.start"))
        if not paths:
            self._print(self.i18n.t("cleanup.none"))
            return []
        if self.mode == "keep":
            return [ArchiveCleanupResult(path, self.mode, "kept") for path in paths]
        if expected_generations is None:
            raise ValueError("source cleanup requires generations recorded before extraction")

        def prepared_files():
            if self.mode == "delete":
                # One Rust call for the complete delete batch; no per-file
                # interpreter crossings or extra path-based delete fallback.
                inputs = [(os.path.abspath(path), expected_generations.get(absolute_path_key(path))) for path in paths]
                yield from zip(paths, prepare_file_cleanup(inputs, False))
            else:
                # Stage and recycle one source at a time, so a recycle failure
                # cannot strand later sources already moved out of their paths.
                for path in paths:
                    row = prepare_file_cleanup([(os.path.abspath(path), expected_generations.get(absolute_path_key(path)))], True)[0]
                    yield path, row

        results: list[ArchiveCleanupResult] = []
        for path, (status, staged, code, message) in prepared_files():
            if status in {"deleted", "staged", "failed"}:
                self._print(self.i18n.t("cleanup.delete" if self.mode == "delete" else "cleanup.recycle",
                                        reason=self.i18n.t("cleanup.label"), filename=os.path.basename(path)))
            if status == "staged":
                try:
                    send2trash(staged)
                    status = "recycled"
                except Exception as exc:
                    status = "failed"
                    message = str(exc)
                    try:
                        restore_staged_cleanup(staged, os.path.abspath(path))
                    except Exception as restore_error:
                        message += f"; preserved source at {staged}: {restore_error}"
                    code = int(getattr(exc, "winerror", 0) or 0)
                    if not code:
                        code = int(getattr(exc, "hresult", 0) or 0) & 0xFFFF
            results.append(ArchiveCleanupResult(path, self.mode, status, error_code=code, message=message))
        return results
