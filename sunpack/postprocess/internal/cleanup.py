import os
import sys
from typing import Iterable

from send2trash import send2trash
from sunpack_native import delete_files_batch as _native_delete_files_batch
from sunpack.contracts.results import ArchiveCleanupResult
from sunpack.i18n import I18nContext


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


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
        previous: dict[str, ArchiveCleanupResult] | None = None,
    ) -> list[ArchiveCleanupResult]:
        unique_paths = {}
        for parts in archives_to_clean:
            for path in parts:
                unique_paths.setdefault(_path_key(path), os.path.normpath(path))
        paths = list(unique_paths.values())
        if previous is None:
            self._print(self.i18n.t("cleanup.keep_done" if self.mode == "keep" else "cleanup.start"))
            if not paths:
                self._print(self.i18n.t("cleanup.none"))
        results: list[ArchiveCleanupResult] = []
        pending: list[tuple[str, int]] = []
        for path in paths:
            prior = (previous or {}).get(_path_key(path))
            attempts = prior.attempts + 1 if prior else 1
            if self.mode == "keep":
                results.append(ArchiveCleanupResult(path, self.mode, "kept", attempts))
                continue
            if not os.path.exists(path):
                results.append(ArchiveCleanupResult(path, self.mode, "missing", attempts))
                continue
            self._print(self.i18n.t("cleanup.delete" if self.mode == "delete" else "cleanup.recycle",
                                    reason=self.i18n.t("cleanup.label"), filename=os.path.basename(path)))
            pending.append((path, attempts))
        if self.mode == "delete":
            try:
                native_results = list(_native_delete_files_batch([item[0] for item in pending]))
            except Exception as exc:
                code = int(getattr(exc, "winerror", 0) or 0)
                return [
                    *results,
                    *(
                        ArchiveCleanupResult(path, self.mode, "failed", attempts, code, str(exc))
                        for path, attempts in pending
                    ),
                ]
            for index, (path, attempts) in enumerate(pending):
                item = native_results[index] if index < len(native_results) else {
                    "status": "error",
                    "error": "Native cleanup returned no result",
                    "error_code": 0,
                }
                native_status = str(item.get("status") or "error")
                status = native_status if native_status in {"deleted", "missing"} else "failed"
                results.append(ArchiveCleanupResult(path, self.mode, status, attempts,
                                                   int(item.get("error_code") or 0),
                                                   str(item.get("error") or "")))
        else:
            for path, attempts in pending:
                try:
                    send2trash(path)
                    results.append(ArchiveCleanupResult(path, self.mode, "recycled", attempts))
                except Exception as exc:
                    code = int(getattr(exc, "winerror", 0) or 0)
                    if not code:
                        code = int(getattr(exc, "hresult", 0) or 0) & 0xFFFF
                    results.append(ArchiveCleanupResult(path, self.mode, "failed", attempts,
                                                       code, str(exc)))
        return results

    def cleanup_archive_file(self, path: str, reason: str | None = None) -> ArchiveCleanupResult:
        return self.cleanup_success_archives([[path]])[0]
