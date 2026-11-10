import os
from typing import Iterable

from send2trash import send2trash
from sunpack.core.support.path_keys import case_key
from sunpack_native import delete_files_batch as _native_delete_files_batch
from sunpack.core.contracts.results import ArchiveCleanupResult


def _path_key(path: str) -> str:
    return case_key(os.path.abspath(path))


class ArchiveCleanup:
    def __init__(self, mode: str = "recycle"):
        if mode not in {"keep", "recycle", "delete"}:
            raise ValueError("archive_cleanup_mode must be normalized before ArchiveCleanup starts")
        self.mode = mode

    def cleanup_success_archives(
        self,
        archives_to_clean: Iterable[Iterable[str]],
    ) -> list[ArchiveCleanupResult]:
        unique_paths = {}
        for parts in archives_to_clean:
            for path in parts:
                unique_paths.setdefault(_path_key(path), os.path.normpath(path))
        paths = list(unique_paths.values())
        results: list[ArchiveCleanupResult] = []
        pending: list[str] = []
        for path in paths:
            if self.mode == "keep":
                results.append(ArchiveCleanupResult(path, self.mode, "kept"))
                continue
            if not os.path.exists(path):
                results.append(ArchiveCleanupResult(path, self.mode, "missing"))
                continue
            pending.append(path)
        if self.mode == "delete":
            try:
                native_results = list(_native_delete_files_batch(pending))
            except Exception as exc:
                code = int(getattr(exc, "winerror", 0) or 0)
                return [
                    *results,
                    *(
                        ArchiveCleanupResult(path, self.mode, "failed", code, str(exc))
                        for path in pending
                    ),
                ]
            for index, path in enumerate(pending):
                item = native_results[index] if index < len(native_results) else {
                    "status": "error",
                    "error": "Native cleanup returned no result",
                    "error_code": 0,
                }
                native_status = str(item.get("status") or "error")
                status = native_status if native_status in {"deleted", "missing"} else "failed"
                results.append(ArchiveCleanupResult(path, self.mode, status,
                                                   int(item.get("error_code") or 0),
                                                   str(item.get("error") or "")))
        else:
            for path in pending:
                try:
                    send2trash(path)
                    results.append(ArchiveCleanupResult(path, self.mode, "recycled"))
                except Exception as exc:
                    code = int(getattr(exc, "winerror", 0) or 0)
                    if not code:
                        code = int(getattr(exc, "hresult", 0) or 0) & 0xFFFF
                    results.append(ArchiveCleanupResult(path, self.mode, "failed",
                                                       code, str(exc)))
        return results
