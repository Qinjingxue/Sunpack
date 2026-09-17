from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sunpack_native import (
    validate_ntfs_watch_root as _native_validate_ntfs_watch_root,
    watch_candidate_for_path as _native_watch_candidate_for_path,
    watch_file_is_ready as _native_watch_file_is_ready,
    watch_volume_cursor as _native_watch_volume_cursor,
    watch_path_identity as _native_watch_path_identity,
    watch_root_changes as _native_watch_root_changes,
)


@dataclass(frozen=True)
class WatchCandidate:
    path: str
    size: int
    mtime: float
    file_id: str = ""
    change_usn: int = 0
    change_reasons: int = 0
    change_reasons_without_close: int = 0
    change_reasons_known: bool = False
    change_reason_error: str = ""


def scan_watch_candidates(roots: list[str], *, recursive: bool = True) -> list[WatchCandidate]:
    return _scan_filesystem_candidates(list(roots or []), bool(recursive))


def _candidate_for(path: str, *, since_usn: int = 0) -> WatchCandidate | None:
    item = _native_watch_candidate_for_path(str(path), int(since_usn) or None)
    return _candidate_from_native(item) if item is not None else None


def watch_candidate_for_path(path: str, *, since_usn: int = 0) -> WatchCandidate | None:
    """Return the native identity and change journal observation for a path."""

    return _candidate_for(path, since_usn=since_usn)


def _candidate_from_native(item: dict) -> WatchCandidate:
    return WatchCandidate(
        path=str(item.get("path") or ""),
        size=int(item.get("size", 0) or 0),
        mtime=float(item.get("mtime", 0.0) or 0.0),
        file_id=str(item.get("file_id") or ""),
        change_usn=int(item.get("change_usn", 0) or 0),
        change_reasons=int(item.get("change_reasons", 0) or 0),
        change_reasons_without_close=int(
            item.get("change_reasons_without_close", item.get("change_reasons", 0)) or 0
        ),
        change_reasons_known=bool(item.get("change_reasons_known", False)),
        change_reason_error=str(item.get("change_reason_error") or ""),
    )


def _scan_filesystem_candidates(roots: list[str], recursive: bool) -> list[WatchCandidate]:
    from sunpack_native import scan_watch_candidates as native_scan_watch_candidates

    return [_candidate_from_native(item) for item in native_scan_watch_candidates(roots, recursive)]


def validate_ntfs_watch_roots(roots: list[str]) -> None:
    for root in roots:
        _native_validate_ntfs_watch_root(str(root))


def watch_file_is_ready(path: str) -> bool:
    return bool(_native_watch_file_is_ready(str(path)))


def watch_volume_cursor(path: str) -> tuple[str, int, int]:
    volume, journal_id, next_usn = _native_watch_volume_cursor(str(path))
    return str(volume).lower(), int(journal_id), int(next_usn)


def watch_path_identity(path: str) -> tuple[str, str, int]:
    volume, file_id, change_usn = _native_watch_path_identity(str(path))
    return str(volume).lower(), str(file_id), int(change_usn)


def watch_root_changes(path: str, start_usn: int, end_usn: int) -> list[str]:
    names = _native_watch_root_changes(str(path), int(start_usn), int(end_usn))
    root = Path(path)
    return [str(root if name == "" else root / str(name)) for name in names]
