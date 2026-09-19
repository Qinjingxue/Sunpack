from __future__ import annotations

from pathlib import Path


def marker_present(root: Path, marker_name: str) -> bool:
    """Return whether a name matches ``marker_name`` under ``root`` right now.

    Safe to call while extraction is publishing: a Watch staging directory is
    renamed to its final name on a broker worker thread, so a directory that
    ``rglob`` has already listed can vanish before pathlib enters it.  That
    transient view is not evidence of absence -- the caller polls again.
    """
    return any(safe_rglob(root, marker_name))


def safe_rglob(root: Path, pattern: str):
    """``root.rglob(pattern)`` that tolerates a tree mutating under the walk.

    Without this guard a rename or cleanup racing the traversal raises
    ``FileNotFoundError`` out of ``os.scandir``.
    """
    try:
        yield from root.rglob(pattern)
    except FileNotFoundError:
        return


def marker_was_extracted(root: Path, marker_name: str, marker_text: str) -> bool:
    """Return whether a file whose text equals the marker was produced under root."""
    return marker_scan_state(root, marker_name, marker_text) == "found"


def marker_scan_state(root: Path, marker_name: str, marker_text: str) -> str:
    """Three-way marker scan for watch tests that poll while extraction runs.

    Returns:
      - "found": a file whose text equals the marker exists and was read.
      - "missing": no candidate file exists (nothing to retry).
      - "locked": a candidate file exists but could not be read (e.g. it is
        still open for writing right after extraction).

    Polling callers should sleep-retry only on "locked"; "missing" means the
    archive is simply not extracted yet, so retrying would only block the
    event loop that drives the pipeline.
    """
    candidate_exists = False

    for path in safe_rglob(root, marker_name):
        try:
            if path.read_text(encoding="utf-8") == marker_text:
                return "found"
        except OSError:
            candidate_exists = True
            continue
    for path in safe_rglob(root, "*"):
        try:
            if not path.is_file():
                continue
        except OSError:
            candidate_exists = True
            continue
        try:
            if path.read_text(encoding="utf-8") == marker_text:
                return "found"
        except UnicodeDecodeError:
            continue
        except OSError:
            candidate_exists = True
            continue
    return "locked" if candidate_exists else "missing"
