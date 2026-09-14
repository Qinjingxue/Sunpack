from __future__ import annotations

from pathlib import Path


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

    def safe_rglob(pattern: str):
        try:
            yield from root.rglob(pattern)
        except FileNotFoundError:
            # Extraction/cleanup may remove a directory while pathlib is
            # advancing the iterator.  Treat this tick as a changed
            # filesystem view; the next poll will observe the stable state.
            return

    for path in safe_rglob(marker_name):
        try:
            if path.read_text(encoding="utf-8") == marker_text:
                return "found"
        except OSError:
            candidate_exists = True
            continue
    for path in safe_rglob("*"):
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
