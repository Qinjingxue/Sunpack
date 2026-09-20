"""Marker scans must tolerate a directory tree that mutates under the walk."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.helpers.marker_utils import marker_present, safe_rglob

MARKER = "payload.marker.txt"
MARKER_TEXT = "watch-output-routing"


def _rename_then_fail_rglob(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    source: Path,
    destination: Path,
) -> dict:
    """Inject the publication race at the public Path.rglob boundary.

    The behavior under test is that safe_rglob absorbs a FileNotFoundError
    raised while advancing the recursive iterator. Do not couple this test
    to pathlib private internals such as Path._accessor; those differ across
    supported Python versions.

    Rename the staging directory out of the tree immediately before raising
    the same error that a raced filesystem walk would surface.
    """
    state = {"renamed": False}
    real_rglob = Path.rglob
    root_key = os.path.abspath(os.fspath(root))

    def raced_rglob(path: Path, pattern: str):
        if not state["renamed"] and os.path.abspath(os.fspath(path)) == root_key:
            state["renamed"] = True
            os.rename(source, destination)
            raise FileNotFoundError(os.fspath(source))
        yield from real_rglob(path, pattern)

    monkeypatch.setattr(Path, "rglob", raced_rglob)
    return state

def _staged_marker(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "out"
    staging = root / ".sunpack-partial-abc123"
    staged = staging / "extracted"
    staged.mkdir(parents=True)
    (staged / MARKER).write_text(MARKER_TEXT, encoding="utf-8")
    return root, staging, staged


def test_safe_rglob_survives_the_staging_directory_vanishing_mid_walk(tmp_path, monkeypatch):
    root, staging, _staged = _staged_marker(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    # Simulate pathlib observing the staging directory disappear while its
    # recursive iterator is being advanced.
    state = _rename_then_fail_rglob(monkeypatch, root, staging, elsewhere / "published")

    matches = list(safe_rglob(root, MARKER))

    assert state["renamed"] is True
    assert matches == []


def test_unguarded_rglob_raises_on_the_same_interleaving(tmp_path, monkeypatch):
    """Pin the hazard the guard exists for."""
    root, staging, _staged = _staged_marker(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _rename_then_fail_rglob(monkeypatch, root, staging, elsewhere / "published")

    with pytest.raises(FileNotFoundError):
        list(root.rglob(MARKER))


def test_marker_present_finds_a_stable_marker(tmp_path):
    """The polling predicate must still see the ordinary, un-raced case."""
    root, _staging, _staged = _staged_marker(tmp_path)

    assert marker_present(root, MARKER) is True
    assert marker_present(root, "absent.marker.txt") is False


def test_marker_present_is_false_when_the_marker_left_the_tree(tmp_path, monkeypatch):
    root, staging, _staged = _staged_marker(tmp_path)
    # Redirect the rename out of the scanned tree: the poll must observe
    # absence instead of raising out of scandir.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    state = _rename_then_fail_rglob(monkeypatch, root, staging, elsewhere / "published")

    assert marker_present(root, MARKER) is False
    assert state["renamed"] is True
    assert (elsewhere / "published" / "extracted" / MARKER).exists()
