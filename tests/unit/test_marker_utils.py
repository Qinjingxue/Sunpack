"""Marker scans must tolerate a directory tree that mutates under the walk."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.helpers.marker_utils import marker_present, safe_rglob

MARKER = "payload.marker.txt"
MARKER_TEXT = "watch-output-routing"


def _rename_on_first_deep_scan(
    monkeypatch: pytest.MonkeyPatch,
    trigger: Path,
    source: Path,
    destination: Path,
) -> dict:
    """Rename ``source`` -> ``destination`` the first time anything scandirs ``trigger``.

    Reproduces the Watch publication race: the output root is scanned, the
    staging directory is listed, and only then does the publisher's worker
    thread rename it away -- so pathlib's follow-up scandir of the staging
    directory observes a name that no longer exists.

    ``trigger`` must be strictly above ``source`` in the tree, so the rename
    lands after the parent listing that exposed the staging directory.

    ``pathlib`` resolves the scandir callable from ``Path._accessor`` on each
    walk, so the override lives on that accessor class rather than on
    ``os.scandir`` (``pathlib`` binds ``os.scandir`` at import and never
    re-reads it).
    """
    state = {"renamed": False}
    accessor = type(Path()._accessor)
    real_scandir = accessor.scandir
    trigger_key = os.path.abspath(str(trigger))

    def scandir(path=os.curdir):
        if not state["renamed"] and os.path.abspath(os.fspath(path)) == trigger_key:
            state["renamed"] = True
            os.rename(source, destination)
        return real_scandir(path)

    monkeypatch.setattr(accessor, "scandir", staticmethod(scandir))
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
    # The rename fires while scanning the *staging* directory, i.e. after the
    # output root was already listed with `.sunpack-partial-abc123` present.
    state = _rename_on_first_deep_scan(monkeypatch, staging, staging, elsewhere / "published")

    matches = list(safe_rglob(root, MARKER))

    assert state["renamed"] is True
    assert matches == []


def test_unguarded_rglob_raises_on_the_same_interleaving(tmp_path, monkeypatch):
    """Pin the hazard the guard exists for."""
    root, staging, _staged = _staged_marker(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _rename_on_first_deep_scan(monkeypatch, staging, staging, elsewhere / "published")

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
    state = _rename_on_first_deep_scan(monkeypatch, staging, staging, elsewhere / "published")

    assert marker_present(root, MARKER) is False
    assert state["renamed"] is True
    assert (elsewhere / "published" / "extracted" / MARKER).exists()
