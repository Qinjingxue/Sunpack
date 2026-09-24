"""Marker scans handle ordinary stable output trees."""

from __future__ import annotations

from tests.helpers.marker_utils import marker_present


def test_marker_present_finds_a_stable_marker(tmp_path):
    root = tmp_path / "out"
    extracted = root / "extracted"
    extracted.mkdir(parents=True)
    (extracted / "payload.marker.txt").write_text("watch-output-routing", encoding="utf-8")

    assert marker_present(root, "payload.marker.txt") is True
    assert marker_present(root, "absent.marker.txt") is False
