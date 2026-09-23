from pathlib import Path

from sunpack.core.support import resources


def test_arm64_tool_dir_candidates_prefer_arm64(monkeypatch):
    monkeypatch.setattr(resources.platform, "machine", lambda: "ARM64")

    assert resources.tool_dir_candidates() == (Path("tools-arm64"), Path("tools"))
