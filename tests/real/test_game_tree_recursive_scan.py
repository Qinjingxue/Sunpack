import io
import os
import subprocess
import zipfile
from pathlib import Path

import pytest


def test_game_like_tree_preserves_resource_archives_at_default_authorization(package, tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("internal.txt", "resource payload")
    source = tmp_path / "game.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("graphics/resources.zip", inner.getvalue())
        archive.writestr("graphics/texture.bin", b"texture data" * 16_384)
        archive.writestr("sound/music.bin", b"audio data" * 16_384)

    output = tmp_path / "protected"
    report = package.json("extract", "-r", "*", "-F", "-o", output, source)
    assert report["summary"]["success_count"] == 1, report
    assert (output / "game/graphics/resources.zip").read_bytes() == inner.getvalue()
    assert not list(output.rglob("internal.txt"))

    package.configure(recursive_authorization={"enabled": False})
    output = tmp_path / "unrestricted"
    report = package.json("extract", "-r", "*", "-F", "-o", output, source)
    assert report["summary"]["success_count"] == 2, report
    assert next(output.rglob("internal.txt")).read_text() == "resource payload"


@pytest.mark.skipif(
    os.environ.get("SUNPACK_RUN_GAME_TREE_TEST") != "1",
    reason="set SUNPACK_RUN_GAME_TREE_TEST=1 to use a local game tree",
)
def test_local_game_tree_resources_are_not_extracted_recursively(package, tmp_path):
    game_tree = Path(os.environ.get("SUNPACK_GAME_TREE_ROOT", r"D:\game"))
    if not game_tree.is_dir():
        pytest.skip(f"game tree is not available: {game_tree}")
    children = [f".\\{path.name}" for path in game_tree.iterdir() if path.is_dir()]
    if not children:
        pytest.skip("game tree has no child directories")

    source = tmp_path / "game.7z"
    subprocess.run(
        [str(package.tools / "7z.exe"), "a", "-t7z", "-mx=0", str(source), *children],
        cwd=game_tree, capture_output=True, check=True,
    )
    report = package.json("extract", "-r", "*", "-F", "-o", tmp_path / "out", source, timeout=None)
    assert report["summary"]["success_count"] == 1, report
    assert report["summary"]["processed_count"] == 1, report
