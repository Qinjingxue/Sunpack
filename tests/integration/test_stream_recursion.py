"""Compressed TAR inputs use two ordinary extraction rounds.

Report tests cannot catch a coordinator skipping the second round or a CLI
ignoring its recursion depth. These small real inputs cover those independent
boundaries for foreground and Watch; LZ4 is covered by test_lz4_pipeline.py.
"""
import asyncio
import json
import subprocess
import sys

import pytest

from sunpack.core.config.schema import normalize_config
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.real_archives import create_tar_archive


def make_input(tmp_path, fmt):
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "marker.txt").write_text("recursive TAR payload", encoding="utf-8")
    source = tmp_path / "input.photo"
    create_tar_archive(seed, source, fmt)
    return source


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("fmt", ["tar.gz", "tar.bz2", "tar.xz", "tar.zst"])
def test_stream_then_tar_uses_the_same_recursive_pipeline(tmp_path, origin, fmt):
    source = make_input(tmp_path, fmt)
    output = tmp_path / "out"
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "2", "cli": {"quiet": True},
        "output": {"root": str(output)},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(source)], origin=origin)

    response = asyncio.run(run())
    assert not response.summary.failed_tasks, response.summary.failures
    assert response.summary.success_count == 2, response.summary.target_results
    markers = list(output.rglob("marker.txt"))
    assert len(markers) == 1
    assert markers[0].read_text(encoding="utf-8") == "recursive TAR payload"
    assert source.exists()


@pytest.mark.parametrize("rounds", [1, 2])
def test_cli_recursion_depth_controls_when_the_inner_tar_is_extracted(tmp_path, repo_root, rounds):
    source = make_input(tmp_path, "tar.gz")
    output = tmp_path / "out"
    completed = subprocess.run([
        sys.executable, "-B", str(repo_root / "sunpack.py"), "extract", "--json",
        "--direct-file", "--out-dir", str(output), "--cleanup", "k",
        "--recur", str(rounds), str(source), "--no-pause",
    ], capture_output=True, text=True, encoding="utf-8",
        creationflags=subprocess.CREATE_NO_WINDOW)
    assert completed.returncode == 0, completed.stderr + completed.stdout
    response = json.loads(completed.stdout)
    assert response["summary"]["success_count"] == rounds, response
    assert bool(list(output.rglob("marker.txt"))) == (rounds == 2)
    assert source.exists()
