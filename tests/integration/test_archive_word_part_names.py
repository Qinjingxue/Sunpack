import asyncio
import subprocess
from pathlib import Path

import pytest

from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.detection_config import with_detection_pipeline


@pytest.mark.parametrize("origin", ["foreground", "watch"])
def test_independent_archives_with_part_inside_words_keep_distinct_names(tmp_path, origin):
    sevenzip = Path(__file__).resolve().parents[2] / "tools" / "7z.exe"
    payload = tmp_path / "payload.txt"
    payload.write_text("independent archive payload", encoding="utf-8")
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    names = ("Counterpart2.zip", "Counterpart3.zip", "Rampart1.rar", "Rampart2.rar")
    for name in names:
        # The .rar names deliberately disguise ZIP content.
        subprocess.run(
            [str(sevenzip), "a", "-tzip", str(inputs / name), str(payload)],
            check=True, capture_output=True,
        )
    config = normalize_config(with_detection_pipeline({
        "output": {"root": str(tmp_path / "out")},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(inputs)], origin=origin)

    response = asyncio.run(run())
    results = response.summary.target_results
    assert len(results) == len(names)
    assert {Path(result.input_path).name for result in results} == set(names)
    for result in results:
        assert result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
        output = Path(result.output_dir)
        assert output.name == Path(result.input_path).stem
        assert (output / payload.name).read_text(encoding="utf-8") == "independent archive payload"
