import asyncio
import subprocess
from pathlib import Path

import pytest

from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.detection_config import with_detection_pipeline


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("encrypted", [False, True])
def test_nested_failure_keeps_retry_path_while_success_still_flattens(tmp_path, origin, encrypted):
    sevenzip = Path(__file__).resolve().parents[2] / "tools" / "7z.exe"
    fixture = tmp_path / "fixture"
    wrapper = fixture / "wrapper"
    wrapper.mkdir(parents=True)
    payload = tmp_path / "payload.txt"
    payload.write_text("nested payload", encoding="utf-8")
    inner = wrapper / "inner.7z"
    password_args = ["-punknown-fixture-password", "-mhe=on"] if encrypted else []
    subprocess.run(
        [str(sevenzip), "a", "-t7z", str(inner), str(payload), *password_args],
        check=True, capture_output=True,
    )
    outer = tmp_path / "outer.7z"
    subprocess.run(
        [str(sevenzip), "a", "-t7z", str(outer), "wrapper"],
        cwd=fixture, check=True, capture_output=True,
    )
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "3",
        "user_passwords": ["wrong-fixture-password"],
        "builtin_passwords": [],
        "output": {"root": str(tmp_path / "out")},
        "post_extract": {"archive_cleanup_mode": "d", "flatten_single_directory": True},
    }))

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(outer)], origin=origin)

    response = asyncio.run(run())
    results = response.summary.target_results
    outer_result = next(result for result in results if result.input_path == str(outer))
    output = Path(outer_result.output_dir)
    assert outer_result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
    if encrypted:
        failed = [result for result in results if result.outcome_kind == OutcomeKind.FAILURE]
        assert len(failed) == 1
        assert failed[0].failure.is_password_failure
        assert Path(failed[0].input_path).is_file()
        assert Path(failed[0].input_path).parent.name == "wrapper"
        assert (output / "wrapper").is_dir()
    else:
        assert response.summary.failed_tasks == []
        assert response.summary.success_count == 2
        assert (output / "payload.txt").is_file()
        assert not (output / "wrapper").exists()
