import asyncio
import os
import subprocess
from pathlib import Path

import pytest

from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.detection_config import with_detection_pipeline

PAYLOAD_MTIME_NS = 1578009600345678900


def _nested_fixture(tmp_path, encrypted):
    sevenzip = Path(__file__).resolve().parents[2] / "tools" / "7z.exe"
    fixture = tmp_path / "fixture"
    wrapper = fixture / "wrapper"
    wrapper.mkdir(parents=True)
    payload = tmp_path / "payload.txt"
    payload.write_text("nested payload", encoding="utf-8")
    os.utime(payload, ns=(PAYLOAD_MTIME_NS, PAYLOAD_MTIME_NS))
    os.chmod(payload, 0o444)
    inner = wrapper / "inner.7z"
    password_args = ["-punknown-fixture-password", "-mhe=on"] if encrypted else []
    subprocess.run(
        [str(sevenzip), "a", "-t7z", str(inner), str(payload), *password_args],
        check=True, capture_output=True,
    )
    os.chmod(payload, 0o666)
    os.chmod(inner, 0o444)
    outer = tmp_path / "outer.7z"
    subprocess.run(
        [str(sevenzip), "a", "-t7z", str(outer), "wrapper"],
        cwd=fixture, check=True, capture_output=True,
    )
    os.chmod(inner, 0o666)
    return outer


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("cleanup_mode", ["d", "k"])
def test_nested_failure_keeps_retry_path_while_success_still_flattens(tmp_path, origin, encrypted, cleanup_mode):
    outer = _nested_fixture(tmp_path, encrypted)
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "3",
        "user_passwords": ["wrong-fixture-password"],
        "builtin_passwords": [],
        "output": {"root": str(tmp_path / "out")},
        "post_extract": {"archive_cleanup_mode": cleanup_mode, "flatten_single_directory": True},
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
        assert Path(failed[0].input_path).stat().st_file_attributes & 1
        assert Path(failed[0].input_path) == tmp_path / "inner.7z"
        assert not (tmp_path / "out" / "outer" / "wrapper").exists()
        assert not (tmp_path / "out" / "outer").exists()
        assert outer_result.output_dir == ""
        assert outer.exists() == (cleanup_mode == "k"), "promoted failure must not alter outer cleanup"
    else:
        assert response.summary.failed_tasks == []
        assert response.summary.success_count == 2
        assert (output / "payload.txt").is_file()
        # Existing worker-only tests cannot catch metadata loss during recursive
        # cleanup/flatten in both origins; this adds one stat to the real fixture.
        assert (output / "payload.txt").stat().st_mtime_ns == PAYLOAD_MTIME_NS
        assert (output / "payload.txt").stat().st_file_attributes & 1
        assert not (output / "wrapper").exists()
        assert outer.exists() == (cleanup_mode == "k")


@pytest.mark.parametrize("cleanup_mode", ["d", "k"])
def test_cli_password_prompt_retries_promoted_input_with_real_pipeline(tmp_path, monkeypatch, cleanup_mode):
    from types import SimpleNamespace
    from sunpack.runtime.cli.cli_context import CliContext
    from sunpack.runtime.cli.cli_reporter import CliReporter
    from sunpack.runtime.cli.commands import extract

    outer = _nested_fixture(tmp_path, True)
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "3",
        "output": {"root": str(tmp_path / "out")},
        "post_extract": {"archive_cleanup_mode": cleanup_mode, "flatten_single_directory": True},
    }))
    requested = []

    class RecordingEngine(PipelineEngine):
        async def run(self, paths, **kwargs):
            requested.append(list(paths))
            return await super().run(paths, **kwargs)

    monkeypatch.setattr(extract, "load_request_config", lambda cwd: config)
    monkeypatch.setattr(extract, "pipeline_engine", RecordingEngine)
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda cfg: [])
    answers = iter(["y", "unknown-fixture-password", ""])
    ctx = CliContext(language="en", reporter=CliReporter(), cwd=str(tmp_path),
        input_reader=lambda prompt: next(answers))
    args = SimpleNamespace(
        paths=[str(outer)], password=["wrong-fixture-password"], password_file=None,
        prompt_passwords=False, no_builtin_passwords=True, recursive_extract=None,
        archive_cleanup_mode=None, flatten_single_directory=None,
        json=False, quiet=False, verbose=False, recursive=False,
    )
    code, result = asyncio.run(extract.handle(args, ctx))
    assert code == 0 and result.errors == []
    assert requested == [[str(outer)], [str(tmp_path / "inner.7z")]]
    assert result.summary["password_retry_count"] == 1
    payloads = list((tmp_path / "out").rglob("payload.txt"))
    assert len(payloads) == 1
    assert payloads[0].stat().st_mtime_ns == PAYLOAD_MTIME_NS
    assert payloads[0].stat().st_file_attributes & 1
    assert outer.exists() == (cleanup_mode == "k")
    assert not (tmp_path / "inner.7z").exists()
