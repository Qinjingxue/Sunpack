import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.scenarios.extraction_large_archive import (
    RequestRuntimeProfiler,
    _derived_timing,
    _cleanup_generated_output,
    _generated_output_path,
    _run_profile_once,
)


def test_request_profiler_hooks_current_per_request_runtime_factory(monkeypatch):
    runtime = object()
    runner = SimpleNamespace(_request_runtime_factory=lambda: runtime)
    profiler = RequestRuntimeProfiler()
    instrumented = []
    monkeypatch.setattr(
        profiler,
        "_instrument_runtime",
        lambda current, timings: instrumented.append((current, timings)),
    )

    profiler.install(runner)
    profiler.enabled = True
    try:
        assert runner._request_runtime_factory() is runtime
        assert instrumented[0][0] is runtime
        assert len(profiler.request_timings) == 1
        assert profiler.request_timings[0]["pipeline_runtime_create"]
    finally:
        profiler.restore()


def test_cleanup_generated_output_removes_only_profile_tree(tmp_path: Path):
    output_base = tmp_path / "profile"
    output = _generated_output_path(output_base, "run", 3)
    output.mkdir()
    (output / "payload.bin").write_bytes(b"payload")

    _cleanup_generated_output(output, output_base)

    assert not output.exists()
    with pytest.raises(ValueError, match="non-generated output"):
        _cleanup_generated_output(tmp_path / "unrelated", output_base)


def test_profile_run_cleans_output_when_pipeline_fails(tmp_path: Path):
    output_base = tmp_path / "profile"
    output = _generated_output_path(output_base, "run", 0)
    config = {"output": {"root": str(output_base)}}

    async def run(*_args, **_kwargs):
        output.mkdir(parents=True)
        (output / "partial.bin").write_bytes(b"partial")
        raise RuntimeError("pipeline failed")

    runner = SimpleNamespace(run=run)

    with pytest.raises(RuntimeError, match="pipeline failed"):
        asyncio.run(
            _run_profile_once(
                runner,
                str(tmp_path / "archive.rar"),
                output,
                output_base,
                config,
                keep_output=False,
            )
        )

    assert not output.exists()


def test_worker_wait_residual_excludes_protocol_processing():
    derived = _derived_timing({
        "sevenzip_worker": [1.0],
        "worker_protocol_json_decode": [0.1],
        "worker_protocol_drain_stderr": [0.02],
        "worker_protocol_emit_progress": [0.03],
    })

    assert derived["worker_wait_residual"] == pytest.approx(0.85)


def test_pipeline_derived_timings_remove_nested_batch_and_planning_costs():
    derived = _derived_timing({
        "pipeline_run": [1.0],
        "pipeline_runtime_create": [0.2],
        "pipeline_runtime_execute": [0.77],
        "batch_execute": [0.6],
        "pipeline_plan_task_isolated": [0.1],
        "planning_signature_prepass": [0.08],
        "pipeline_direct_scan": [0.02],
        "pipeline_nested_authorize": [0.02],
        "output_take_scan_session": [0.01],
        "pipeline_final_report": [0.01],
        "extractor_close": [0.01],
    })

    assert derived["pipeline_run_outside_batch"] == pytest.approx(0.4)
    assert derived["pipeline_runtime_outside_batch"] == pytest.approx(0.17)
    assert derived["pipeline_plan_task_unattributed"] == pytest.approx(0.02)
    assert derived["pipeline_runtime_outside_batch_residual"] == pytest.approx(0.0)
    assert derived["pipeline_run_outer_residual"] == pytest.approx(0.03)
