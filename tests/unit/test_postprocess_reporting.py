import asyncio
import io
from types import SimpleNamespace

import pytest

from sunpack.core.contracts.pipeline import PipelineTarget
from sunpack.core.contracts.results import ArchiveCleanupResult, DirectoryFlattenResult, OutcomeKind, TargetRunResult
from sunpack.core.contracts.run_state import RunState
from sunpack.pipeline.coordinator.engine import _RequestResults, _RequestRuntime
from sunpack.pipeline.coordinator.reporting import RunReporter
from sunpack.pipeline.postprocess.actions import PostProcessActions
from tests.helpers.fake_pipeline_engine import _InlineBroker


@pytest.mark.parametrize("publish_succeeded", [True, False])
def test_flatten_relocates_nested_outputs_and_reports_retained_work(tmp_path, monkeypatch, publish_succeeded):
    import sunpack.pipeline.postprocess.internal.flatten as module

    root = str(tmp_path / "output")
    leaf = str(tmp_path / "output" / "wrapper" / "payload")
    work = str(tmp_path / "output.__sunpack_flatten_work__")
    actual = root if publish_succeeded else work
    native_result = {
        "moved": int(publish_succeeded), "removed_dirs": 2 if publish_succeeded else 0,
        "source_dir": leaf if publish_succeeded else root,
        "output_dir": actual,
        "errors": [] if publish_succeeded else ["cannot publish flattened directory"],
    }
    monkeypatch.setattr(module, "_native_flatten_single_branch_directories", lambda _path: native_result)
    state = RunState()
    parent = TargetRunResult("outer.carrier", OutcomeKind.COMPLETE_SUCCESS, output_dir=root)
    nested = TargetRunResult("inner.disguised", OutcomeKind.COMPLETE_SUCCESS, output_dir=leaf + "/inner")
    unrelated = TargetRunResult("other", OutcomeKind.COMPLETE_SUCCESS, output_dir=str(tmp_path / "other"))
    state.target_results = [parent, nested, unrelated]
    state.cleanup_results = [ArchiveCleanupResult(leaf + "/inner.001", "recycle", "failed", message="locked")]
    runtime = object.__new__(_RequestRuntime)
    runtime.config = {"post_extract": {"archive_cleanup_mode": "keep"}}
    runtime.context = state
    runtime.submission = SimpleNamespace(request_id="request", stdout=io.StringIO(), targets=(PipelineTarget("outer.carrier"),))
    runtime.reporter = RunReporter(stdout=runtime.submission.stdout)
    runtime.reporter._top_level_outputs = [root]
    ownership = _RequestResults(runtime.submission, runtime.config)
    ownership.remember_results(state.target_results)

    flattened = asyncio.run(runtime._flatten_output(
        SimpleNamespace(key="task", main_path="outer.carrier"), root,
        broker=_InlineBroker(), cancellation=None,
    ))
    ownership.relocate_outputs(flattened)
    response = ownership.response(state, recent_passwords=[])
    expected_nested = root + "/inner" if publish_succeeded else work + "/wrapper/payload/inner"
    assert state.target_results[0].output_dir == actual
    assert state.target_results[1].output_dir.replace("\\", "/") == expected_nested.replace("\\", "/")
    assert state.target_results[2] == unrelated
    assert response.summary.success_count == 3
    assert response.artifacts.shell_refresh_paths[0] == actual
    assert runtime.reporter._top_level_outputs == [actual]
    assert len(response.summary.cleanup_results) == (1 if publish_succeeded else 2)
    if not publish_succeeded:
        warning = response.summary.cleanup_results[-1]
        assert (warning.mode, warning.status, warning.path) == ("flatten", "failed", work)
        assert warning.message == native_result["errors"][0]


def test_flatten_exception_is_a_postprocess_warning(tmp_path, monkeypatch):
    import sunpack.pipeline.postprocess.internal.flatten as module

    def fail(_base):
        raise OSError("flatten unavailable")

    monkeypatch.setattr(module, "_native_flatten_single_branch_directories", fail)
    runtime = object.__new__(_RequestRuntime)
    runtime.config = {"post_extract": {"archive_cleanup_mode": "keep"}}
    runtime.context = RunState()
    runtime.submission = SimpleNamespace(request_id="request", stdout=io.StringIO())
    runtime.reporter = RunReporter(stdout=runtime.submission.stdout)
    result = asyncio.run(runtime._flatten_output(
        SimpleNamespace(key="task", main_path="source"), str(tmp_path),
        broker=_InlineBroker(), cancellation=None,
    ))
    assert result.errors == ("flatten unavailable",)
    assert runtime.context.cleanup_results[0].mode == "flatten"


def test_postprocess_actions_returns_flatten_warning_in_existing_cleanup_results(tmp_path, monkeypatch):
    from sunpack.pipeline.postprocess.internal.flatten import DirectoryFlattener

    monkeypatch.setattr(DirectoryFlattener, "flatten_dirs", lambda self, base, **kwargs:
        DirectoryFlattenResult(base, base + ".work", errors=("publish failed",)))
    results = PostProcessActions({"post_extract": {"archive_cleanup_mode": "keep"}}).apply(
        cleanup_archives=False, flatten_targets=[str(tmp_path)],
    )
    assert results == [ArchiveCleanupResult(str(tmp_path) + ".work", "flatten", "failed", message="publish failed")]


def test_flatten_projection_handles_removed_wrappers_and_other_drives():
    result = DirectoryFlattenResult("C:/output", "C:/output", "C:/output/outer/inner", moved=1)
    assert result.relocate("C:/output/outer") == "C:/output"
    assert result.relocate("D:/other") == "D:/other"
    assert result.relocate("C:/output-sibling") == "C:/output-sibling"


def test_existing_final_report_shows_postprocess_warning_and_actual_output():
    stream = io.StringIO()
    reporter = RunReporter("zh", stdout=stream)
    reporter._top_level_outputs = ["C:/output"]
    reporter.relocate_outputs(DirectoryFlattenResult("C:/output", "C:/output.work", "C:/output"))
    reporter.log_final_summary(0, 1, [], cleanup_results=[
        ArchiveCleanupResult("C:/output.work", "flatten", "failed", message="publish failed"),
    ])
    assert "1 项后处理操作失败" in stream.getvalue()
    assert "输出位置：C:/output.work" in stream.getvalue().replace("\\", "/")
    assert "C:/output.work: publish failed" in stream.getvalue()
