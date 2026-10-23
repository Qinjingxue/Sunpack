import asyncio
import io
from types import SimpleNamespace

import pytest

from sunpack.core.contracts.pipeline import PipelineTarget
from sunpack.core.contracts.results import ArchiveCleanupResult, DirectoryFlattenResult, OutcomeKind, TargetRunResult, RunSummary
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
    monkeypatch.setattr(module, "_native_flatten_single_branch_directories", lambda _path, _work=None: native_result)
    state = RunState()
    parent = TargetRunResult("outer.carrier", OutcomeKind.COMPLETE_SUCCESS, output_dir=root)
    nested = TargetRunResult("inner.disguised", OutcomeKind.COMPLETE_SUCCESS, output_dir=leaf + "/inner")
    unrelated = TargetRunResult("other", OutcomeKind.COMPLETE_SUCCESS, output_dir=str(tmp_path / "other"))
    for result in (parent, nested, unrelated):
        state.add_target_result(result)
    state.add_cleanup_result(ArchiveCleanupResult(leaf + "/inner.001", "recycle", "failed", message="locked"))
    runtime = object.__new__(_RequestRuntime)
    runtime.config = {"post_extract": {"archive_cleanup_mode": "keep"}}
    runtime.services = SimpleNamespace(output_ownership=SimpleNamespace(prepare_flatten=lambda *args: None), output_reservations=None)
    runtime.context = state
    runtime.submission = SimpleNamespace(request_id="request", stdout=io.StringIO(), targets=(PipelineTarget("outer.carrier"),))
    runtime.reporter = RunReporter(stdout=runtime.submission.stdout)
    runtime.reporter._top_level_outputs[root] = root
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
    assert state.target_results[2] is unrelated
    assert response.summary.success_count == 3
    assert response.artifacts.shell_refresh_paths[0] == actual
    assert list(runtime.reporter._top_level_outputs.values()) == [actual]
    assert len(response.summary.cleanup_results) == (1 if publish_succeeded else 2)
    if not publish_succeeded:
        warning = response.summary.cleanup_results[-1]
        assert (warning.mode, warning.status, warning.path) == ("flatten", "failed", work)
        assert warning.message == native_result["errors"][0]


def test_flatten_exception_is_a_postprocess_warning(tmp_path, monkeypatch):
    import sunpack.pipeline.postprocess.internal.flatten as module

    def fail(_base, _work=None):
        raise OSError("flatten unavailable")

    monkeypatch.setattr(module, "_native_flatten_single_branch_directories", fail)
    runtime = object.__new__(_RequestRuntime)
    runtime.config = {"post_extract": {"archive_cleanup_mode": "keep"}}
    runtime.services = SimpleNamespace(output_ownership=SimpleNamespace(prepare_flatten=lambda *args: None), output_reservations=None)
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


def test_nested_relocation_updates_replacements_and_collapsed_output_roots(tmp_path):
    # Single moves do not cover records that collapse onto the same root and
    # then move again, or a replacement result leaving its previous index slot.
    root = str(tmp_path / "out")
    inner = root + "/wrapper/inner"
    state = RunState()
    for path in (root, inner, inner + "/payload/child"):
        state.add_target_result(TargetRunResult(path + ".zip", OutcomeKind.COMPLETE_SUCCESS, output_dir=path))
    state.add_cleanup_result(ArchiveCleanupResult(inner + "/payload/source.001", "delete", "failed"))
    state.relocate_outputs(DirectoryFlattenResult(inner, inner, inner + "/payload", moved=1))
    child = state.target_results[-1]
    replacement = TargetRunResult(child.input_path, OutcomeKind.FAILURE, output_dir=child.output_dir, error="retained")
    state.replace_target_result(child, replacement)
    state.relocate_outputs(DirectoryFlattenResult(root, root, inner, moved=1))
    retained = root + ".work"
    state.relocate_outputs(DirectoryFlattenResult(root, retained, root))
    assert [item.output_dir.replace("\\", "/") for item in state.target_results] == [
        retained.replace("\\", "/"), retained.replace("\\", "/"), retained.replace("\\", "/") + "/child",
    ]
    assert state.target_results[-1].error == "retained"
    assert state.cleanup_results[0].path.replace("\\", "/") == retained.replace("\\", "/") + "/source.001"


def test_output_target_ownership_survives_junction_flatten_and_forget(tmp_path):
    """Cover alias lookup, nearest ownership and index retirement in one move.

    Existing relocation tests only inspect reported paths, so deleting this
    leaves target routing untested; a small directory rename is sufficient.
    """
    import subprocess
    from sunpack.pipeline.postprocess.internal.flatten import DirectoryFlattener

    first = tmp_path / "source-one"
    second = tmp_path / "source-two"
    physical = tmp_path / "published"
    for path in (first, second, physical):
        path.mkdir()
    alias = tmp_path / "alias"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(physical)],
                   check=True, capture_output=True)
    one, two = PipelineTarget(str(first)), PipelineTarget(str(second))
    ownership = _RequestResults(SimpleNamespace(targets=(two, one)), {})
    output = alias / "result"
    leaf = output / "wrapper" / "inner"
    child = leaf / "child"
    child.mkdir(parents=True)
    (leaf / "payload.txt").write_text("payload", encoding="utf-8")
    ownership.remember_results([
        TargetRunResult(str(first / "one.zip"), OutcomeKind.COMPLETE_SUCCESS, output_dir=str(output)),
        TargetRunResult(str(second / "two.zip"), OutcomeKind.COMPLETE_SUCCESS, output_dir=str(child)),
    ])
    assert ownership._target_for_path(str(physical / "result" / "wrapper" / "inner" / "child" / "new.zip")) is two
    flattened = DirectoryFlattener().flatten_dirs(str(output), announce=False)
    assert not flattened.errors
    ownership.relocate_outputs(flattened)
    assert ownership._target_for_path(str(physical / "result" / "new.zip")) is one
    assert ownership._target_for_path(str(physical / "result" / "child" / "new.zip")) is two
    ownership.forget_output(str(alias / "result" / "child"))
    assert ownership._target_for_path(str(physical / "result" / "child" / "new.zip")) is one


@pytest.mark.parametrize("quiet", [False, True])
def test_existing_final_report_shows_postprocess_warning_and_actual_output(quiet):
    stream = io.StringIO()
    errors = io.StringIO()
    reporter = RunReporter("zh", stdout=stream, stderr=errors, quiet=quiet)
    reporter._top_level_outputs["C:/output"] = "C:/output"
    reporter.relocate_outputs(DirectoryFlattenResult("C:/output", "C:/output.work", "C:/output"))
    reporter.log_final_summary(0, RunSummary(target_results=(TargetRunResult("archive", OutcomeKind.COMPLETE_SUCCESS),), cleanup_results=(
        ArchiveCleanupResult("C:/output.work", "flatten", "failed", message="publish failed"),
    )))
    assert "[后处理警告] 解压完成，1 项后处理操作失败" in errors.getvalue()
    assert "C:/output.work: publish failed" in errors.getvalue()
    if quiet:
        assert stream.getvalue() == ""
    else:
        assert "输出位置：C:/output.work" in stream.getvalue().replace("\\", "/")
