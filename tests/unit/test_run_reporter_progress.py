import io
import re
from types import SimpleNamespace

import pytest

import sunpack.pipeline.coordinator.reporting as reporting
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.results import RunSummary, TargetRunResult, OutcomeKind
from sunpack.pipeline.coordinator.reporting import RunReporter
from sunpack.core.support.filesystem_scan_errors import filesystem_scan_failure


def _task(path):
    return SimpleNamespace(main_path=str(path), logical_name=path.stem)


def _outcome(out_dir, *, success=True, partial=False, error=""):
    return SimpleNamespace(
        success=success,
        result=SimpleNamespace(success=success, out_dir=str(out_dir), error=error),
        verification=SimpleNamespace(decision_hint="accept_partial" if partial else "accept"),
    )


def test_progress_displays_nested_archive_parent_chain_and_final_page(tmp_path, capsys):
    reporter = RunReporter("zh")
    outer = _task(tmp_path / "outer.zip")
    outer_output = tmp_path / "outer"

    reporter.scan_started(1)
    reporter.tasks_discovered(1, [outer])
    reporter.task_started(outer, 1)
    reporter.task_finished(outer, _outcome(outer_output), 1)

    inner = _task(outer_output / "folder" / "inner.7z")
    inner_output = outer_output / "folder" / "inner"
    reporter.tasks_discovered(2, [inner])
    reporter.task_started(inner, 2)
    reporter.task_finished(inner, _outcome(inner_output), 2)
    reporter.log_final_summary(0, RunSummary(target_results=(
        TargetRunResult(str(outer.main_path), OutcomeKind.COMPLETE_SUCCESS),
        TargetRunResult(str(inner.main_path), OutcomeKind.COMPLETE_SUCCESS),
    )))

    output = capsys.readouterr().out
    assert "[扫描中] 正在查找压缩包…" in output
    assert "[扫描完成] 发现 1 个待处理压缩包" in output
    assert "[递归扫描] 第 2 层发现 1 个嵌套压缩包" in output
    assert "+- [成功 2/2] inner.7z（来自 outer.zip）" in output
    assert "完整成功：2  部分恢复：0  解压失败：0  扫描错误：0" in output
    assert "递归层级：2 层，处理嵌套包：1 个" in output
    assert f"输出位置：{outer_output}" in output


def test_progress_displays_full_lineage_for_deep_recursion(tmp_path, capsys):
    reporter = RunReporter("zh")
    paths = [
        (tmp_path / "outer.zip", tmp_path / "outer"),
        (tmp_path / "outer" / "inner.rar", tmp_path / "outer" / "inner"),
        (tmp_path / "outer" / "inner" / "data.7z", tmp_path / "outer" / "inner" / "data"),
    ]

    for depth, (archive, output_dir) in enumerate(paths, start=1):
        task = _task(archive)
        reporter.tasks_discovered(depth, [task])
        reporter.task_finished(task, _outcome(output_dir), depth)

    output = capsys.readouterr().out
    assert "data.7z（来自 outer.zip > inner.rar）" in output


def test_partial_recovery_prints_possible_missing_volume_warning(tmp_path, capsys):
    warning = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction_report",
        "压缩包内容不完整；可能缺少一个或多个分卷",
        details={"missing_volume_confirmed": False, "partial_recovery": True},
    )

    RunReporter("zh").log_final_summary(
        0,
        RunSummary(target_results=(TargetRunResult(str(tmp_path / "sample.zip.001"), OutcomeKind.PARTIAL_SUCCESS, recovery={
            "archive": str(tmp_path / "sample.zip.001"),
            "completeness": 0.75,
            "warning": warning.to_dict(),
        }),)),
    )

    output = capsys.readouterr().out
    assert "[部分恢复] sample.zip.001" in output
    assert "[警告] 压缩包内容不完整；可能缺少一个或多个分卷" in output


@pytest.mark.parametrize("language", ["zh", "en"])
@pytest.mark.parametrize("quiet, emit_errors", [(False, True), (True, True), (True, False)])
def test_final_summary_distinguishes_scan_and_archive_errors(tmp_path, language, quiet, emit_errors):
    # Separately covers mixed error presentation and overflow counts. Native
    # scan tests alone cannot expose quiet swallowing archive failure messages.
    output, errors = io.StringIO(), io.StringIO()
    path = tmp_path / "broken.7z"
    failure = FailureInfo(
        FailureKind.DAMAGED,
        "embedded_boundary",
        "Embedded archive is truncated before its terminal boundary",
        message_key="failure.damaged",
        details={"path": str(path)},
    )
    scan_failures = [filesystem_scan_failure(error, language) for error in (
        ("read_dir", str(tmp_path / "blocked"), "access denied"),
        ("omitted", str(tmp_path), "4"),
    )]
    # Classification must survive a processing error sharing the scan text.
    from dataclasses import replace
    failure = replace(failure, message=scan_failures[0].message)

    RunReporter(language, quiet=quiet, emit_errors=emit_errors, stdout=output, stderr=errors).log_final_summary(
        0,
        RunSummary(scan_failures=(failure, *scan_failures)),
    )

    labels = ("[解压失败]", "[扫描错误]", "[扫描不完整]", "压缩包损坏", "解压失败：1  扫描错误：5") if language == "zh" else (
        "[Extraction failed]", "[Scan error]", "[Scan incomplete]", "Archive is damaged", "Extraction failed: 1  Scan errors: 5",
    )
    if emit_errors:
        assert f"{path}: {labels[3]}" in errors.getvalue()
        assert errors.getvalue().count(labels[0]) == 1
        assert errors.getvalue().count(labels[1]) == 2
        assert labels[2] in errors.getvalue()
    else:
        assert errors.getvalue() == ""
    if quiet:
        assert output.getvalue() == ""
    else:
        assert labels[4] in output.getvalue()
        assert all(label not in output.getvalue() for label in labels[:3])


def test_interactive_panel_updates_fixed_row_with_progress_and_colors(tmp_path, monkeypatch):
    stream = io.StringIO()
    stream.terminal_columns = 72
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: True)
    monkeypatch.setattr(reporting.sys, "stdout", stream)
    reporter = RunReporter("zh")
    task = _task(tmp_path / "large.7z")

    reporter.tasks_discovered(1, [task])
    reporter.task_started(task, 1)
    reporter._last_render_at = 0.0
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})
    reporter.task_status(task, "extracting")
    reporter.task_finished(task, _outcome(tmp_path / "large"), 1)

    output = stream.getvalue()
    assert "等待队列" in output
    assert "50%" in output
    assert "正在解压" in output
    assert "\033[32m" in output and "完成" in output
    assert "\033[1A" in output
    row = reporter._format_task_row(reporter._task_rows[id(task)])
    plain_row = re.sub(r"\033\[[0-9;]*m", "", row)
    assert reporting._display_width(plain_row) <= stream.terminal_columns


def test_interactive_row_accounts_for_wide_status_and_archive_characters(tmp_path, monkeypatch):
    stream = io.StringIO()
    stream.terminal_columns = 80
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: True)
    reporter = RunReporter("zh", stdout=stream)
    task = _task(tmp_path / ("很长的嵌套压缩包名称" * 8 + ".zip"))

    reporter.tasks_discovered(2, [task])
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})

    row = reporter._format_task_row(reporter._task_rows[id(task)])
    plain_row = re.sub(r"\033\[[0-9;]*m", "", row)
    assert reporting._display_width(plain_row) <= stream.terminal_columns
    assert plain_row.endswith("…")


def test_forwarded_terminal_capability_does_not_require_server_console():
    stream = io.StringIO()
    stream.isatty = lambda: True
    stream.supports_terminal_updates = True

    assert reporting._terminal_supports_updates(stream)


def test_noninteractive_terminal_streams_throttled_progress_bar(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: False)
    reporter = RunReporter("zh")
    task = _task(tmp_path / "large.7z")

    reporter.tasks_discovered(1, [task])
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 5, "total_bytes": 100})
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 9, "total_bytes": 100})
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})

    output = capsys.readouterr().out
    assert output.count("正在解压") == 2
    assert "  5%" in output
    assert " 50%" in output
