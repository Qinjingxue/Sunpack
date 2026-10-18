"""Console progress regressions from a real Windows user report.

These exercise the production RunReporter and output streams rather than
mocking the renderer. The pipeline integration test exercises the native worker.
"""
import io
import os
import re
import sys
from types import SimpleNamespace

import pytest

import sunpack.pipeline.coordinator.reporting as reporting
from sunpack.pipeline.coordinator.reporting import RunReporter


def _task(path):
    return SimpleNamespace(main_path=str(path), logical_name=path.stem)


def _success(out_dir):
    return SimpleNamespace(
        success=True,
        result=SimpleNamespace(success=True, out_dir=str(out_dir), error=""),
        verification=SimpleNamespace(decision_hint="accept"),
    )


def test_semantic_events_do_not_reset_native_progress_or_finished_row(tmp_path, monkeypatch):
    stream = io.StringIO()
    stream.terminal_columns = 100
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: True)
    reporter = RunReporter("zh", stdout=stream)
    task = _task(tmp_path / "nested.zip")
    reporter.tasks_discovered(1, [task])
    reporter.task_status(task, "extracting")
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})
    row = reporter._task_rows[id(task)]
    assert row["progress"] == 0.5

    for event in ("extract_ready", "task_sources_claimed", "task_output_started"):
        reporter.task_progress(task, {"type": "semantic", "event": event})
    assert row["progress"] == 0.5
    assert row["state"] == "extracting"

    reporter.task_finished(task, _success(tmp_path / "out"), 1)
    rendered = stream.getvalue()
    reporter.task_progress(task, {"type": "semantic", "event": "task_output_finished"})
    assert row["state"] == "complete"
    assert row["progress"] == 1.0
    assert row["progress_known"] is True
    assert stream.getvalue() == rendered


def test_unknown_total_displays_indeterminate_once_without_zero_spam(tmp_path, monkeypatch):
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: False)
    out = io.StringIO()
    reporter = RunReporter("zh", stdout=out)
    task = _task(tmp_path / "unknown.zip")
    reporter.tasks_discovered(1, [task])
    for completed in (0, 10, 20):
        reporter.task_progress(task, {
            "type": "progress", "event": "progress",
            "completed_bytes": completed, "total_bytes": 0,
        })
    assert reporter._task_rows[id(task)]["progress_known"] is False
    assert out.getvalue().count(" --%") == 1
    assert "  0%" not in out.getvalue()

    reporter.task_progress(task, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})
    assert " 50%" in out.getvalue()
    reporter.task_finished(task, _success(tmp_path / "out"), 1)
    assert reporter._task_rows[id(task)]["progress_known"] is True


def test_noninteractive_stdout_never_emits_escape_codes(tmp_path):
    out = io.StringIO()
    reporter = RunReporter("zh", stdout=out)
    task = _task(tmp_path / "a.zip")
    reporter.tasks_discovered(1, [task])
    reporter.task_started(task, 1)
    reporter.task_progress(task, {"type": "progress", "completed_bytes": 25, "total_bytes": 100})
    reporter.task_finished(task, _success(tmp_path / "out"), 1)
    assert "\033[" not in out.getvalue()
    assert " 25%" in out.getvalue()
    assert "成功" in out.getvalue()


def test_interactive_panel_only_repaints_changed_row_for_many_tasks(tmp_path, monkeypatch):
    stream = io.StringIO()
    stream.terminal_columns = 110
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: True)
    reporter = RunReporter("zh", stdout=stream)
    tasks = [_task(tmp_path / f"item_{i:03d}.zip") for i in range(100)]
    reporter.tasks_discovered(1, tasks)
    assert stream.getvalue().count("等待队列") == 100
    stream.seek(0)
    stream.truncate(0)

    reporter.task_started(tasks[50], 1)
    rendered = stream.getvalue()
    assert rendered.count("\033[2K") == 1
    assert "\033[50A" in rendered and "\033[50B" in rendered
    assert "item_050.zip" in rendered
    assert "item_049.zip" not in rendered

    stream.seek(0)
    stream.truncate(0)
    reporter.task_finished(tasks[50], _success(tmp_path / "out"), 1)
    assert stream.getvalue().count("\033[2K") == 1
    assert "完成" in stream.getvalue()


def test_console_row_reserves_a_column_to_avoid_unexpected_wrap(tmp_path, monkeypatch):
    stream = io.StringIO()
    stream.terminal_columns = 56
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: True)
    reporter = RunReporter("zh", stdout=stream)
    task = _task(tmp_path / ("很长的嵌套归档名称" * 5 + ".zip"))
    reporter.tasks_discovered(1, [task])
    row = reporter._format_task_row(reporter._task_rows[id(task)])
    plain = re.sub(r"\033\[[0-9;]*m", "", row)
    assert reporting._display_width(plain) < stream.terminal_columns


@pytest.mark.skipif(sys.platform != "win32", reason="requires real Windows console handles")
def test_windows_pipe_handle_is_not_mistaken_for_vt_console():
    reader, writer = os.pipe()
    try:
        class RedirectedOutput:
            def isatty(self):
                return True

            def fileno(self):
                return writer

        assert reporting._terminal_supports_updates(RedirectedOutput()) is False
    finally:
        os.close(reader)
        os.close(writer)
