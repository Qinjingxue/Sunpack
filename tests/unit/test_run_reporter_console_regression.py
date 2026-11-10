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
from sunpack.core.contracts.results import OutcomeKind


def _success(out_dir):
    return SimpleNamespace(
        outcome_kind=OutcomeKind.COMPLETE_SUCCESS,
        result=SimpleNamespace(success=True, out_dir=str(out_dir), error=""),
        verification=SimpleNamespace(decision_hint="accept"),
    )


def _screen(text):
    """Decode the panel's VT subset independently of its frame cache."""
    lines, row, column = {}, 0, 0
    for token in re.findall(r"\033\[\d*[ABJK]|\r|\n|[^\033\r\n]+", text):
        if token.startswith("\033["):
            count = int(token[2:-1] or "1")
            if token[-1] == "A":
                row = max(0, row - count)
            elif token[-1] == "B":
                row += count
            elif token[-1] == "J":
                lines = {i: value for i, value in lines.items() if i < row}
            else:
                assert token == "\033[2K"
                lines[row] = ""
        elif token == "\r":
            column = 0
        elif token == "\n":
            row, column = row + 1, 0
        else:
            old = lines.get(row, "")
            lines[row] = old[:column] + token + old[column + len(token):]
            column += len(token)
    return [lines.get(i, "") for i in range(row + 1)], column


def test_incremental_panel_preserves_cursor_rows_and_completed_history(tmp_path):
    # Raw-text checks cannot detect stale suffixes or cursor drift after an
    # unchanged tail. Decode repeated lifecycle/progress updates and scope flush.
    from tests.helpers.archive_tasks import make_archive_task

    stream = io.StringIO()
    stream.isatty = lambda: True
    stream.supports_terminal_updates = True
    stream.terminal_size = os.terminal_size((100, 10))
    reporter = RunReporter("en", stdout=stream)
    tasks = [make_archive_task(tmp_path / f"item_{i}.zip") for i in range(2)]
    reporter.tasks_discovered(1, tasks)

    def check(history=()):
        expected = list(history) + list(reporter._scope_lines(reporter._scope_roots, columns=100)) + [""]
        assert _screen(stream.getvalue()) == (expected, 0)

    check()
    before = len(stream.getvalue())
    reporter.task_started(tasks[0])
    patch = stream.getvalue()[before:]
    assert patch.count("\033[2K") == 1 and "item_1.zip" not in patch
    check()
    before = stream.getvalue()
    reporter.task_status(tasks[0], "preparing")
    assert stream.getvalue() == before
    for event in ({"event": "space_blocked"}, {"event": "space_resumed"},
                  {"type": "progress", "completed_bytes": 50, "total_bytes": 100}):
        reporter._last_render_at = 0
        reporter.task_progress(tasks[0], event)
        check()
    reporter.task_finished(tasks[0], _success(tmp_path / "out"), 1)
    check()
    history = list(reporter._scope_lines((reporter._row_key(tasks[0]),)))
    reporter.scope_finished(tasks[0])
    check(history)
    reporter.pause_panel()
    assert _screen(stream.getvalue()) == (history + [""], 0)
    reporter.task_status(tasks[1], "extracting")
    reporter.resume_panel()
    check(history)
    reporter._print("a log message")
    check([*history, "a log message"])


@pytest.mark.parametrize("action", ["refresh", "pause", "log", "finish", "write_error", "flush_error"])
def test_panel_reanchors_after_resize_or_uncertain_output(tmp_path, action):
    # A resized or partly accepted frame has no trustworthy cursor origin.
    # Clearing by its former logical height can erase completed output above it.
    from tests.helpers.archive_tasks import make_archive_task

    class Output(io.StringIO):
        terminal_size = os.terminal_size((100, 10))
        supports_terminal_updates = True
        failure = ""

        def isatty(self):
            return True

        def write(self, text):
            if self.failure == "write_error":
                self.failure = ""
                super().write(text[:6])
                raise BlockingIOError("partially accepted frame")
            return super().write(text)

        def flush(self):
            if self.failure == "flush_error":
                self.failure = ""
                raise BlockingIOError("uncertain flush")

    stream = Output()
    reporter = RunReporter("en", stdout=stream)
    tasks = [make_archive_task(tmp_path / f"item_{i}.zip") for i in range(2)]
    reporter.tasks_discovered(1, tasks)
    if action.endswith("error"):
        stream.failure = action
        with pytest.raises(BlockingIOError):
            reporter.task_started(tasks[0])
    else:
        stream.terminal_size = os.terminal_size((30, 4))
    before = len(stream.getvalue())
    if action == "pause":
        reporter.pause_panel()
        reporter.resume_panel()
    elif action == "log":
        reporter._print("preserve this log")
    elif action == "finish":
        reporter.scope_finished(tasks[0])
    else:
        reporter.task_status(tasks[0], "extracting")
    patch = stream.getvalue()[before:]
    anchor = "\x18\r\n" if action.endswith("error") else "\r\n"
    assert patch.startswith(anchor) and not re.search(r"\033\[\d+A", patch)
    assert reporter._rendered_lines < stream.terminal_size.lines


def test_scope_tree_keeps_segments_and_recursive_output_with_bounded_terminal(tmp_path, monkeypatch):
    # One tree checks routing, stable grouping, no task retention, and viewport
    # bounds; former flat-row tests could not detect cross-segment updates.
    import weakref
    import gc
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
    from sunpack.core.contracts.input_plan import LogicalArchiveInput
    from sunpack.core.contracts.tasks import ArchiveTask
    from tests.helpers.archive_tasks import make_archive_task

    for interactive in (False, True):
        monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: interactive)
        stream = io.StringIO()
        stream.terminal_size = os.terminal_size((68, 5))
        reporter = RunReporter("zh", stdout=stream)
        nodes = tuple(LogicalArchiveInput(ArchiveInputDescriptor(
            str(tmp_path / "carrier.bin"), open_mode="file_range", format_hint="zip",
            parts=[ArchiveInputPart(InputExtent(str(tmp_path / "carrier.bin"), start, start + 40))],
        ), position=i) for i, start in enumerate((32, 128), 1))
        outer = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="embedded", logical_inputs=nodes)
        other = make_archive_task(tmp_path / "other.zip")
        reporter.tasks_discovered(1, [outer, other])
        reporter.task_started(outer)
        reporter.task_started(other)
        before_detail = stream.getvalue()
        reporter.task_progress(outer, {"event": "task_detail", "detail": "invisible in normal mode"})
        assert stream.getvalue() == before_detail
        for node in nodes:
            child = ArchiveTask.from_archive_input(node.descriptor, discovery_source="embedded", logical_inputs=(node,))
            child.key = node.input_id
            child.runtime = dict(outer.runtime)
            reporter.task_progress(child, {"type": "progress", "completed_bytes": node.position, "total_bytes": 10})
            assert reporter._task_rows[reporter._row_key(child)]["progress"] == node.position / 10
            reporter.task_progress(child, {"type": "semantic", "event": "input_finished", "success": True,
                                           "out_dir": str(tmp_path / "out" / str(node.position))})
        reporter.task_finished(outer, _success(tmp_path / "out"), 1)
        nested = make_archive_task(tmp_path / "out" / "2" / "nested.zip")
        reporter.tasks_discovered(2, [nested])
        reporter.task_started(nested)
        reporter.task_finished(nested, _success(tmp_path / "out" / "2" / "nested"), 2)
        ref = weakref.ref(nested)
        del nested, child
        gc.collect()
        assert ref() is None
        if interactive:
            assert reporter._rendered_lines < stream.terminal_size.lines
            for line in stream.getvalue().splitlines():
                plain = re.sub(r"\033\[[0-9;]*[A-Za-z]", "", line).replace("\r", "")
                assert reporting._display_width(plain) < stream.terminal_size.columns
        else:
            assert stream.getvalue() == ""
        stream.seek(0); stream.truncate(0)
        reporter.pause_panel()
        paused = stream.getvalue()
        reporter.scope_finished(outer)
        assert stream.getvalue() == paused and reporter._row_key(outer) in reporter._task_rows
        reporter.resume_panel()
        text = stream.getvalue()
        assert text.index("段 1") < text.index("段 2") < text.index("nested.zip")
        assert "   └─ nested.zip" in text.splitlines()
        assert text.count("[完成] [####################] 100%") == 3
        assert "│" in text and "└─" in text
        assert reporter._row_key(outer) not in reporter._task_rows
        if not interactive:
            assert "other.zip" not in text and "\033[" not in text
        reporter.task_finished(other, _success(tmp_path / "other"), 1)
        reporter.task_progress(other, {"event": "memory_blocked"})
        assert reporter._task_rows[reporter._row_key(other)]["state"] == "complete"
        reporter.scope_finished(other)
        assert not reporter._task_rows and not reporter._output_rows

        from dataclasses import replace
        from sunpack.core.contracts.failures import FailureInfo, FailureKind, aggregate_input_failures
        blocked_nodes = tuple(replace(node,
            descriptor=node.descriptor.with_path_mapping(lambda path: path.replace("carrier.bin", "blocked.bin")),
            input_id="", failure=FailureInfo(FailureKind.DAMAGED, "embedded", f"segment {node.position} damaged"),
        ) for node in nodes)
        blocked = ArchiveTask.from_archive_input(blocked_nodes[0].descriptor,
                    discovery_source="embedded", logical_inputs=blocked_nodes)
        reporter.tasks_discovered(1, [blocked])
        reporter.task_started(blocked)
        failure = aggregate_input_failures(
            [node.failure for node in blocked_nodes], segment_count=len(blocked_nodes), i18n=reporter.i18n,
        )
        reporter.task_finished(blocked, SimpleNamespace(outcome_kind=OutcomeKind.FAILURE,
                               result=SimpleNamespace(error=failure.message, out_dir="", failure=failure)), 1)
        stream.seek(0); stream.truncate(0)
        reporter.scope_finished(blocked)
        assert "segment 1 damaged" in stream.getvalue() and "segment 2 damaged" in stream.getvalue()
        assert failure.message not in stream.getvalue()
        assert not reporter._task_rows

        reporter.tasks_discovered(1, [outer])
        reporter.task_started(outer)
        reporter.task_finished(outer, SimpleNamespace(outcome_kind=OutcomeKind.FAILURE,
                               result=SimpleNamespace(error="access denied", out_dir="")), 1)
        stream.seek(0); stream.truncate(0)
        reporter.scope_finished(outer)
        assert "access denied" in stream.getvalue()
        assert stream.getvalue().count("[跳过]") == 2
        assert "等待队列" not in stream.getvalue()


@pytest.mark.parametrize("complete_positions", [(1,), (1, 3)])
def test_retry_tree_keeps_retained_siblings_and_selected_input_updates(tmp_path, complete_positions):
    # The normal tree test has no recovery checkpoints. This covers a retry
    # selecting one or several inputs without hiding failed/complete siblings,
    # resurrecting selected inputs' stale errors, or losing output ownership.
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
    from sunpack.core.contracts.input_plan import InputCheckpoint, InputRecovery, LogicalArchiveInput
    from sunpack.core.contracts.tasks import ArchiveTask
    from sunpack.core.contracts.failures import FailureInfo, FailureKind, aggregate_input_failures
    from sunpack.core.contracts.extraction import ExtractionResult, InputExecutionResult
    from sunpack.core.support.path_keys import path_key
    from tests.helpers.archive_tasks import make_archive_task

    carrier = str(tmp_path / "carrier.bin")
    nodes = tuple(LogicalArchiveInput(ArchiveInputDescriptor(
        carrier, open_mode="file_range", format_hint="zip",
        parts=[ArchiveInputPart(InputExtent(carrier, i * 100, i * 100 + 40))],
    ), position=i) for i in range(1, 5))
    missing = FailureInfo(FailureKind.MISSING_VOLUME, "extraction", "retained segment needs volume")
    password = FailureInfo(FailureKind.WRONG_PASSWORD, "extraction", "old password failure")
    generation = ((path_key(carrier), 1, 1000),)
    output = str(tmp_path / "out")
    task = ArchiveTask.from_archive_input(nodes[0].descriptor, discovery_source="embedded", logical_inputs=nodes)
    recovery = InputRecovery(tuple(InputCheckpoint(
        node, generation, str(tmp_path / "out" / str(node.position)),
        complete=node.position in complete_positions,
        failure=None if node.position in complete_positions else missing if node.position == 2 else password,
    ) for node in nodes), output, len(nodes))
    selected, task.recovery = recovery.select(nodes, generation, password_changed=True)
    assert tuple(node.position for node in selected) == ((3, 4) if complete_positions == (1,) else (4,))

    stream = io.StringIO()
    reporter = RunReporter("en", stdout=stream)
    reporter.tasks_discovered(1, [task])
    reporter.task_started(task)
    task.set_inputs(selected)
    reporter.task_replanned(task)
    for node in selected:
        child = ArchiveTask.from_archive_input(node.descriptor, discovery_source="embedded", logical_inputs=(node,))
        child.key = node.input_id
        child.runtime = dict(task.runtime)
        reporter.task_progress(child, {"event": "input_started"})
        reporter.task_progress(child, {"event": "input_finished", "success": True,
                                      "out_dir": str(tmp_path / "out" / str(node.position))})
    failure = aggregate_input_failures([missing], segment_count=len(nodes), i18n=reporter.i18n)
    reporter.task_finished(task, SimpleNamespace(outcome_kind=OutcomeKind.FAILURE,
        result=SimpleNamespace(error=failure.message, out_dir=output, failure=failure, has_retained_outputs=True,
            input_results=[InputExecutionResult(node, ExtractionResult(True,
                str(tmp_path / "out" / str(node.position)))) for node in selected])), 1)
    nested = make_archive_task(tmp_path / "out" / "1" / "nested.zip")
    reporter.tasks_discovered(2, [nested])
    reporter.task_finished(nested, _success(tmp_path / "out" / "1" / "nested"), 2)
    reporter.scope_finished(task)
    text = stream.getvalue()
    assert [text.index(f"Segment {i}") for i in range(1, 5)] == sorted(text.index(f"Segment {i}") for i in range(1, 5))
    assert text.count("[Complete]") == 4  # Three complete segments plus nested output.
    assert "retained segment needs volume" in text and "old password failure" not in text
    assert text.index("nested.zip") < text.index("Segment 2")
    assert not reporter._task_rows and not reporter._scope_roots and not reporter._output_rows


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


def test_progress_bar_survives_resize_and_plain_output(tmp_path):
    # The tree test checks routing; this catches a missing bar, lost percent on
    # narrow terminals, and VT leaking into clients that cannot update lines.
    from tests.helpers.archive_tasks import make_archive_task

    for updates in (True, False):
        stream = io.StringIO()
        stream.isatty = lambda: True
        stream.supports_terminal_updates = updates
        stream.terminal_size = os.terminal_size((100, 25))
        reporter = RunReporter("zh", stdout=stream)
        task = make_archive_task(tmp_path / ("中文长名称" * 30 + ".zip"))
        reporter.tasks_discovered(1, [task])
        reporter.task_started(task)
        if updates:
            assert "[--------------------]  --%" in stream.getvalue()
        reporter.task_progress(task, {"type": "progress", "completed_bytes": 50, "total_bytes": 100})
        for width in (100, 30, 1, 100):
            stream.seek(0); stream.truncate(0)
            stream.terminal_size = os.terminal_size((width, 25))
            reporter.task_status(task, "extracting")  # Force a semantic refresh, without sleeping.
            text = stream.getvalue()
            if updates:
                for line in text.splitlines():
                    plain = re.sub(r"\033\[[0-9;]*[A-Za-z]", "", line).replace("\r", "")
                    assert reporting._display_width(plain) < width
                if width == 100:
                    assert "[##########----------]  50%" in text
                elif width == 30:
                    assert "50%" in text and "##########" not in text
            else:
                assert not text
        reporter.task_finished(task, _success(tmp_path / "out"), 1)
        reporter.scope_finished(task)
        assert "[####################] 100%" in stream.getvalue()
        if not updates:
            assert "\033[" not in stream.getvalue()
        assert not reporter._task_rows
