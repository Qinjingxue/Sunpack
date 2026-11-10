"""Destination encoding, tree topology and viewport behavior share one palette."""
import io
import os
from types import SimpleNamespace

import pytest

from sunpack.core.support.console_tree import ASCII_TREE, UNICODE_TREE, tree_style
from sunpack.pipeline.coordinator.reporting import RunReporter, _display_width, _truncate_display


@pytest.mark.parametrize("encoding, expected", [("utf-8", UNICODE_TREE), ("cp1252", ASCII_TREE), ("ascii", ASCII_TREE)])
def test_palette_is_encoding_based_even_when_redirected(encoding, expected):
    # VT/TTY cannot establish whether the receiving byte stream encodes strokes.
    for tty in (False, True):
        stream = io.TextIOWrapper(io.BytesIO(), encoding=encoding)
        stream.isatty = lambda: tty
        stream.supports_terminal_updates = tty
        assert tree_style(stream) is expected
        stream.write(expected.branch + expected.last_branch + expected.vertical)
        stream.flush()  # Strict encoding must succeed, including ASCII fallback.


def test_custom_text_sinks_and_forwarded_destinations_are_not_probed_by_writing():
    # StringIO is Unicode text, whereas an unknown custom sink cannot promise it;
    # a server proxy must honor its client rather than its UTF-8 wire encoding.
    class Output:
        encoding = None

        def write(self, _text):
            pytest.fail("Capability selection must not emit probe output")

    stream = Output()
    assert tree_style(stream) is ASCII_TREE
    stream.encoding = "not-a-codec"
    assert tree_style(stream) is ASCII_TREE
    stream.encoding = "utf-8"
    stream.supports_unicode_tree = False
    assert tree_style(stream) is ASCII_TREE
    stream.encoding = "ascii"
    stream.supports_unicode_tree = True
    assert tree_style(stream) is UNICODE_TREE
    assert tree_style(io.StringIO()) is UNICODE_TREE

    class EncodedText(io.StringIO):
        encoding = "ascii"

    assert tree_style(EncodedText()) is ASCII_TREE


@pytest.mark.parametrize("encoding, edges", [
    ("utf-8", ("├─ first", "│  ├─ nested", "│  │  └─ deep", "│  └─ next", "└─ last")),
    ("cp1252", ("+---first", "|   +---nested", "|   |   \\---deep", "|   \\---next", "\\---last")),
])
def test_deep_sibling_tree_keeps_ancestor_bars_and_releases_rows(encoding, edges):
    # A single-child example cannot expose lost ancestor bars or a wrong last
    # connector inside a non-last segment. No archive/native I/O is needed.
    output, errors = io.BytesIO(), io.BytesIO()
    stream = io.TextIOWrapper(output, encoding=encoding)
    error_stream = io.TextIOWrapper(errors, encoding="cp1252" if encoding == "utf-8" else "utf-8")
    reporter = RunReporter(stdout=stream, stderr=error_stream, verbose=True)
    reporter._scope_roots["root"] = None
    for key, children in (("root", ["first", "last"]), ("first", ["nested", "next"]),
                          ("nested", ["deep"]), ("deep", []), ("next", []), ("last", [])):
        row = reporter._task_rows[key] = reporter._new_row(key)
        row["children"] = children
        row["state"] = "complete"
        row["detail"] = "detail"
    reporter._print("diagnostic", error=True)
    task = SimpleNamespace(runtime={"report_scope": "root"})
    reporter.scope_finished(task)
    text = output.getvalue().decode(encoding)
    names = [line for line in text.splitlines() if not ("[" in line or "detail" in line)]
    assert names == ["root", *edges]
    stem = "│  │    " if encoding == "utf-8" else "|   |     "
    assert stem + "detail" in text.splitlines()
    assert "diagnostic" not in text and errors.getvalue().decode(error_stream.encoding) == "diagnostic\n"
    assert not reporter._task_rows and not reporter._scope_roots


def test_ascii_live_panel_handles_tiny_widths_and_unicode_strokes_use_one_cell():
    # Final output never truncates, so it cannot detect a Unicode ellipsis in
    # strict ASCII or incorrect cell budgets in live, resized tree panels.
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii")
    stream.supports_terminal_updates = True
    stream.isatty = lambda: True
    reporter = RunReporter(stdout=stream)
    reporter._scope_roots["root"] = None
    reporter._task_rows["root"] = reporter._new_row("a long name")
    for width in (80, 3, 2, 1, 80):
        stream.terminal_size = os.terminal_size((width, 4))
        reporter._render_panel_locked(force=True)
        assert all(_display_width(line) < width for line in reporter._rendered_panel)
    assert "…" not in raw.getvalue().decode("ascii")
    assert _display_width("│  └─ file") == len("│  └─ file")
    assert _truncate_display("a", 1, ellipsis="...") == "a"
    assert _truncate_display("long", 1, ellipsis="...") == "."
    assert _truncate_display("long", 2, ellipsis="...") == ".."
    assert _truncate_display("│  └─ file", 8) == "│  └─ f…"


def test_json_scan_projection_is_independent_of_tree_palette():
    # JSON consumers receive facts, never display strokes or indentation.
    from sunpack.core.contracts.results import OutcomeKind, RunSummary, TargetRunResult
    from sunpack.core.i18n import I18nContext
    from sunpack.runtime.cli.cli_reporter import CliReporter
    from sunpack.runtime.cli.commands.scan import command_result

    item = {"main_path": "carrier.bin", "offset": 1, "end_offset": 10, "format": "zip"}
    summary = RunSummary(target_results=(TargetRunResult("carrier.bin", OutcomeKind.SCANNED,
                                                       scan_items=(item,)),))
    for encoding in ("ascii", "utf-8"):
        raw = io.BytesIO()
        output = io.TextIOWrapper(raw, encoding=encoding)
        ctx = SimpleNamespace(t=I18nContext("en").t, reporter=CliReporter(json_mode=True, stdout=output))
        code, result = command_result(SimpleNamespace(json=True, verbose=False, deep_detect=True),
                                      ctx, ["carrier.bin"], summary)
        assert code == 0 and result.items == [item]
        output.flush()
        assert raw.getvalue() == b""
