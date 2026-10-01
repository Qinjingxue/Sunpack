from __future__ import annotations

from pathlib import Path

import pytest

from sunpack.core.contracts.failures import FailureKind
from tests.helpers.marker_utils import marker_present
from tests.helpers.tool_config import get_optional_rar
from tests.real.nested_cases import assert_nested_outputs, build_nested_case
from tests.real.plan7_watch_downloads.plan7_support import (
    arrive_slowly, drive_watch_until, start_watch,
)


@pytest.mark.parametrize("outer_format", ["7z", "zip", "rar"])
def test_plan7_disguised_split_nested_carrier_survives_two_restarts_and_password_update(
    tmp_path, plan7_error, outer_format,
):
    if outer_format == "rar" and get_optional_rar() is None:
        pytest.skip("RAR writer is required")
    case = build_nested_case(tmp_path / "fixtures", f"watch-{outer_format}", outer_format)
    label = f"nested-lifecycle-{outer_format}"
    options = dict(passwords=list(case.passwords[:2]), cleanup_mode="delete", flatten_single_directory=True)
    first = start_watch(tmp_path, label, **options)
    try:
        # Reverse the data-volume arrival order, leave the tail absent, and
        # deliver the head last. No nested output can appear from this group.
        for part in reversed(case.parts[:-1]):
            arrive_slowly(first, part)
        assert not marker_present(first.output_root, case.ready_marker)
        assert not marker_present(first.output_root, case.blocked.marker_name)
    finally:
        first.close()

    second = start_watch(tmp_path, label, **options)
    try:
        arrive_slowly(second, case.parts[-1])
        drive_watch_until(second.watcher, lambda: any(
            Path(entry.path).name == case.blocked_name and entry.status == "failed_password"
            for entry in second.watcher.state.entries.values()
        ))
        entries = list(second.watcher.state.entries.values())
        assert len(entries) == 1
        entry = entries[0]
        assert entry.failure_kind == FailureKind.WRONG_PASSWORD.value
        assert (entry.failure_payload or {})["blockers"] == ["password"]
        password_scope = Path(entry.failure_payload["password_scope_dir"])
        assert password_scope == second.watch_root
        retry_input = Path(entry.path)
        assert retry_input.is_file()
        assert_nested_outputs(second.output_root, case, leaf_success=False)
        plan7_error.update({"layout": case.layout, "retry_input": str(retry_input), "status": entry.status})
    finally:
        second.close()

    third = start_watch(tmp_path, label, **options)
    try:
        # Generated inner tasks inherit the original input password scope even
        # when their retained retry input is under a separate output root.
        password_file = password_scope / "sunpack-passwords.txt"
        password_file.write_text("\n".join(["wrong-again", *case.passwords]) + "\n", encoding="utf-8")
        third.watcher.notify_password_table_changed(str(password_file))
        result = drive_watch_until(third.watcher, lambda: marker_present(third.output_root, case.blocked.marker_name))
        assert result.failed == 0
        assert result.succeeded == 1
        assert not third.watcher.state.entries
        assert not retry_input.exists(), "successful retry must clean the retained inner archive"
        assert_nested_outputs(third.output_root, case, leaf_success=True)
    finally:
        third.close()
