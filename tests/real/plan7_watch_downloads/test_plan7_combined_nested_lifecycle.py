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
        assert not marker_present(first.output_root, case.lz4_marker)
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
        restored = third.watcher.state.failed_password_entries_under(str(password_scope))
        assert [Path(item.path) for item in restored] == [retry_input]
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


def test_plan7_cp437_names_inside_encrypted_disguised_split_carrier(tmp_path, plan7_error):
    from scripts.generate_real_structure_corpus import STRUCTURE_CASES, generate
    from tests.helpers.native_fixture import assemble_carrier, assert_exact_tree
    from tests.helpers.real_archives import ArchiveCase, choose_entry_path, create_7z_archive
    from tests.real.plan6_confused_volumes.plan6_support import SCENARIOS, apply_volume_confusion

    corpus = tmp_path / "corpus"
    sample = generate(corpus, cases=tuple(
        case for case in STRUCTURE_CASES if case[0] == "bsdtar-zip-cp437"
    ))[0]
    wrapper = tmp_path / "wrapper"
    wrapper.mkdir()
    layout = assemble_carrier(wrapper / "picture.jpg", [corpus / sample["file"]], seed=437, decoys=True)
    archive_dir = tmp_path / "volumes"
    archive_dir.mkdir()
    password = "cp437-watch-regression"
    create_7z_archive(wrapper, archive_dir / "legacy.7z", password=password,
                      split=True, split_volume_size=4096)
    outer = ArchiveCase(
        case_id="legacy", archive_dir=archive_dir,
        entry_path=choose_entry_path(archive_dir, "legacy", "7z"),
        marker_name="marker.txt", marker_text="corpus::bsdtar-zip-cp437\n",
        archive_format="7z", password=password, split=True,
    )
    parts = apply_volume_confusion(outer, SCENARIOS[2], add_distractors=False)
    assert len(parts) >= 2
    plan7_error["layout"] = layout
    harness = start_watch(tmp_path, "cp437", passwords=["wrong", password],
                          cleanup_mode="delete", flatten_single_directory=True)
    try:
        for part in reversed(parts[:-1]):
            arrive_slowly(harness, part)
        assert not marker_present(harness.output_root, "marker.txt")
    finally:
        harness.close()

    harness = start_watch(tmp_path, "cp437", passwords=["wrong", password],
                          cleanup_mode="delete", flatten_single_directory=True)
    try:
        arrive_slowly(harness, parts[-1])
        def output_is_committed():
            # Inspect paths only once the request has finished moving them.
            # Windows directory enumeration can otherwise prevent flattening.
            with harness.watcher._lock:
                if harness.watcher._inflight_requests:
                    return False
            return marker_present(harness.output_root, "marker.txt")

        result = drive_watch_until(harness.watcher, output_is_committed)
        assert result.failed == 0
        assert not harness.watcher.state.entries
        markers = list(harness.output_root.rglob("marker.txt"))
        assert len(markers) == 1
        assert_exact_tree(markers[0].parent, sample["expected_files"])
    finally:
        harness.close()
