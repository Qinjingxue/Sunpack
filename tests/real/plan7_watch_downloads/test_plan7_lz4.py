from __future__ import annotations

import pytest

from tests.helpers.real_archives import create_multi_member_stream_archive
from tests.helpers.seven_zip_lz4 import create_7z_lz4_case
from tests.real.plan1_real_archives.plan1_support import assert_expected_files_extracted
from tests.real.plan7_watch_downloads.plan7_support import (
    arrive_interleaved,
    arrive_slowly,
    drive_watch_until,
    marker_text_extracted,
    start_watch,
)


@pytest.mark.parametrize("write_mode", ["rename_commit", "direct_final_path"])
def test_plan7_concatenated_lz4_frames_download_and_verify_full_output(tmp_path, write_mode):
    case = create_multi_member_stream_archive(
        tmp_path / "fixtures", f"lz4_concat_{write_mode}", "lz4", payload_size=256 * 1024,
    )
    harness = start_watch(tmp_path, f"lz4-{write_mode}", passwords=[])
    try:
        arrive_interleaved(harness, [case.entry_path], write_mode=write_mode)
        result = drive_watch_until(
            harness.watcher,
            lambda: marker_text_extracted(
                harness.output_root, case.marker_name,
                case.marker_text + case.metadata["second_member_content"],
            ),
        )
        assert result.failed == 0
        assert not harness.watcher.state.entries
        assert_expected_files_extracted(case, harness.output_root)
    finally:
        harness.close()


@pytest.mark.parametrize("split", [False, True], ids=["encrypted", "encrypted-disguised-split"])
def test_plan7_seven_zip_lz4_coder_downloads_through_existing_password_and_volume_chain(tmp_path, split):
    case = create_7z_lz4_case(tmp_path / "fixtures", "seven_zip_lz4", password="secret",
                               split=split, disguise=split)
    harness = start_watch(tmp_path, f"7z-lz4-{split}", passwords=["wrong", "secret"])
    try:
        parts = sorted(case.archive_dir.iterdir())
        for part in reversed(parts):
            arrive_slowly(harness, part)
        result = drive_watch_until(
            harness.watcher,
            lambda: marker_text_extracted(harness.output_root, case.marker_name, case.marker_text),
        )
        assert result.failed == 0
        assert not harness.watcher.state.entries
        assert_expected_files_extracted(case, harness.output_root)
    finally:
        harness.close()
