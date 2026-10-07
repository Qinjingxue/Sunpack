from __future__ import annotations

import pytest

from tests.real.enc_support import ENC_PASSWORD, create_enc_case
from tests.real.plan7_watch_downloads.plan7_support import (
    arrive_slowly,
    drive_watch_until,
    marker_text_extracted,
    start_watch,
)


@pytest.mark.parametrize("write_mode", ["rename_commit", "direct_final_path"])
def test_plan7_enc_download_is_decrypted_after_arrival(tmp_path, plan7_error, write_mode):
    case = create_enc_case(tmp_path / "fixtures", f"official_enc_{write_mode}")
    plan7_error.update(
        {
            "case_id": f"official_enc_{write_mode}",
            "archive_format": "enc",
            "download_write_mode": write_mode,
        }
    )
    harness = start_watch(
        tmp_path,
        f"enc_{write_mode}",
        passwords=["wrong-watch-password", ENC_PASSWORD],
    )
    try:
        arrive_slowly(harness, case.entry_path, write_mode=write_mode)
        result = drive_watch_until(
            harness.watcher,
            lambda: marker_text_extracted(
                harness.output_root,
                case.marker_name,
                case.marker_text,
            ),
        )
        assert result.failed == 0, result.errors
        assert harness.submit_times, "watch did not submit the downloaded ENC file"
        assert not any(harness.watcher.state.entries.values()), "watch retained a failed ENC entry"
    finally:
        harness.close()
