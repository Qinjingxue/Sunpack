from __future__ import annotations

import asyncio
import os
import shutil

import pytest

from sunpack.pipeline.coordinator.archive_job import ArchiveJobExecutor
from sunpack.runtime.watch.scheduler import WatchScheduler
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


def test_watch_sibling_trigger_survives_encrypted_head_rename(tmp_path, monkeypatch):
    """Force the split seed/head mismatch that arrival timing only occasionally hits."""
    case = create_7z_lz4_case(tmp_path / "fixtures", "renamed_head", password="secret",
                              split=True, disguise=True)
    harness = start_watch(tmp_path, "head-rename", passwords=["wrong", "secret"])
    parts = sorted(case.archive_dir.iterdir())
    final_head = harness.watch_root / parts[0].name
    temporary_head = final_head.with_name(final_head.name + ".downloading")
    seed = harness.watch_root / parts[1].name
    for part in parts:
        shutil.copyfile(part, temporary_head if part == parts[0] else harness.watch_root / part.name)
    original = ArchiveJobExecutor._execute_one_async

    async def scenario():
        entered = asyncio.Event()
        resume = asyncio.Event()

        async def hold_old_head(self, task, *args, **kwargs):
            if task.main_path == str(temporary_head):
                entered.set()
                await resume.wait()
            return await original(self, task, *args, **kwargs)

        monkeypatch.setattr(ArchiveJobExecutor, "_execute_one_async", hold_old_head)
        try:
            harness.watcher.enqueue(str(seed))
            await WatchScheduler.run_once(harness.watcher)
            await asyncio.wait_for(entered.wait(), 15)
            os.replace(temporary_head, final_head)
            harness.watcher.notify_path_departed(str(temporary_head))
            harness.watcher.enqueue(str(final_head), event_type="moved", src_path=str(temporary_head))
            resume.set()
            await asyncio.gather(*(request.task for request in harness.watcher._inflight_requests),
                                 return_exceptions=True)
            old_result = await WatchScheduler.run_once(harness.watcher)
            final_result = await harness.watcher.drain()
            assert old_result.failed == final_result.failed == 0
            assert old_result.succeeded + final_result.succeeded == 1
            assert marker_text_extracted(harness.output_root, case.marker_name, case.marker_text)
            assert_expected_files_extracted(case, harness.output_root)
            assert harness.watcher.pending_count == 0
            assert not harness.watcher.state.entries
        finally:
            resume.set()

    try:
        harness.loop.run_until_complete(scenario())
    finally:
        harness.close()


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
