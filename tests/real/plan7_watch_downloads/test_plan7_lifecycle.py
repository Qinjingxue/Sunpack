from __future__ import annotations

import time

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory, corrupt_file
from tests.real.plan7_watch_downloads.plan7_support import (
    PASSWORD,
    arrive_interleaved,
    arrive_slowly,
    drive_watch_until,
    marker_text_extracted,
    start_watch,
    wrong_password_list,
)


FACTORY = ArchiveFixtureFactory()


def _finish(harness, marker_name: str, marker_text: str) -> None:
    drive_watch_until(
        harness.watcher,
        lambda: marker_text_extracted(harness.output_root, marker_name, marker_text),
    )
    assert marker_text_extracted(harness.output_root, marker_name, marker_text)


def test_plan7_existing_file_initial_scan_and_quiet_window(tmp_path):
    """watch 启动时已有完整文件，且使用非零 quiet window 时仍能处理。"""
    case = FACTORY.create(
        tmp_path / "fixtures",
        "p7_initial_scan",
        "zip",
        password=PASSWORD,
        payload_size=32 * 1024,
    )
    watch_root = tmp_path / "initial_scan" / "watch"
    watch_root.mkdir(parents=True)
    target = watch_root / "already-there.zip"
    target.write_bytes(case.entry_path.read_bytes())

    harness = start_watch(
        tmp_path,
        "initial_scan",
        passwords=[*wrong_password_list(), PASSWORD],
        cold_start_seconds=0.05,
        initial_scan=True,
    )
    try:
        _finish(harness, case.marker_name, case.marker_text)
    finally:
        harness.close()


def test_plan7_deleted_partial_download_can_restart_from_scratch(tmp_path):
    """临时下载文件被删除后，watch 重启并重新完整下载仍可恢复。"""
    case = FACTORY.create(
        tmp_path / "fixtures",
        "p7_redownload_after_delete",
        "zip",
        password=PASSWORD,
        payload_size=128 * 1024,
    )
    state_path = tmp_path / "redownload" / "state.json"
    first = start_watch(
        tmp_path,
        "redownload",
        passwords=[*wrong_password_list(), PASSWORD],
        state_path=state_path,
    )
    try:
        arrive_slowly(first, case.entry_path, interrupt_after_chunks=1)
        partial = first.watch_root / f"{case.entry_path.name}.downloading"
        assert partial.exists()
        partial.unlink()
        assert not marker_text_extracted(
            first.output_root, case.marker_name, case.marker_text
        )
    finally:
        first.close()

    second = start_watch(
        tmp_path,
        "redownload",
        passwords=[*wrong_password_list(), PASSWORD],
        state_path=state_path,
    )
    try:
        arrive_slowly(second, case.entry_path)
        _finish(second, case.marker_name, case.marker_text)
    finally:
        second.close()


def test_plan7_stale_downloading_file_does_not_block_final_file(tmp_path):
    """残留的 .downloading 文件不应阻塞同名完整文件的处理。"""
    case = FACTORY.create(
        tmp_path / "fixtures",
        "p7_stale_downloading",
        "7z",
        password=PASSWORD,
        payload_size=32 * 1024,
    )
    watch_root = tmp_path / "stale" / "watch"
    watch_root.mkdir(parents=True)
    (watch_root / f"stale.7z.downloading").write_bytes(b"incomplete download")
    (watch_root / "stale.7z").write_bytes(case.entry_path.read_bytes())

    harness = start_watch(
        tmp_path,
        "stale",
        passwords=[*wrong_password_list(), PASSWORD],
        initial_scan=True,
    )
    try:
        _finish(harness, case.marker_name, case.marker_text)
    finally:
        harness.close()


def test_plan7_split_recovers_when_missing_last_volume_arrives(tmp_path):
    """分卷先缺尾卷，尾卷后来到达后应继续完成。"""
    case = FACTORY.create(
        tmp_path / "fixtures",
        "p7_late_last_volume",
        "7z",
        password=PASSWORD,
        split=True,
        payload_size=256 * 1024,
    )
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    assert len(parts) >= 3
    head = next(path for path in parts if path.name.casefold().endswith(".7z.001"))
    ordered = [head, *[path for path in parts if path != head]]
    last = ordered[-1]

    harness = start_watch(
        tmp_path,
        "late_last_volume",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    try:
        for volume in ordered[:-1]:
            arrive_slowly(harness, volume)
        assert not marker_text_extracted(
            harness.output_root, case.marker_name, case.marker_text
        )
        arrive_slowly(harness, last)
        _finish(harness, case.marker_name, case.marker_text)
    finally:
        harness.close()


def test_plan7_incomplete_split_recovers_after_watcher_restart(tmp_path):
    """watch 重启时保留未完成分卷状态，最后一卷到达后仍能完成。"""
    case = FACTORY.create(
        tmp_path / "fixtures",
        "p7_restart_split",
        "zip",
        password=PASSWORD,
        split=True,
        payload_size=256 * 1024,
    )
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    assert len(parts) >= 3
    head = next(path for path in parts if path.name.casefold().endswith(".zip.001"))
    ordered = [head, *[path for path in parts if path != head]]
    state_path = tmp_path / "restart_split" / "state.json"

    first = start_watch(
        tmp_path,
        "restart_split",
        passwords=[*wrong_password_list(), PASSWORD],
        state_path=state_path,
    )
    try:
        for volume in ordered[:-1]:
            arrive_slowly(first, volume)
        assert not marker_text_extracted(
            first.output_root, case.marker_name, case.marker_text
        )
    finally:
        first.close()

    second = start_watch(
        tmp_path,
        "restart_split",
        passwords=[*wrong_password_list(), PASSWORD],
        state_path=state_path,
    )
    try:
        arrive_slowly(second, ordered[-1])
        _finish(second, case.marker_name, case.marker_text)
    finally:
        second.close()


def test_plan7_same_stem_plain_and_sfx_arrive_interleaved(tmp_path):
    """同 stem 的普通包和 SFX 同时下载时，两个用户可见结果都应出现。"""
    plain = FACTORY.create(
        tmp_path / "fixtures" / "plain",
        "p7_same_stem_plain",
        "zip",
        password=PASSWORD,
        payload_size=32 * 1024,
    )
    sfx = FACTORY.create(
        tmp_path / "fixtures" / "sfx",
        "p7_same_stem_sfx",
        "7z",
        password=PASSWORD,
        sfx=True,
        payload_size=32 * 1024,
    )
    plain_target = plain.archive_dir / "release.zip"
    sfx_target = sfx.archive_dir / "release.exe"
    plain.entry_path.replace(plain_target)
    sfx.entry_path.replace(sfx_target)
    plain.entry_path = plain_target
    sfx.entry_path = sfx_target

    harness = start_watch(
        tmp_path,
        "same_stem",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    try:
        stable = arrive_interleaved(
            harness,
            [plain.entry_path, sfx.entry_path],
        )
        for case in (plain, sfx):
            harness.stable_at_by_name[case.entry_path.name] = stable[case.entry_path.name]
        _finish(harness, plain.marker_name, plain.marker_text)
        _finish(harness, sfx.marker_name, sfx.marker_text)
    finally:
        harness.close()


def test_plan7_replacement_and_reappearance_are_processed(tmp_path):
    """同名归档替换、删除后重新出现时，新的用户可见结果仍能产生。"""
    first = FACTORY.create(
        tmp_path / "fixtures" / "first",
        "p7_replace_first",
        "zip",
        password=PASSWORD,
        payload_size=32 * 1024,
    )
    second = FACTORY.create(
        tmp_path / "fixtures" / "second",
        "p7_replace_second",
        "zip",
        password=PASSWORD,
        payload_size=32 * 1024,
    )
    third = FACTORY.create(
        tmp_path / "fixtures" / "third",
        "p7_replace_third",
        "zip",
        password=PASSWORD,
        payload_size=32 * 1024,
    )
    for case in (first, second, third):
        target = case.archive_dir / "release.zip"
        case.entry_path.replace(target)
        case.entry_path = target

    harness = start_watch(
        tmp_path,
        "replacement",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    try:
        arrive_slowly(harness, first.entry_path)
        _finish(harness, first.marker_name, first.marker_text)

        arrive_slowly(harness, second.entry_path, write_mode="direct_final_path")
        _finish(harness, second.marker_name, second.marker_text)

        final_path = harness.watch_root / "release.zip"
        assert final_path.exists()
        final_path.unlink()
        assert not final_path.exists()

        arrive_slowly(harness, third.entry_path)
        _finish(harness, third.marker_name, third.marker_text)
    finally:
        harness.close()


@pytest.mark.parametrize("archive_format", ["tar.gz", "tar.bz2", "tar.xz", "tar.zst", "gzip", "bzip2", "xz", "zstd"])
def test_plan7_stream_formats_direct_final_path_complete(tmp_path, archive_format):
    """流格式直接写入最终路径时，完整下载后都应有用户可见输出。"""
    case = FACTORY.create(
        tmp_path / "fixtures",
        f"p7_direct_{archive_format.replace('.', '_')}",
        archive_format,
        payload_size=16 * 1024,
    )
    harness = start_watch(
        tmp_path,
        f"direct_{archive_format.replace('.', '_')}",
        passwords=[*wrong_password_list(), PASSWORD],
    )
    try:
        stable = arrive_interleaved(
            harness,
            [case.entry_path],
            write_mode="direct_final_path",
        )
        harness.stable_at_by_name[case.entry_path.name] = stable[case.entry_path.name]
        _finish(harness, case.marker_name, case.marker_text)
    finally:
        harness.close()


def test_plan7_failed_archive_is_not_deleted_and_does_not_extract(tmp_path):
    """失败归档保留给用户排查，且不能产生成功输出。"""
    case = FACTORY.create(
        tmp_path / "fixtures",
        "p7_failed_archive",
        "zip",
        password=PASSWORD,
        payload_size=32 * 1024,
    )
    corrupt_file(case.entry_path, mode="truncate")
    harness = start_watch(
        tmp_path,
        "failed_archive",
        passwords=[*wrong_password_list(), PASSWORD],
        cleanup_mode="delete",
    )
    try:
        arrive_slowly(harness, case.entry_path)
        for _ in range(20):
            harness.watcher.run_once()
            time.sleep(0.02)
        assert not marker_text_extracted(
            harness.output_root, case.marker_name, case.marker_text
        )
        assert (harness.watch_root / case.entry_path.name).exists()
    finally:
        harness.close()
