import pytest

from tests.real.archive_boundary import require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, PASSWORD, assert_once, download, stage_initial, watch_setup,
)


pytestmark = pytest.mark.requires_watch_broker


def test_plan7_stale_download_does_not_block_initial_scan(package, tmp_path):
    case = FACTORY.create(
        tmp_path / "fixtures", "stale", "7z", password=PASSWORD, payload_size=32 * 1024,
    )
    watch = watch_setup(package, tmp_path, start=False)
    (watch.root / f"{case.entry_path.name}.downloading").write_bytes(b"incomplete download")
    stage_initial(watch, case.entry_path)
    watch.start()
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)


@pytest.mark.parametrize("archive_format,restart", [("7z", False), ("zip", True)])
def test_plan7_late_split_tail(package, tmp_path, archive_format, restart):
    case = FACTORY.create(
        tmp_path / "fixtures", "late-volume", archive_format,
        password=PASSWORD, split=True, payload_size=256 * 1024,
    )
    parts = sorted(case.archive_dir.iterdir())
    assert len(parts) >= 3
    watch = watch_setup(package, tmp_path)
    for part in parts[:-1]:
        download(watch, part)
    watch.await_event("suspended_missing_volume", path=parts[0].name)
    assert not list(watch.output.rglob(case.marker_name))
    if restart:
        watch.restart()
    download(watch, parts[-1])
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)


def test_plan7_replacement_and_reappearance(package, tmp_path):
    cases = [
        FACTORY.create(
            tmp_path / "fixtures", f"generation-{index}", "zip",
            password=PASSWORD, payload_size=32 * 1024,
        ) for index in range(3)
    ]
    for case in cases:
        case.entry_path = case.entry_path.rename(case.archive_dir / "release.zip")
    watch = watch_setup(package, tmp_path)
    path = download(watch, cases[0].entry_path)
    watch.await_archive(cases[0])
    watch.await_event("done", path=path.name)
    download(watch, cases[1].entry_path, mode="direct")
    watch.await_archive(cases[1])
    # Same pathname must be recognized as a fresh source after deletion.
    path.unlink()
    download(watch, cases[2].entry_path)
    watch.await_archive(cases[2])
    watch.stop()
    for case in cases:
        assert_once(watch, case)


@pytest.mark.parametrize("archive_format", [
    "tar.gz", "tar.bz2", "tar.xz", "tar.zst", "tar.lz4", "gzip", "bzip2", "xz", "zstd", "lz4",
])
def test_plan7_stream_formats_direct_final_path(package, tmp_path, archive_format):
    require_generator(archive_format)
    case = FACTORY.create(
        tmp_path / "fixtures", "direct-stream", archive_format, payload_size=16 * 1024,
    )
    watch = watch_setup(package, tmp_path)
    download(watch, case.entry_path, mode="direct")
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)


def test_plan7_failed_archive_retains_source(package, tmp_path):
    case = FACTORY.create(
        tmp_path / "fixtures", "failed-archive", "zip", password=PASSWORD, payload_size=32 * 1024,
    )
    with case.entry_path.open("r+b") as file:
        file.truncate(256)
    watch = watch_setup(package, tmp_path, cleanup="d")
    path = download(watch, case.entry_path)
    watch.await_event("pipeline_request_started", path=path.name)
    watch.stop()
    assert path.read_bytes() == case.entry_path.read_bytes()
    assert not list(watch.output.rglob(case.marker_name))
