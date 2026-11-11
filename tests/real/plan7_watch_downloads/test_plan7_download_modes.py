import pytest

from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, PASSWORD, assert_once, download, download_interleaved, watch_setup,
)


pytestmark = pytest.mark.requires_watch_broker


@pytest.mark.parametrize("same_stem", [False, True], ids=["encrypted-pair", "plain-and-sfx-same-stem"])
def test_plan7_interleaved_downloads_complete_every_file(package, tmp_path, same_stem):
    cases = [
        FACTORY.create(
            tmp_path / "fixtures", f"interleaved-{archive_format}", archive_format,
            password=PASSWORD, sfx=same_stem and archive_format == "7z", payload_size=96 * 1024,
        )
        for archive_format in ("7z", "zip")
    ]
    if same_stem:
        for case in cases:
            case.entry_path = case.entry_path.rename(
                case.entry_path.with_name(f"release{case.entry_path.suffix}")
            )
    watch = watch_setup(package, tmp_path)
    download_interleaved(watch, [case.entry_path for case in cases])
    for case in cases:
        watch.await_archive(case)
    watch.stop()
    for case in cases:
        assert_once(watch, case)
    watch.assert_no_terminal_failures()


def test_plan7_direct_encrypted_download(package, tmp_path):
    case = FACTORY.create(
        tmp_path / "fixtures", "direct-zip", "zip", password=PASSWORD, payload_size=128 * 1024,
    )
    watch = watch_setup(package, tmp_path)
    download(watch, case.entry_path, mode="direct")
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)


@pytest.mark.parametrize("resume", [False, True], ids=["deleted-and-redownloaded", "resumed"])
def test_plan7_interrupted_download_completes_after_restart(package, tmp_path, resume):
    case = FACTORY.create(
        tmp_path / "fixtures", "restart-zip", "zip", password=PASSWORD, payload_size=128 * 1024,
    )
    watch = watch_setup(package, tmp_path)
    partial = download(watch, case.entry_path, interrupt=True)
    if not resume:
        partial.unlink()
    assert not list(watch.output.rglob(case.marker_name))
    watch.restart()
    download(watch, case.entry_path, resume=resume)
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)
