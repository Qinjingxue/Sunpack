import pytest

from tests.helpers.marker_utils import open_shared_file

from tests.real.archive_boundary import require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, PASSWORD, assert_once, download, split_order, watch_setup,
)


pytestmark = pytest.mark.requires_watch_broker


@pytest.mark.parametrize("archive_format,order", [
    ("7z", "launcher_first"), ("zip", "launcher_first"),
    ("7z", "head_last"), ("zip", "head_last"), ("rar", "head_first"),
])
def test_plan7_split_sfx_arrival_order(package, tmp_path, archive_format, order):
    require_generator(archive_format, sfx=True)
    case = FACTORY.create(
        tmp_path / "fixtures", f"p7_order_{archive_format}", archive_format,
        password=PASSWORD, split=True, sfx=True, payload_size=192 * 1024,
    )
    watch = watch_setup(package, tmp_path)
    sources = split_order(case, order=order)
    if order == "head_last":
        for part in sources[:-1]:
            download(watch, part)
        watch.await_archive(case)
        launcher = download(watch, sources[-1])
        watch.await_event("pipeline_request_started", path=launcher.name)
    else:
        first = download(watch, sources[0])
        watch.await_event("pipeline_request_started", path=first.name)
        assert not list(watch.output.rglob(case.marker_name))
        for part in sources[1:]:
            download(watch, part)
        watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)
    watch.assert_no_terminal_failures()


def test_watch_reads_complete_related_volume_before_its_writer_closes(package, tmp_path):
    case = FACTORY.create(
        tmp_path / "fixtures", "p7_readable_member", "7z", password=PASSWORD,
        split=True, payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    head, middle, tail = sorted(case.archive_dir.iterdir())
    watch = watch_setup(package, tmp_path)
    download(watch, middle)
    # Only the admitted head needs scheduler readiness. A complete related
    # member remains readable through the downloader's shared write handle.
    with open_shared_file(watch.root / tail.name, "wb") as writer:
        writer.write(tail.read_bytes())
        writer.flush()
        watch.await_event("candidate_busy", path=tail.name)
        download(watch, head)
        watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)
    watch.assert_no_terminal_failures()
