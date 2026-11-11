import pytest

from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, PASSWORD, assert_once, download, split_order, watch_setup,
)
from tests.real.plan7_watch_downloads.test_plan7_plain_and_sfx_downloads import generated_formats


pytestmark = pytest.mark.requires_watch_broker


def test_plan7_split_downloads_out_of_order(package, tmp_path, record_property):
    cases = [
        FACTORY.create(
            tmp_path / "fixtures", f"p7_{archive_format}_{'sfx_split' if sfx else 'split'}",
            archive_format, password=PASSWORD, sfx=sfx, split=True, payload_size=420 * 1024,
        )
        for sfx in (False, True)
        for archive_format in generated_formats(("7z", "zip", "rar"), sfx=sfx)
    ]
    watch = watch_setup(package, tmp_path)
    memory = [watch.memory()]
    for index, case in enumerate(cases):
        order = split_order(case, seed=19 + index)
        for source in order:
            download(watch, source)
        memory.append(watch.memory())
        watch.await_archive(case)
        memory.append(watch.memory())
        assert all((watch.root / part.name).is_file() for part in order)
    watch.stop()
    for case in cases:
        assert_once(watch, case)
    watch.assert_no_terminal_failures()
    record_property("watch_memory_timeline_bytes", memory)
    assert max(runtime for runtime, _, _ in memory) - memory[0][0] < 128 * 1024**2, memory
    worker = [rss for _, rss, count in memory if count]
    assert worker and max(worker) - min(worker) < 64 * 1024**2, memory
    assert max(count for _, _, count in memory) == 1, memory
