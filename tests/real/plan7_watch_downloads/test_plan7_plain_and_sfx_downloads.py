from __future__ import annotations

import pytest

from tests.helpers.tool_config import get_optional_rar, get_optional_rar_sfx, get_test_tools
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, PASSWORD, assert_once, download, watch_setup,
)


pytestmark = pytest.mark.requires_watch_broker

PLAIN_FORMATS = (
    "zip", "rar", "7z", "tar", "tar.gz", "tar.bz2", "tar.xz", "tar.zst", "tar.lz4",
    "gzip", "bzip2", "xz", "zstd", "lz4",
)
SFX_FORMATS = ("7z", "zip", "rar")


def generated_formats(formats, *, sfx=False):
    tools = get_test_tools()
    for archive_format in formats:
        if archive_format == "rar" and (
            not get_optional_rar() or (sfx and not get_optional_rar_sfx())
        ):
            continue
        if archive_format in {"zip", "7z"} and sfx and not tools["seven_zip_sfx"]:
            continue
        if archive_format in {"zstd", "tar.zst"} and not tools["zstd_exe"]:
            continue
        yield archive_format


def test_plan7_plain_and_sfx_download_matrix(package, tmp_path, record_property):
    cases = [
        FACTORY.create(
            tmp_path / "fixtures", f"p7_{archive_format}_{'sfx' if sfx else 'plain'}", archive_format,
            password=PASSWORD if archive_format in SFX_FORMATS else None,
            sfx=sfx, payload_size=64 * 1024,
        )
        for sfx, formats in ((False, PLAIN_FORMATS), (True, SFX_FORMATS))
        for archive_format in generated_formats(formats, sfx=sfx)
    ]
    watch = watch_setup(package, tmp_path)
    memory = [watch.memory()]
    for case in cases:
        download(watch, case.entry_path)
        memory.append(watch.memory())
        watch.await_archive(case)
        memory.append(watch.memory())
    watch.stop()
    for case in cases:
        assert_once(watch, case)
    watch.assert_no_terminal_failures()
    record_property("watch_memory_timeline_bytes", memory)
    assert max(runtime for runtime, _, _ in memory) - memory[0][0] < 128 * 1024**2, memory
    worker = [rss for _, rss, count in memory if count]
    assert worker and max(worker) - min(worker) < 64 * 1024**2, memory
    assert max(count for _, _, count in memory) == 1, memory
