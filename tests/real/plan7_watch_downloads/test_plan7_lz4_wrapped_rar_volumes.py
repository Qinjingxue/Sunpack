from collections import Counter
from pathlib import Path
from zipfile import ZipFile

import pytest

from tests.helpers.native_fixture import create_lz4_frames
from tests.helpers.real_archives import create_encrypted_rar_archive
from tests.real.archive_boundary import require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    PASSWORD, assert_once, download, download_interleaved, wait_for, watch_setup,
)


pytestmark = pytest.mark.requires_watch_broker


@pytest.mark.parametrize("mode,cleanup,separate", [
    ("rename", "k", False), ("direct", "k", False),
    ("rename", "d", False), ("direct", "d", False),
    ("rename", "k", True),
], ids=["rename-keep", "direct-keep", "rename-delete", "direct-delete", "separate-folders"])
def test_plan7_lz4_wrapped_rar_volumes(package, tmp_path, mode, cleanup, separate):
    require_generator("rar")
    case = create_encrypted_rar_archive(
        tmp_path / "fixtures", "wrapped-rar", password=PASSWORD,
        header_encrypt=True, split=True, split_volume_size=100 * 1024, payload_size=320 * 1024,
    )
    parts = sorted(case.archive_dir.glob("*.rar"))
    assert len(parts) == 4 and parts[0] == case.entry_path
    part_names = {part.name for part in parts}
    wrappers = tmp_path / "lz4-inputs"
    wrappers.mkdir()
    sources = []
    for part in reversed(parts):
        wrapper = wrappers / f"{part.name}.lz4"
        create_lz4_frames(wrapper, [part])
        sources.append(wrapper)

    watch = watch_setup(package, tmp_path, cleanup=cleanup, flatten=cleanup == "d", recursive=separate)
    if separate:
        # First let a tail wrapper publish a promoted, incomplete RAR family.
        # Then overlap the remaining downloads in distinct monitored folders.
        first = download(watch, sources[0], directory=watch.root / "first-tail")
        watch.await_event("done", path=first.name)
        assert list(watch.root.rglob(parts[-1].name)), "Watch must retain the promoted tail before the head arrives"
        arrived = [first, *download_interleaved(watch, sources[1:], mode=mode, separate=True)]
    else:
        arrived = download_interleaved(watch, sources, mode=mode)

    def family_completed():
        failure = watch.event("failed_terminal", path=case.entry_path.name)
        assert failure is None, failure
        # Watch may complete the RAR as a child of the last LZ4 wrapper or as
        # a promoted top-level task. Both paths publish the payload and retire
        # every temporary RAR volume.
        if any(path.name in part_names for tree in (watch.root, watch.output) for path in tree.rglob("*.rar")):
            return False
        try:
            return all(
                any(path.stat().st_size == member["size"] for path in watch.output.rglob(name))
                for name, member in case.metadata["expected_files"].items()
            )
        except FileNotFoundError:
            return False

    wait_for(family_completed, "verified RAR output and cleanup of all promoted volumes")
    if mode == "rename" and cleanup == "k":
        # Force another real observer pass while all aliases of the completed
        # family refer to consumed files. Earlier discovery work must settle
        # without reopening the family or publishing another failure.
        barrier = tmp_path / "fixtures" / "after-family-cleanup.zip"
        with ZipFile(barrier, "w") as archive:
            archive.writestr("after-family-cleanup.txt", b"observer pass after RAR cleanup")
        downloaded = download(watch, barrier)
        watch.await_event("done", path=downloaded.name)
        member, = watch.output.rglob("after-family-cleanup.txt")
        assert member.read_bytes() == b"observer pass after RAR cleanup"
    watch.stop()

    assert_once(watch, case)
    for name in case.metadata["expected_files"]:
        assert len(list(watch.output.rglob(name))) == 1
    for part in parts:
        assert not list(watch.root.rglob(part.name)), part
        assert not list(watch.output.rglob(part.name)), part
    assert all(path.is_file() == (cleanup == "k") for path in arrived), arrived
    completed = Counter(
        Path(row["path"]).name for row in watch.display()["history"] if row["event"] == "done"
    )
    assert all(completed[path.name] == 1 for path in arrived), completed
    watch.assert_no_terminal_failures()
