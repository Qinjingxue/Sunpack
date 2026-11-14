from collections import Counter
from pathlib import Path
from zipfile import ZipFile

import pytest

from tests.helpers.native_fixture import create_lz4_frames
from tests.helpers.real_archives import ArchiveFixtureFactory, create_encrypted_rar_archive
from tests.real.archive_boundary import require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    PASSWORD, assert_once, download, download_interleaved, wait_for, watch_setup,
)


pytestmark = pytest.mark.requires_watch_broker


@pytest.mark.parametrize("format,mode,cleanup,order,recursive,inside", [
    ("rar", "rename", "k", "overlap", True, True), ("rar", "direct", "k", "overlap", True, True),
    ("rar", "rename", "d", "overlap", True, True), ("rar", "direct", "d", "overlap", True, True),
    ("rar", "rename", "k", "head-first", True, True),
    ("7z", "rename", "k", "head-first", True, True), ("7z", "rename", "k", "tail-first-restart", True, True),
    ("7z", "rename", "k", "head-first", False, True),
    ("7z", "rename", "k", "tail-first-restart", False, False),
    ("7z", "direct", "d", "overlap", False, False),
    ("7z", "rename", "k", "stale-tail", False, False),
], ids=["rar-rename-keep", "rar-direct-keep", "rar-rename-delete", "rar-direct-delete",
        "rar-head-first", "raw-7z-head-first", "raw-7z-tail-first-restart",
        "shallow-raw-head-first", "shallow-raw-tail-restart-external", "shallow-raw-delete-external",
        "shallow-raw-tail-identity-expired"])
def test_plan7_lz4_wrapped_volumes(package, tmp_path, format, mode, cleanup, order, recursive, inside):
    require_generator(format)
    if format == "rar":
        case = create_encrypted_rar_archive(
            tmp_path / "fixtures", "wrapped-rar", password=PASSWORD,
            header_encrypt=True, split=True, split_volume_size=100 * 1024, payload_size=320 * 1024,
        )
    else:
        case = ArchiveFixtureFactory().create(
            tmp_path / "fixtures", "wrapped-7z", "7z", password=PASSWORD,
            split=True, split_volume_size=100 * 1024, payload_size=320 * 1024,
        )
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    assert len(parts) == 4 and parts[0] == case.entry_path
    if format == "7z":
        # These are raw byte slices, not per-volume containers. Only the first
        # slice has a 7z signature; disguise every filename without losing order.
        renamed = []
        for index, part in enumerate(parts, 1):
            target = part.with_name(f"wrapped-7z.{index:03}.blob")
            part.rename(target)
            renamed.append(target)
        parts = renamed
        case.entry_path = parts[0]
        assert parts[0].read_bytes().startswith(b"7z\xbc\xaf\x27\x1c")
        assert all(not part.read_bytes().startswith(b"7z\xbc\xaf\x27\x1c") for part in parts[1:])
    part_names = {part.name for part in parts}
    wrappers = tmp_path / "lz4-inputs"
    wrappers.mkdir()
    sources = []
    for part in (parts if order == "head-first" else reversed(parts)):
        wrapper = wrappers / f"{part.name}.lz4"
        create_lz4_frames(wrapper, [part])
        sources.append(wrapper)

    watch = watch_setup(package, tmp_path, cleanup=cleanup, flatten=cleanup == "d", recursive=recursive, output_inside=inside)
    if order != "overlap":
        # A completed wrapper is a real barrier: either register the missing
        # head before peers exist, or persist raw tails before the head exists.
        first = download(watch, sources[0], directory=watch.root / "first" if recursive else watch.root)
        watch.await_event("done", path=first.name)
        if order == "head-first":
            watch.await_event("suspended_missing_volume", path=case.entry_path.name)
        else:
            generated, = (path for path in watch.output.rglob(parts[-1].name) if path.is_file())
            if order == "stale-tail":
                # Byte-identical replacement is outside the ordinary scope:
                # it must lose dependency visibility, not become a new input.
                generated.rename(tmp_path / "original-tail.blob")
                generated.write_bytes(parts[-1].read_bytes())
            else:
                watch.restart()
        assert not (watch.root / case.entry_path.name).exists(), "nested blockers must remain in place"
        arrived = [first, *download_interleaved(watch, sources[1:], mode=mode, separate=recursive)]
    else:
        arrived = download_interleaved(watch, sources, mode=mode)

    if order == "stale-tail":
        watch.await_event("suspended_missing_volume", path=case.entry_path.name)
        package.json("watch", "start", "--once", "--no-tray")
        watch.restart()
        package.json("watch", "start", "--once", "--no-tray")
        assert not list(watch.output.rglob(case.marker_name))
        assert generated.read_bytes() == parts[-1].read_bytes()
        first.rename(tmp_path / "consumed-wrapper.lz4")
        download(watch, sources[0])

    def family_completed():
        failure = watch.event("failed_terminal", path=case.entry_path.name)
        assert failure is None, failure
        # All generated members are nested sources, including raw tails found
        # later through catalog. Keep mode applies only to the LZ4 inputs.
        if any(path.name in part_names and path.is_file() for path in watch.root.rglob("*")):
            return False
        try:
            return all(
                any(path.stat().st_size == member["size"] for path in watch.output.rglob(name))
                for name, member in case.metadata["expected_files"].items()
            )
        except FileNotFoundError:
            return False

    wait_for(family_completed, "verified output and cleanup of all generated volumes")
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
        assert not any(path.is_file() for path in watch.root.rglob(part.name)), part
        remaining = [path for path in watch.output.rglob(part.name) if path.is_file()]
        assert remaining == ([generated] if order == "stale-tail" and part == parts[-1] else []), part
    assert all(path.is_file() == (cleanup == "k") for path in arrived), arrived
    completed = Counter(
        Path(row["path"]).name for row in watch.display()["history"] if row["event"] == "done"
    )
    assert all(completed[path.name] == (2 if order == "stale-tail" and path == first else 1)
               for path in arrived), completed
    watch.assert_no_terminal_failures()


def test_plan7_mixed_rar_family_keeps_original_volumes_after_watch_restart(package, tmp_path):
    require_generator("rar")
    case = create_encrypted_rar_archive(
        tmp_path / "fixtures", "mixed-rar", password=PASSWORD,
        header_encrypt=True, split=True, split_volume_size=100 * 1024, payload_size=160 * 1024,
    )
    head, tail = sorted(case.archive_dir.glob("*.rar"))
    wrapper = tmp_path / f"{tail.name}.lz4"
    create_lz4_frames(wrapper, [tail])
    watch = watch_setup(package, tmp_path, cleanup="k", recursive=False, output_inside=False)
    downloaded = download(watch, wrapper)
    watch.await_event("done", path=downloaded.name)
    generated, = watch.output.rglob(tail.name)
    assert generated.read_bytes() == tail.read_bytes()

    watch.restart()
    original = download(watch, head)
    watch.await_archive(case)
    wait_for(lambda: not generated.exists(), "retirement of the generated RAR member")
    watch.stop()
    assert original.read_bytes() == head.read_bytes()
    assert downloaded.read_bytes() == wrapper.read_bytes()
    assert_once(watch, case)
