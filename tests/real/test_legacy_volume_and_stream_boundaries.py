"""Port the archive boundary regressions from main to real entry points."""

import io
import lzma
import struct
import tarfile
import zlib
from pathlib import Path
from shutil import copyfile
from zipfile import ZipFile

import pytest

from tests.helpers.native_fixture import assemble_carrier, file_inventory
from tests.helpers.real_archives import run_cmd, write_payload
from tests.helpers.tool_config import get_optional_rar
from tests.real.archive_boundary import assert_extracted, extract_report, failure_kinds, require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, download, download_interleaved, stage_initial, watch_setup,
)


WATCH = pytest.param("watch", marks=pytest.mark.requires_watch_broker)


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_rar4_old_numbering_recovers_with_disguised_head(package, tmp_path, entry_mode):
    require_generator("rar")
    payload = tmp_path / "payload"
    manifest = write_payload(payload, "legacy", size_bytes=62 * 1024)
    volumes = tmp_path / "volumes"
    volumes.mkdir()
    head = volumes / "legacy.rar"
    run_cmd([
        str(get_optional_rar()), "a", "-ep1", "-idq", "-m0", "-y", "-ma4", "-vn",
        "-v24k", str(head), str(payload / "*"),
    ], volumes)
    middle, tail = sorted(volumes.glob("legacy.r[0-9][0-9]"))
    assert middle.suffix == ".r00" and tail.suffix == ".r01"
    head = head.rename(head.with_suffix(".图片"))
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, volumes, output, cleanup="d")
        assert report["summary"]["success_count"] == 1, report
        parts = [head, middle, tail]
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d")
        delivered_head, delivered_tail = download_interleaved(watch, [head, tail])
        watch.await_event("suspended_missing_volume", path=head.name)
        assert not list(output.rglob(manifest["marker_name"]))
        parts = [delivered_head, delivered_tail, download(watch, middle, mode="direct")]
        watch.await_event("done", path=head.name)
        watch.stop()
        watch.assert_no_terminal_failures()
    assert not any(path.exists() for path in parts)
    marker, = output.rglob(manifest["marker_name"])
    assert marker.parent.name == "legacy"
    assert file_inventory(marker.parent) == manifest["expected_files"]


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_concatenated_xz_reassembles_tar_header_and_preserves_carrier_peer(package, tmp_path, entry_mode):
    # The TAR header itself straddles two XZ streams with different integrity
    # checks. Joining only complete TAR headers or ignoring XZ stream padding
    # would drop the member, and an overlong extent could swallow the peer ZIP.
    payload = b"tar member after a split header"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo("tar-leaf.txt")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    tar = buffer.getvalue()
    stream = tmp_path / "joined.xz"
    stream.write_bytes(lzma.compress(tar[:257], check=lzma.CHECK_CRC32) + bytes(4)
                       + lzma.compress(tar[257:], check=lzma.CHECK_CRC64))
    peer = tmp_path / "peer.zip"
    with ZipFile(peer, "w") as archive:
        archive.writestr("zip-leaf.txt", b"independent ZIP")
    source = tmp_path / "stream.bin"
    assemble_carrier(source, [stream, peer], seed=257)
    package.configure(recursive_authorization={"enabled": False})
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, source, output, cleanup="d")
        assert report["summary"]["failed_count"] == 0, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d")
        source = download(watch, source, mode="direct")
        watch.await_event("done", path=source.name)
        watch.stop()
        watch.assert_no_terminal_failures()
    assert [p.read_bytes() for p in output.rglob("tar-leaf.txt")] == [payload]
    assert [p.read_bytes() for p in output.rglob("zip-leaf.txt")] == [b"independent ZIP"]
    assert len(file_inventory(output)) == 2
    assert not source.exists()


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_standalone_sfx_is_independent_of_same_stem_missing_split(package, tmp_path, entry_mode):
    # The executable contains a complete archive and must not be consumed as
    # a launcher companion for the unrelated, incomplete numbered family.
    require_generator("7z", sfx=True)
    fixtures = tmp_path / "fixtures"
    standalone = FACTORY.create(fixtures, "standalone", "7z", sfx=True, payload_size=12 * 1024)
    split = FACTORY.create(
        fixtures, "numbered", "7z", split=True, payload_size=62 * 1024, split_volume_size=24 * 1024,
    )
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    executable = standalone.entry_path.rename(inputs / "release.exe")
    head, _, tail = sorted(split.archive_dir.iterdir())
    present = [part.rename(inputs / f"release.7z{part.suffix}.图片") for part in (head, tail)]
    original = {path.name: path.read_bytes() for path in present}
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, cleanup="d", code=1)
        assert report["summary"]["success_count"] == 1, report
        assert failure_kinds(report) == {"missing_volume"}, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d", start=False)
        for source in [executable, *present]:
            stage_initial(watch, source)
        package.json("watch", "start", "--once", "--no-tray")
        inputs = watch.root
    assert_extracted(standalone, output, exact=True)
    assert {path.name: path.read_bytes() for path in inputs.iterdir()} == original


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_same_named_local_sets_do_not_share_a_tail_across_subdirectories(package, tmp_path, entry_mode):
    # Main prefers complete local sets. The same basename and volume size
    # must not let an incomplete sibling borrow the complete set's tail.
    cases = [
        FACTORY.create(tmp_path / "fixtures", name, "7z", split=True,
                       payload_size=62 * 1024, split_volume_size=24 * 1024)
        for name in ("complete", "delayed")
    ]
    inputs = tmp_path / "inputs"
    for index, case in enumerate(cases):
        directory = inputs / case.case_id
        directory.mkdir(parents=True)
        parts = sorted(case.archive_dir.iterdir())
        assert len(parts) == 3
        delivered = parts if index == 0 else parts[:-1]
        for part in delivered:
            copyfile(part, directory / f"release.7z{part.suffix}.图片")
    complete, delayed = cases
    delayed_tail = sorted(delayed.archive_dir.iterdir())[-1]
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, recursive=True, cleanup="d", code=1)
        assert report["summary"]["success_count"] == 1, report
        assert failure_kinds(report) == {"missing_volume"}, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d", recursive=True)
        inputs = inputs.rename(watch.root / inputs.name)
        watch.await_archive(complete)
        blocked = watch.await_event("suspended_missing_volume", path="release.7z.001.图片")
        assert Path(blocked["path"]).parent == inputs / delayed.case_id, blocked

    marker, = output.rglob(complete.marker_name)
    identity = marker.stat().st_ino, marker.stat().st_mtime_ns
    assert not list(output.rglob(delayed.marker_name))
    blocked = inputs / delayed.case_id
    assert len(list(blocked.iterdir())) == 2
    arriving = tmp_path / "release.7z.003.图片"
    copyfile(delayed_tail, arriving)
    arriving.rename(blocked / arriving.name)
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, recursive=True, cleanup="d")
        assert report["summary"]["success_count"] == 1, report
    else:
        watch.await_archive(delayed)
        watch.stop()
        watch.assert_no_terminal_failures()
    assert not any(path.is_file() for path in inputs.rglob("*"))
    for case in cases:
        leaf, = output.rglob(case.marker_name)
        assert file_inventory(leaf.parent) == case.metadata["expected_files"]
    assert (marker.stat().st_ino, marker.stat().st_mtime_ns) == identity


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_false_7z_start_header_cannot_hide_real_zip_in_carrier(package, tmp_path, entry_mode):
    # The start header has a valid CRC and claims the ZIP as packed data.
    # Its next header also has a matching CRC, but an invalid type. That
    # structural failure must leave the inner ZIP available to discovery.
    payload = b"real ZIP behind an invalid 7z header"
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("real.txt", payload)
    zip_data = buffer.getvalue()
    invalid_next = b"\x7f"
    fields = struct.pack("<QQI", len(zip_data), len(invalid_next), zlib.crc32(invalid_next))
    fake = bytes.fromhex("377abcaf271c0004") + struct.pack("<I", zlib.crc32(fields)) + fields
    source = tmp_path / "false-header.图片"
    source.write_bytes(b"prefix" + fake + zip_data + invalid_next + b"suffix")
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, source, output, cleanup="d")
        assert report["summary"]["success_count"] == 1, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d")
        source = download(watch, source)
        watch.await_event("done", path=source.name)
        watch.stop()
        watch.assert_no_terminal_failures()
    leaf, = (path for path in output.rglob("*") if path.is_file())
    assert leaf.name == "real.txt" and leaf.read_bytes() == payload
    assert not source.exists()
