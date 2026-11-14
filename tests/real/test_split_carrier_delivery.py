"""Exercise volume relationships and the real entry points together."""

from pathlib import Path
from shutil import copyfile
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from tests.helpers.marker_utils import marker_present, open_shared_file
from tests.helpers.native_fixture import assemble_carrier, file_inventory
from tests.helpers.real_archives import create_zip_multidisk_archive
from tests.real.archive_boundary import extract_report, require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    DOWNLOAD_CHUNK_SIZE, FACTORY, assert_once, download, download_interleaved, wait_for, watch_setup,
)


def _wrap_volume(volume, directory, index, *before):
    target = directory / f"{volume.name}.图片"
    assemble_carrier(target, [*before, volume], seed=50 + index)
    return target


def _carrier_batch(base, *, wrap_all_rar_volumes):
    fixtures = base / "fixtures"
    batch = base / "交付"
    batch.mkdir()
    cases = [
        FACTORY.create(
            fixtures, f"batch-{fmt}", fmt, password=f"key-{fmt}", split=True,
            payload_size=104 * 1024, split_volume_size=40 * 1024,
        )
        for fmt in ("7z", "rar")
    ]
    sibling_dir = fixtures / "expected-sibling"
    sibling_dir.mkdir()
    leaf = sibling_dir / "叶子.txt"
    leaf.write_bytes(b"nested beside the split head")
    child = fixtures / "child.opaque"
    with ZipFile(child, "w") as archive:
        archive.write(leaf, leaf.name)
    sibling = fixtures / "sibling.zip"
    with ZipFile(sibling, "w", compression=ZIP_DEFLATED) as archive:
        archive.write(child, child.name)

    parts = []
    for case in cases:
        volumes = sorted(case.archive_dir.iterdir())
        assert len(volumes) == 3 and volumes[0] == case.entry_path
        group = []
        for index, volume in enumerate(volumes):
            if index == 0 or (wrap_all_rar_volumes and case.archive_format == "rar"):
                # RAR members carry their own structure; the 7z continuation
                # disks are raw byte ranges. Place an independent ZIP before
                # the 7z head to test both logical inputs sharing that file.
                before = (sibling,) if case.archive_format == "7z" else ()
                target = _wrap_volume(volume, batch, index, *before)
            else:
                target = batch / f"{volume.name}.图片"
                copyfile(volume, target)
            group.append(target)
        parts.append(group)
    # Interleave the families and send the two heads at different positions.
    arrivals = [part for pair in zip(parts[0], reversed(parts[1]), strict=True) for part in pair]
    unrelated = batch / "batch-7z.notes.txt"
    unrelated.write_bytes(b"same stem, not a member")
    return cases, batch, arrivals, unrelated, file_inventory(sibling_dir)


def _assert_only_payloads(output, cases, extra):
    # Normalize away allocation/flattening of the outer task directories.
    # Count each expected member once, including the non-marker binary data.
    actual = file_inventory(output)
    for case in cases:
        marker, = output.rglob(case.marker_name)
        for name, contents in case.metadata["expected_files"].items():
            path = (marker.parent / name).relative_to(output).as_posix()
            assert actual.pop(path, None) == contents, path
    assert {Path(path).name: value for path, value in actual.items()} == extra
    assert len(actual) == len(extra), actual


@pytest.mark.parametrize("delivery", [
    "cli",
    pytest.param("rename", marks=pytest.mark.requires_watch_broker),
    pytest.param("direct", marks=pytest.mark.requires_watch_broker),
    pytest.param("move-tree", marks=pytest.mark.requires_watch_broker),
])
def test_mixed_split_carriers_extract_and_clean_only_selected_sources(package, tmp_path, delivery):
    # The nested sibling shares the 7z head's lifetime while an independent
    # family with a different key is in flight. For complete snapshots also
    # require correct offsets inside each RAR carrier.
    require_generator("rar")
    cases, batch, parts, unrelated, extra = _carrier_batch(
        tmp_path, wrap_all_rar_volumes=delivery in {"cli", "move-tree"},
    )
    passwords = ["wrong-key", *(case.password for case in cases)]
    package.configure(filesystem={"scan_filters_enabled": False}, recursive_authorization={"enabled": False})
    output = tmp_path / "out"
    if delivery == "cli":
        report = extract_report(package, batch, output, passwords=passwords, cleanup="d")
        assert report["summary"]["failed_count"] == report["summary"]["partial_success_count"] == 0, report
        live_parts = parts
    else:
        watch = watch_setup(package, tmp_path, passwords=passwords, cleanup="d", recursive=delivery == "move-tree")
        if delivery == "move-tree":
            target = batch.rename(watch.root / batch.name)
            live_parts = [target / part.name for part in parts]
            unrelated = target / unrelated.name
        else:
            unrelated = unrelated.rename(watch.root / unrelated.name)
            live_parts = download_interleaved(watch, parts, mode=delivery)
        wait_for(lambda: not any(path.exists() for path in live_parts), "cleanup of all selected carrier volumes")
        watch.stop()
        watch.assert_no_terminal_failures()

    _assert_only_payloads(output, cases, extra)
    assert not any(path.exists() for path in live_parts)
    assert unrelated.read_bytes() == b"same stem, not a member"


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("delivery", ["append-after-restart", "discard-and-rename", "preallocate"])
def test_watch_recovers_when_the_final_pkzip_disk_finishes(package, tmp_path, delivery):
    # The final PKZIP disk contains the central directory, unlike a raw
    # numbered ZIP tail. Its pathname appears before those bytes are available.
    password = "final-disk-key"
    case = create_zip_multidisk_archive(
        tmp_path / "fixtures", "final-disk", password=password, encryption="AES256",
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    parts = [part.rename(part.with_name(f"{part.name}.图片")) for part in case.metadata["volume_paths"]]
    package.configure(filesystem={"scan_filters_enabled": False})
    watch = watch_setup(package, tmp_path, passwords=["wrong-key", password])
    # Two completed disks arrive through different write modes in one family.
    assert len(parts) == 3
    download(watch, parts[1], mode="direct")
    head = download(watch, parts[0])
    watch.await_event("suspended_missing_volume", path=head.name)
    final = watch.root / parts[-1].name
    if delivery == "preallocate":
        # Reaching the final size is not evidence of completeness. Watch
        # observes the file while the downloader still owns the write handle.
        with open_shared_file(final, "wb") as writer:
            writer.truncate(parts[-1].stat().st_size)
            watch.await_event("candidate_busy", path=final.name)
            assert not marker_present(watch.output, case.marker_name)
            writer.write(parts[-1].read_bytes())
    else:
        download(watch, parts[-1], mode="direct", interrupt=True)
        assert 0 < final.stat().st_size < parts[-1].stat().st_size
        identity = final.stat().st_ino
        watch.await_event("candidate_active", path=final.name)
        assert not marker_present(watch.output, case.marker_name)
        if delivery == "append-after-restart":
            watch.restart()
            assert not marker_present(watch.output, case.marker_name)
            download(watch, parts[-1], mode="direct", resume=True)
            assert final.stat().st_ino == identity
        else:
            # Keep the abandoned partial so Windows cannot reuse its file ID.
            final.rename(tmp_path / "abandoned-disk")
            download(watch, parts[-1])
            assert final.stat().st_ino != identity

    watch.await_archive(case)
    watch.await_event("done", path=head.name)
    watch.stop()
    assert_once(watch, case)
    watch.assert_no_terminal_failures()
    assert all((watch.root / part.name).read_bytes() == part.read_bytes() for part in parts)


@pytest.mark.parametrize("target_disk", [0, 2])
def test_cli_single_wrapped_rar_member_restores_family_and_peer_sibling(package, tmp_path, target_disk):
    require_generator("rar")
    case = FACTORY.create(
        tmp_path / "fixtures", "wrapped", "rar", password="wrapped-key", split=True,
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    parts = sorted(case.archive_dir.iterdir())
    assert len(parts) == 3
    carriers = tmp_path / "carriers"
    carriers.mkdir()
    sibling = tmp_path / "sibling.zip"
    with ZipFile(sibling, "w") as archive:
        archive.writestr("peer-sibling.txt", b"independent payload in a related carrier")
    wrapped = [
        _wrap_volume(part, carriers, index, *((sibling,) if index == 1 else ()))
        for index, part in enumerate(parts)
    ]
    unrelated = carriers / "wrapped.notes.bin"
    with ZipFile(unrelated, "w") as archive:
        archive.writestr("unrelated.txt", b"not a requested archive")
    original = unrelated.read_bytes()
    output = tmp_path / "out"
    package.configure(filesystem={"scan_filters_enabled": False})
    report = extract_report(package, wrapped[target_disk], output, passwords=[case.password], cleanup="d")
    assert report["summary"]["failed_count"] == report["summary"]["partial_success_count"] == 0, report
    assert marker_present(output, case.marker_name)
    peer, = output.rglob("peer-sibling.txt")
    assert peer.read_bytes() == b"independent payload in a related carrier"
    assert not list(output.rglob("unrelated.txt"))
    assert unrelated.read_bytes() == original
    assert not any(path.exists() for path in wrapped)


@pytest.mark.parametrize("sibling_format,head_first", [("7z", True), ("rar", True), ("rar", False)],
                         ids=["mixed-formats", "same-format-head-first", "same-format-member-first"])
def test_cli_wrapped_member_preserves_split_sibling_on_shared_peer(package, tmp_path, sibling_format, head_first):
    require_generator("rar")
    cases = [FACTORY.create(
        tmp_path / "fixtures", f"wrapped.{name}", fmt, password=f"key-{name}", split=True,
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    ) for name, fmt in (("a", "rar"), ("b", sibling_format))]
    parts = [sorted(case.archive_dir.iterdir()) for case in cases]
    assert all(len(group) == 3 for group in parts)
    carriers = tmp_path / "carriers"
    carriers.mkdir()
    first = []
    for index, part in enumerate(parts[0]):
        target = carriers / f"{part.name}.图片"
        members = [parts[1][0], part] if index == 1 else [part]
        if index == 1 and not head_first:
            members.reverse()
        assemble_carrier(target, members, seed=50 + index)
        first.append(target)
    if sibling_format == "rar":
        second = [_wrap_volume(part, carriers, index + 3) for index, part in enumerate(parts[1][1:])]
    else:
        second = [carriers / part.name for part in parts[1][1:]]
        for source, target in zip(parts[1][1:], second, strict=True):
            copyfile(source, target)
    output = tmp_path / "out"
    package.configure(filesystem={"scan_filters_enabled": False})
    report = extract_report(package, first[0], output, passwords=[case.password for case in cases], cleanup="d")
    assert report["summary"]["failed_count"] == report["summary"]["partial_success_count"] == 0, report
    for case in cases:
        assert marker_present(output, case.marker_name)
    assert not any(path.exists() for path in [*first, *second])


@pytest.mark.requires_watch_broker
def test_watch_embedded_rar_tail_before_head_is_retried(package, tmp_path):
    require_generator("rar")
    case = FACTORY.create(
        tmp_path / "fixtures", "wrapped", "rar", password="wrapped-key", split=True,
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    parts = sorted(case.archive_dir.iterdir())
    assert len(parts) == 3 and parts[0] == case.entry_path
    carriers = tmp_path / "carriers"
    carriers.mkdir()
    wrapped = [_wrap_volume(part, carriers, index) for index, part in enumerate(parts)]

    watch = watch_setup(package, tmp_path, passwords=["wrong-key", case.password], cleanup="d", start=False)
    tail = download(watch, wrapped[-1], mode="direct")
    package.json("watch", "start", "--once", "--no-tray")
    watch.assert_no_terminal_failures()
    assert tail.read_bytes() == wrapped[-1].read_bytes()
    assert not marker_present(watch.output, case.marker_name)
    watch.start()
    # Publish the head last, after the other two files are complete. A missing
    # result for the head can no longer be attributed to a partial download.
    middle = download(watch, wrapped[1])
    head = download(watch, wrapped[0])
    watch.await_archive(case)
    watch.stop()
    watch.assert_no_terminal_failures()
    assert_once(watch, case)
    assert not any(path.exists() for path in (head, middle, tail))


@pytest.mark.requires_watch_broker
def test_watch_does_not_borrow_split_members_from_another_root(package, tmp_path):
    # Each root has a valid view of the same stem, but a different relation
    # scope. The misplaced disk must not unlock the head until it moves in.
    case = FACTORY.create(
        tmp_path / "fixtures", "scoped", "7z", split=True,
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    head, middle, tail = sorted(case.archive_dir.iterdir())
    watch = watch_setup(package, tmp_path, passwords=[], cleanup="d", recursive=True, start=False)
    other = tmp_path / "other-watch"
    other.mkdir()
    other_out = tmp_path / "other-out"
    package.json("watch", "add", "-d", other, "-o", other_out)
    watch.start()
    misplaced = download(watch, middle, directory=other)
    download(watch, tail, directory=watch.root / "tails")
    delivered_head = download(watch, head)
    watch.await_event("suspended_missing_volume", path=delivered_head.name)
    assert misplaced.read_bytes() == middle.read_bytes()
    assert delivered_head.read_bytes() == head.read_bytes()
    assert not marker_present(watch.output, case.marker_name)

    # An existing file moves across the boundary; there is no new file write
    # to wake the head's retry. The destination is a different subdirectory.
    misplaced.rename(watch.root / "tails" / middle.name)
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)
    assert not marker_present(other_out, case.marker_name)
    assert not any(watch.root.rglob("*.7z.*"))
    watch.assert_no_terminal_failures()


def test_cli_split_carrier_falls_back_to_valid_middle_volume_without_deleting_decoy(package, tmp_path):
    # Both middle candidates have the expected length and slot number. Only
    # member verification distinguishes them after volume planning succeeds.
    case = FACTORY.create(
        tmp_path / "fixtures", "fallback", "7z", password="fallback-key", split=True,
        payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    head, middle, tail = sorted(case.archive_dir.iterdir())
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    head = _wrap_volume(head, inputs, 0)
    correct = inputs / f"{middle.name}.图片"
    copyfile(middle, correct)
    delivered_tail = inputs / tail.name
    copyfile(tail, delivered_tail)
    damaged = bytearray(middle.read_bytes())
    damaged[len(damaged) // 2] ^= 0xFF
    decoy = inputs / middle.name
    decoy.write_bytes(damaged)
    output = tmp_path / "out"

    report = extract_report(package, head, output, passwords=["wrong-key", case.password], cleanup="d")
    assert report["summary"]["success_count"] == 1, report
    _assert_only_payloads(output, [case], {})
    assert not any(path.exists() for path in (head, correct, delivered_tail))
    assert decoy.read_bytes() == damaged


@pytest.mark.requires_watch_broker
def test_watch_direct_rar_sfx_head_waits_for_its_writer(package, tmp_path):
    # This executable is the first data volume itself. Unlike a separate 7z
    # SFX launcher, its presence is insufficient while the writer is open.
    require_generator("rar", sfx=True)
    case = FACTORY.create(
        tmp_path / "fixtures", "sfx-head", "rar", password="sfx-key", sfx=True, split=True,
        payload_size=120 * 1024, split_volume_size=48 * 1024,
    )
    head = case.entry_path
    tails = sorted(path for path in case.archive_dir.iterdir() if path != head)
    assert head.suffix == ".exe" and len(tails) >= 2
    watch = watch_setup(package, tmp_path, passwords=["wrong-key", case.password], cleanup="d")
    dest = watch.root / head.name
    with head.open("rb") as reader, open_shared_file(dest, "wb") as writer:
        writer.write(reader.read(DOWNLOAD_CHUNK_SIZE))
        writer.flush()
        delivered = download_interleaved(watch, reversed(tails))
        watch.await_event("candidate_busy", path=head.name)
        assert not watch.event("pipeline_request_started", path=head.name)
        assert all(path.is_file() for path in delivered)
        assert not marker_present(watch.output, case.marker_name)
        writer.write(reader.read())

    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)
    assert not any(path.exists() for path in [dest, *delivered])
    watch.assert_no_terminal_failures()
