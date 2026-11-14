"""Main's volume arbitration and recovery cases through the public runtime."""

import struct
from pathlib import Path
from zipfile import ZipFile

import pytest

from tests.helpers.native_fixture import assemble_carrier, assert_exact_tree
from tests.helpers.real_archives import create_encrypted_rar_archive, create_zip_multidisk_archive
from tests.real.archive_boundary import assert_extracted, extract_report, require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, download, wait_for, watch_setup,
)


WATCH = pytest.param("watch", marks=pytest.mark.requires_watch_broker)


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
@pytest.mark.parametrize("archive_format", ["7z", "zip"])
def test_competing_number_columns_choose_the_valid_complete_order(package, tmp_path, entry_mode, archive_format):
    # Both numeric columns describe contiguous sets, but one exchanges the
    # second and third volumes. Only the right ordering verifies all members.
    case = FACTORY.create(
        tmp_path / "fixtures", "columns", archive_format,
        split=True, payload_size=136 * 1024, split_volume_size=40 * 1024,
    )
    parts = sorted(case.archive_dir.iterdir())
    assert len(parts) == 4 and parts[1].stat().st_size == parts[2].stat().st_size
    for index, part in enumerate(parts, 1):
        alternative = {2: 3, 3: 2}.get(index, index)
        part.rename(part.with_name(f"shared.build{alternative}.chunk{index}.图片"))

    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, case.archive_dir, output, cleanup="d")
        assert report["summary"]["success_count"] == 1, report
        delivered = case.archive_dir
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d", recursive=True)
        delivered = case.archive_dir.rename(watch.root / case.archive_dir.name)
        wait_for(lambda: not any(delivered.iterdir()), "cleanup of the correctly ordered volume set")
        watch.stop()
        watch.assert_no_terminal_failures()
    assert_extracted(case, output, exact=True)
    assert not any(delivered.iterdir())


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_encrypted_rar_carrier_is_not_borrowed_as_same_size_7z_middle(package, tmp_path, entry_mode):
    require_generator("rar")
    fixtures = tmp_path / "fixtures"
    split = FACTORY.create(
        fixtures, "split", "7z", split=True, payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    secret = "independent-rar-key"
    peer = create_encrypted_rar_archive(
        fixtures, "independent", password=secret, header_encrypt=True, payload_size=4 * 1024,
    )
    head, middle, tail = sorted(split.archive_dir.iterdir())
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    assemble_carrier(inputs / "shared.jpg", [head], seed=51)
    middle = middle.rename(inputs / "shared.chunk2.z.opaque")
    tail.rename(inputs / "shared.chunk3.z.opaque")
    competitor = inputs / "shared.chunk2.a.opaque"
    assemble_carrier(competitor, [peer.entry_path], seed=52)
    # The competing input matches the slot, size and stem. Discovery must
    # preserve it as a standalone archive with its own password and output.
    data = competitor.read_bytes()
    assert len(data) < middle.stat().st_size
    competitor.write_bytes(data.ljust(middle.stat().st_size, b"!"))

    passwords = ["wrong", secret]
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, passwords=passwords, cleanup="d")
        assert report["summary"]["success_count"] == 2, report
    else:
        watch = watch_setup(package, tmp_path, passwords=passwords, cleanup="d", recursive=True)
        inputs = inputs.rename(watch.root / inputs.name)
        wait_for(lambda: not any(inputs.iterdir()), "cleanup of both independent archives")
        watch.stop()
        watch.assert_no_terminal_failures()
    parents = []
    for case in (split, peer):
        marker, = output.rglob(case.marker_name)
        assert_exact_tree(marker.parent, case.metadata["expected_files"])
        parents.append(marker.parent)
    assert parents[0] != parents[1]
    assert not any(inputs.iterdir())


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_rar_header_numbers_override_false_part_markers_in_mixed_directory(package, tmp_path, entry_mode):
    require_generator("rar")
    fixtures = tmp_path / "fixtures"
    cases = [
        FACTORY.create(fixtures, fmt, fmt, split=True,
                       payload_size=104 * 1024, split_volume_size=40 * 1024)
        for fmt in ("rar", "7z")
    ]
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for case in cases:
        parts = sorted(case.archive_dir.iterdir())
        assert len(parts) == 3
        for number, part in enumerate(parts, 1):
            if case.archive_format == "rar":
                # Reverse the only varying number. RAR has volume numbers
                # in its headers and must use those to recover the ordering.
                name = f"shared.alpha.part99.chunk{len(parts) + 1 - number}.图片"
            else:
                name = f"shared.beta.7z.chunk{number}.图片"
            part.rename(inputs / name)
    # A same-stem extra number beyond the last 7z volume must remain on disk.
    extra = inputs / "shared.beta.7z.chunk4.图片"
    extra.write_bytes(b"not a volume" * 4096)

    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, inputs, output, cleanup="d")
        assert report["summary"]["success_count"] == 2, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d", recursive=True)
        inputs = inputs.rename(watch.root / inputs.name)
        for case in cases:
            watch.await_archive(case)
        watch.stop()
        watch.assert_no_terminal_failures()
    for case in cases:
        marker, = output.rglob(case.marker_name)
        assert_exact_tree(marker.parent, case.metadata["expected_files"])
    assert {path.name: path.read_bytes() for path in inputs.iterdir()} == {extra.name: b"not a volume" * 4096}


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_password_retry_does_not_authorize_cleanup_of_carrier_with_damaged_peer(package, tmp_path, entry_mode):
    secret = "retry-one-segment"
    locked = FACTORY.create(tmp_path / "fixtures", "locked", "7z", password=secret, payload_size=8 * 1024)
    damaged = tmp_path / "damaged.zip"
    with ZipFile(damaged, "w") as archive:
        archive.writestr("damaged.txt", b"invalid CRC despite a complete ZIP structure")
    data = bytearray(damaged.read_bytes())
    name_len, extra_len = struct.unpack_from("<HH", data, 26)
    data[30 + name_len + extra_len] ^= 1
    damaged.write_bytes(data)
    carrier = tmp_path / "retry.图片"
    assemble_carrier(carrier, [locked.entry_path, damaged], seed=53)
    original = carrier.read_bytes()
    output = tmp_path / "out"
    package.configure(extraction={"content_requirement": "complete"})

    if entry_mode == "cli":
        result = package.run(
            "extract", "-d", "-r", "1", "-c", "d", "-o", output,
            "--no-bpw", "--no-pause", "-p", "wrong", carrier, input=f"y\n{secret}\n\n",
        )
        assert result.returncode == 1, (result.stdout, result.stderr)
    else:
        watch = watch_setup(package, tmp_path, passwords=["wrong"], cleanup="d")
        carrier = download(watch, carrier)
        watch.await_event("failed_password", path=carrier.name)
        assert not list(output.rglob(locked.marker_name))
        watch.passwords([secret])
        watch.await_archive(locked)
        watch.stop()
        failures = [row for row in watch.display()["history"] if row["event"] == "archive_failure_evidence"
                    and Path(row.get("path", "")) == carrier]
        assert any(row["failure"]["kind"] == "damaged" for row in failures), failures
    marker, = output.rglob(locked.marker_name)
    assert_exact_tree(marker.parent, locked.metadata["expected_files"])
    assert carrier.read_bytes() == original


@pytest.mark.parametrize("entry_mode", ["cli", WATCH])
def test_pkzip_terminal_disk_with_long_trailer_and_disguised_names(package, tmp_path, entry_mode):
    # Main's long-padding case puts the EOCD outside a normal ZIP tail read.
    # The terminal disk still has to join the existing local-data disks.
    case = create_zip_multidisk_archive(
        tmp_path / "fixtures", "padded", payload_size=104 * 1024, split_volume_size=40 * 1024,
    )
    parts = [path.rename(path.with_name(f"{path.name}.图片")) for path in case.metadata["volume_paths"]]
    head, middle, terminal = parts
    with terminal.open("ab") as disk:
        disk.write(b"x" * 100_000)
    output = tmp_path / "out"
    if entry_mode == "cli":
        report = extract_report(package, case.archive_dir, output, cleanup="d")
        assert report["summary"]["success_count"] == 1, report
    else:
        watch = watch_setup(package, tmp_path, passwords=[], cleanup="d")
        arrived_head = download(watch, head)
        arrived_middle = download(watch, middle)
        watch.await_event("suspended_missing_volume", path=arrived_head.name)
        assert arrived_head.is_file() and arrived_middle.is_file()
        parts = [arrived_head, arrived_middle, download(watch, terminal, mode="direct")]
        watch.await_archive(case)
        watch.stop()
        watch.assert_no_terminal_failures()
    assert_extracted(case, output, exact=True)
    assert not any(path.exists() for path in parts)
