"""A recoverable member prefix does not prove whole-archive completion."""
from io import BytesIO
import tarfile
from zipfile import ZipFile

import pytest

from tests.helpers.real_archives import run_cmd
from tests.helpers.tool_config import get_optional_rar
from tests.real.archive_boundary import assert_extracted, extract_report, failure_kinds, require_generator
from tests.real.plan7_watch_downloads.plan7_support import FACTORY, wait_for, watch_setup


def _zip(name, data):
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


def _appendable_zip(path):
    old = _zip("one.txt", b"one")
    path.write_bytes(old)
    with ZipFile(path, "a") as archive:
        # Preserve the old directory to model an append-only writer.
        archive.fp.seek(0, 2)
        archive.start_dir = archive.fp.tell()
        archive.writestr("two.txt", b"two" * 64 * 1024)
    return path.read_bytes(), len(old)


def _tar(path):
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in [("one.txt", b"one"), ("two.txt", b"two")]:
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            if name == "two.txt":
                member.pax_headers = {"mtime": "1700000000.25"}
                next_header = archive.offset
            archive.addfile(member, BytesIO(payload))
    # End inside the PAX extension block, before the actual member header.
    return path.read_bytes(), next_header + 512 + 84


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("format,deep", [("zip", False), ("zip", True), ("tar", False), ("rar", False)])
def test_watch_does_not_publish_or_cleanup_structurally_truncated_archive(package, tmp_path, format, deep):
    name = f"item.{format}"
    fixture = tmp_path / name
    if format == "zip":
        full, boundary = _appendable_zip(fixture)
        cut = boundary + (10 if deep else 80 * 1024)
        expected = {"one.txt": b"one", "two.txt": b"two" * 64 * 1024}
    elif format == "tar":
        full, cut = _tar(fixture)
        expected = {"one.txt": b"one", "two.txt": b"two"}
    else:
        require_generator("rar")
        case = FACTORY.create(tmp_path / "fixtures", "archive", "rar", payload_size=8 * 1024)
        full = case.entry_path.read_bytes()
        assert full.startswith(b"Rar!\x1a\x07\x01\0")
        cut = len(full) - 1
        expected = None

    watch = watch_setup(package, tmp_path, cleanup="d", passwords=[], deep=deep)
    source = watch.root / name
    staged = tmp_path / "incoming"
    staged.write_bytes(full[:cut])
    staged.replace(source)
    try:
        failure = package.await_watch_event("failed_terminal", path=name)
        assert failure.get("error_kind") == "damaged", failure
        assert source.is_file()
        assert not any(p.is_file() for p in watch.output.rglob("*"))
        with source.open("ab") as output:
            output.write(full[cut:])
        wait_for(lambda: not source.exists(), "delivery and cleanup after append")
        if expected is None:
            assert_extracted(case, watch.output, exact=True)
            return
        actual = {}
        for path in watch.output.rglob("*"):
            if path.is_file():
                assert path.name not in actual
                actual[path.name] = path.read_bytes()
        assert actual == expected
    finally:
        watch.stop()


def test_zip_carrier_independent_ranges_still_deliver(package, tmp_path):
    left = _zip("left.txt", b"left")
    right = _zip("right.txt", b"right")
    # At the root start, a complete adjacent ZIP must be treated as a peer.
    adjacent = tmp_path / "adjacent.bin"
    adjacent.write_bytes(left + right + b"trailing data")
    # A carrier suffix that merely starts with ZIP magic must not trigger a
    # block. The following fixed header is deliberately not plausible.
    collision = tmp_path / "collision.bin"
    collision.write_bytes(b"carrier prefix" + _zip("solo.txt", b"solo") + b"PK\x03\x04" + b"\xff" * 40)
    output = tmp_path / "out"
    for carrier in (adjacent, collision):
        report = extract_report(package, carrier, output, deep=True)
        assert report["summary"]["failed_count"] == 0, report
    assert {p.name: p.read_bytes() for p in output.rglob("*") if p.is_file()} == {
        "left.txt": b"left", "right.txt": b"right", "solo.txt": b"solo",
    }


@pytest.mark.parametrize("version", [4, 5])
def test_rar_rejects_prefix_with_evidence_of_missing_bytes(package, tmp_path, version):
    require_generator("rar")
    first = b"first stored member\n" * 64
    second = b"second stored member\n" * 64
    (tmp_path / "a.bin").write_bytes(first)
    (tmp_path / "z.bin").write_bytes(second)
    archive = tmp_path / "fixture.rar"
    quick_open = ["-qo+"] if version == 5 else []
    run_cmd([
        str(get_optional_rar()), "a", "-ep", "-idq", "-m0", f"-ma{version}", *quick_open,
        str(archive), "a.bin", "z.bin",
    ], tmp_path)
    full = archive.read_bytes()
    start = full.index(first)
    assert start < full.index(second)
    # RAR4 has a short member header. RAR5 has the whole member, but the
    # main header locates a later quick-open service record beyond the cut.
    cut = start - 1 if version == 4 else start + len(first)
    source = tmp_path / "archive.data"
    source.write_bytes(full[:cut])
    output = tmp_path / "out"
    report = extract_report(package, source, output, deep=False, cleanup="d", code=1)
    assert failure_kinds(report) == {"damaged"}, report
    assert source.is_file()
    assert not any(path.is_file() for path in output.rglob("*"))

    if version == 5:
        package.configure(extraction={"content_requirement": "allow_partial"})
        salvage = tmp_path / "salvage"
        report = extract_report(package, source, salvage, deep=False, cleanup="d", code=(0, 4))
        assert report["summary"]["partial_success_count"] == 1, report
        assert report["summary"]["success_count"] == 0, report
        assert failure_kinds(report) == {"damaged"}, report
        assert source.is_file()
        assert {path.name: path.read_bytes() for path in salvage.rglob("*") if path.is_file()} == {
            "a.bin": first,
        }
        package.configure(extraction={"content_requirement": "complete"})

    with source.open("ab") as writer:
        writer.write(full[cut:])
    report = extract_report(package, source, output, deep=False, cleanup="d")
    assert report["summary"]["success_count"] == 1, report
    assert not source.exists()
    assert {path.name: path.read_bytes() for path in output.rglob("*") if path.is_file()} == {
        "a.bin": first, "z.bin": second,
    }



def test_clean_tar_member_boundary_does_not_require_zero_blocks(package, tmp_path):
    source = tmp_path / "no-marker.tar"
    payload = b"complete member"
    member = tarfile.TarInfo("complete.txt")
    member.size = len(payload)
    source.write_bytes(member.tobuf() + payload + bytes(-len(payload) % 512))
    output = tmp_path / "out"
    report = extract_report(package, source, output, deep=False)
    assert report["summary"]["success_count"] == 1, report
    assert [p.read_bytes() for p in output.rglob("complete.txt")] == [payload]
