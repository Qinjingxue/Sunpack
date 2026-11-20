"""Archive records whose physical layout differs from their logical file tree."""

import io
import struct
import tarfile
import zipfile
import zlib

import pytest

from tests.helpers.real_archives import _NonSeekableZipWriter, run_cmd
from tests.real.archive_boundary import extract_report


def _files_under(root):
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*") if path.is_file()
    }


def test_zip64_stream_descriptors_with_reverse_central_directory(package, tmp_path):
    # An empty ZIP64 member's descriptor has the same initial bytes as a
    # classic descriptor. It is physically followed by another local record,
    # while the central directory points to the local records in reverse order.
    entries = {"first.txt": b"first local member", "empty.bin": b"", "last.txt": b"last local member"}
    writer = _NonSeekableZipWriter()
    with zipfile.ZipFile(writer, "w") as archive:
        for name, data in entries.items():
            with archive.open(name, "w", force_zip64=name == "empty.bin") as member:
                member.write(data)
        # zipfile has already written the local records and will serialize
        # the central directory from this list on close.
        archive.filelist.reverse()

    source = tmp_path / "streamed.zip"
    fixture = writer.buffer.getvalue()
    source.write_bytes(fixture)
    with zipfile.ZipFile(source) as reference:
        records = reference.infolist()
        assert [member.filename for member in records] == list(reversed(entries))
        assert all(member.flag_bits & 8 for member in records)
        last_local, empty_local, first_local = [member.header_offset for member in records]
        assert last_local > empty_local > first_local
        name_length, extra_length = struct.unpack_from("<HH", fixture, empty_local + 26)
        extra_start = empty_local + 30 + name_length
        descriptor_start = extra_start + extra_length
        assert fixture[extra_start:descriptor_start] == struct.pack("<HHQQ", 1, 16, 0, 0)
        assert fixture[descriptor_start:last_local] == b"PK\x07\x08" + bytes(20)
        assert {member.filename: reference.read(member) for member in records} == entries
    run_cmd([str(package.tools / "7z.exe"), "t", str(source)], tmp_path)

    output = tmp_path / "output"
    report = extract_report(package, source, output, recur="1", deep=False)
    assert report["summary"]["success_count"] == 1, report
    assert _files_under(output / source.stem) == entries


def test_zip_renamed_member_ignores_stale_unicode_path_extra_field(package, tmp_path):
    # A ZIP editor renamed one legacy header without updating its Unicode
    # path field. Following that stale field would alias two distinct files.
    unicode_name = "資料/説明.txt"
    original = "original.txt"
    renamed = "renamed.txt"
    unicode_path = struct.pack("<BI", 1, zlib.crc32(original.encode("ascii"))) + unicode_name.encode("utf-8")
    extra = struct.pack("<HH", 0x7075, len(unicode_path)) + unicode_path
    source = tmp_path / "names.zip"
    entries = {unicode_name: b"member with a current Unicode path", renamed: b"renamed legacy member"}
    with zipfile.ZipFile(source, "w") as archive:
        for legacy_name, data in zip((original, renamed), entries.values(), strict=True):
            member = zipfile.ZipInfo(legacy_name)
            member.extra = extra
            archive.writestr(member, data)

    # Verify the authored legacy names and payloads without asking the host's
    # tar to decode or create a Unicode path under its active code page.
    # The explicit expected tree below is the oracle for applying the extra.
    with zipfile.ZipFile(source) as raw_zip:
        records = raw_zip.infolist()
        assert [member.orig_filename for member in records] == [original, renamed]
        assert all(member.extra == extra for member in records)
        assert [raw_zip.read(member) for member in records] == list(entries.values())

    output = tmp_path / "output"
    report = extract_report(package, source, output, recur="1", deep=False)
    assert report["summary"]["success_count"] == 1, report
    assert _files_under(output / source.stem) == entries


@pytest.mark.parametrize(
    ("codec", "legacy_name"),
    [
        ("cp932", "操作手順.txt"),
        ("gbk", "数据.txt"),
        ("cp950", "財務報表.txt"),
        ("cp949", "한글똠.txt"),
    ],
)
def test_zip_guesses_legacy_filename_encoding(package, tmp_path, codec, legacy_name):
    class LegacyZipInfo(zipfile.ZipInfo):
        def _encodeFilenameFlags(self):
            return self.filename.encode(codec), self.flag_bits

    source = tmp_path / "legacy.zip"
    entries = {legacy_name: b"legacy name", "Unicode/例.txt": b"explicit UTF-8 name"}
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr(LegacyZipInfo(legacy_name), entries[legacy_name])
        archive.writestr("Unicode/例.txt", entries["Unicode/例.txt"])

    output = tmp_path / "output"
    report = extract_report(package, source, output, recur="1", deep=False)
    assert report["summary"]["success_count"] == 1, report
    assert _files_under(output / source.stem) == entries


def _old_gnu_sparse_tar(filename, trailer):
    # Old GNU TAR holds four pairs in the header and 21 pairs per extension.
    # A terminal zero-length extent preserves the trailing hole.
    block = 512
    count = 26
    chunks = [bytes([index + 1]) * block for index in range(count)]
    logical_size = (count * 2 + 2) * block
    extents = [((2 * index + 1) * block, block) for index in range(count)] + [(logical_size, 0)]
    expected = bytearray(logical_size)
    for (offset, length), data in zip(extents[:-1], chunks, strict=True):
        expected[offset:offset + length] = data

    def extent_bytes(pairs):
        return b"".join(f"{offset:011o}\0{length:011o}\0".encode("ascii") for offset, length in pairs)

    member = tarfile.TarInfo(filename)
    member.type = tarfile.GNUTYPE_SPARSE
    member.size = sum(map(len, chunks))
    header = bytearray(member.tobuf(format=tarfile.GNU_FORMAT))
    header[386:482] = extent_bytes(extents[:4])
    header[482] = 1
    header[483:495] = f"{logical_size:011o}\0".encode("ascii")
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")

    extension = extent_bytes(extents[4:25]) + b"\x01" + bytes(7)
    last_extension = extent_bytes(extents[25:]).ljust(block, b"\0")
    following = tarfile.TarInfo(trailer[0])
    following.size = len(trailer[1])
    tail = following.tobuf(format=tarfile.GNU_FORMAT) + trailer[1].ljust(block, b"\0")
    return bytes(header) + extension + last_extension + b"".join(chunks) + tail + bytes(2 * block), bytes(expected)


@pytest.mark.requires_watch_broker
def test_watch_extracts_gnu_sparse_tar_with_multiple_map_blocks(package, tmp_path):
    sparse_name = "sparse.bin"
    trailer = "following.txt", b"ordinary member after the sparse payload"
    archive, sparse_contents = _old_gnu_sparse_tar(sparse_name, trailer)
    entries = {sparse_name: sparse_contents, trailer[0]: trailer[1]}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reference:
        assert {member.name: reference.extractfile(member).read() for member in reference} == entries

    watched = tmp_path / "watched"
    watched.mkdir()
    source = tmp_path / "mapped.tar"
    source.write_bytes(archive)
    output = tmp_path / "output"
    package.configure(post_extract={"flatten_single_directory": False})
    package.json("watch", "add", watched, "-o", output)
    with package.watch_session():
        source.replace(watched / source.name)
        event = package.await_watch_event("done", "failed_terminal", path=source.name, root=watched)
    assert event["event"] == "done", event
    assert _files_under(output / source.stem) == entries
