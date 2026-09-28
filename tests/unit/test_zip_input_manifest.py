import io
import os
import struct
import zipfile
import zlib

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from sunpack.pipeline.verification.archive_input_manifest import archive_input_manifest
from sunpack.pipeline.verification.methods._archive_output_match import coverage_from_native_inventory


def _zip_bytes(entries: dict[str, bytes], *, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def _input(path, **kwargs):
    return ArchiveInputDescriptor(entry_path=str(path), format_hint="zip", **kwargs)


def test_zip_manifest_streams_deflate_payload_crc(tmp_path):
    payload = os.urandom(3 * 1024 * 1024) + b"z" * (2 * 1024 * 1024)
    path = tmp_path / "large.zip"
    path.write_bytes(_zip_bytes({"dir/": b"", "dir/big.bin": payload, "small.txt": b"small"}))

    manifest = archive_input_manifest(_input(path))

    assert manifest.ok is True
    assert manifest.item_count == 3
    assert manifest.file_count == 2
    assert manifest.total_unpacked_size == len(payload) + len(b"small")
    assert manifest.expected_names == ["dir/big.bin", "small.txt"]
    first = manifest.entries.entry_page(0, 1)[0]
    assert first["has_crc"] is True
    assert first["crc32"] == zipfile.ZipFile(path).getinfo("dir/big.bin").CRC


def test_zip_manifest_detects_corrupted_stored_and_deflated_payloads(tmp_path):
    for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        data = bytearray(_zip_bytes({"a.txt": b"a" * 4096}, compression=compression))
        header_end = 30 + len("a.txt")
        data[header_end + 10] ^= 0xFF
        path = tmp_path / f"corrupt-{compression}.zip"
        path.write_bytes(bytes(data))

        manifest = archive_input_manifest(_input(path))

        assert manifest.damaged is True, compression
        assert manifest.checksum_error is True, compression
        assert "a.txt" in manifest.message


def test_zip_manifest_counts_all_files_beyond_retained_entry_limit(tmp_path):
    path = tmp_path / "many.zip"
    path.write_bytes(_zip_bytes({f"item-{index:03d}.txt": b"xy" for index in range(40)}))

    manifest = archive_input_manifest(_input(path), max_items=7)

    assert manifest.ok is True
    assert manifest.file_count == 40
    assert manifest.retained_file_count == 7
    assert manifest.entries_truncated is True
    assert manifest.total_unpacked_size == 80


def test_zip_manifest_finds_eocd_before_trailing_data_larger_than_search_window(tmp_path):
    path = tmp_path / "trailing.zip"
    path.write_bytes(_zip_bytes({"a.txt": b"payload"}) + b"\0" * (3 * 1024 * 1024 + 1))

    manifest = archive_input_manifest(_input(path))

    assert manifest.ok is True
    assert manifest.expected_names == ["a.txt"]


def test_zip_manifest_reads_carrier_range_and_split_concat_ranges(tmp_path):
    archive = _zip_bytes({"inner/one.txt": b"one" * 1000, "two.txt": b"two"})
    carrier = tmp_path / "carrier.bin"
    prefix = os.urandom(4099)
    carrier.write_bytes(prefix + archive + os.urandom(777))
    ranged = _input(
        carrier,
        open_mode="file_range",
        parts=[ArchiveInputPart(extent=InputExtent(str(carrier), len(prefix), len(prefix) + len(archive)))],
    )

    manifest = archive_input_manifest(ranged)

    assert manifest.ok is True
    assert manifest.expected_names == ["inner/one.txt", "two.txt"]

    split = len(archive) // 2
    first = tmp_path / "split.001"
    second = tmp_path / "split.002"
    first.write_bytes(archive[:split])
    second.write_bytes(archive[split:])
    concatenated = _input(
        first,
        open_mode="concat_ranges",
        extents=[InputExtent(str(first)), InputExtent(str(second))],
    )

    manifest = archive_input_manifest(concatenated)

    assert manifest.ok is True
    assert manifest.file_count == 2


def test_zip_manifest_without_eocd_is_damaged_zip_with_empty_table(tmp_path):
    data = _zip_bytes({"a.txt": b"payload"})
    path = tmp_path / "no-eocd.zip"
    path.write_bytes(data[: data.rindex(b"PK\x05\x06")])

    manifest = archive_input_manifest(_input(path))

    assert manifest.is_archive is True
    assert manifest.damaged is True
    assert manifest.retained_file_count == 0
    assert manifest.expected_names == []


def test_zip_manifest_view_matches_output_from_native_entries(tmp_path):
    entries = {"a.txt": b"aaa", "b/c.txt": b"ccc"}
    path = tmp_path / "match.zip"
    path.write_bytes(_zip_bytes(entries))
    out_dir = tmp_path / "out"
    (out_dir / "b").mkdir(parents=True)
    (out_dir / "a.txt").write_bytes(b"aaa")
    (out_dir / "b" / "c.txt").write_bytes(b"cXc")

    manifest = archive_input_manifest(_input(path))
    coverage, raw = coverage_from_native_inventory(
        manifest,
        collect_output_inventory(str(out_dir)),
        method="test",
        verify_crc=True,
    )

    assert coverage.expected_files == 2
    assert coverage.complete_files == 1
    assert raw["mismatch_count"] == 1
    assert raw["mismatches"][0]["path"] == "b/c.txt"


class _ZipCrypto:
    def __init__(self, password: bytes):
        self.keys = [0x12345678, 0x23456789, 0x34567890]
        for byte in password:
            self._update(byte)

    @staticmethod
    def _crc(value: int, byte: int) -> int:
        return zlib.crc32(bytes([byte]), value ^ 0xFFFFFFFF) ^ 0xFFFFFFFF

    def _update(self, byte: int) -> None:
        self.keys[0] = self._crc(self.keys[0], byte)
        self.keys[1] = ((self.keys[1] + (self.keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.keys[2] = self._crc(self.keys[2], self.keys[1] >> 24)

    def encrypt(self, data: bytes) -> bytes:
        output = bytearray()
        for byte in data:
            temp = (self.keys[2] | 2) & 0xFFFF
            output.append(byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
            self._update(byte)
        return bytes(output)


def _zipcrypto_zip(name: str, payload: bytes, password: bytes, *, deflate: bool, corrupt: bool = False) -> bytes:
    crc = zlib.crc32(payload)
    if deflate:
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        stored = compressor.compress(payload) + compressor.flush()
        method = 8
    else:
        stored, method = payload, 0
    header = os.urandom(11) + bytes([crc >> 24])
    encrypted = _ZipCrypto(password).encrypt(header + stored)
    if corrupt:
        encrypted = encrypted[:20] + bytes([encrypted[20] ^ 0xFF]) + encrypted[21:]
    raw_name = name.encode()
    local = struct.pack(
        "<4sHHHHHIIIHH", b"PK\x03\x04", 20, 1, method, 0, 0,
        crc, len(encrypted), len(payload), len(raw_name), 0,
    ) + raw_name + encrypted
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 1, method, 0, 0,
        crc, len(encrypted), len(payload), len(raw_name), 0, 0, 0, 0, 0, 0,
    ) + raw_name
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + eocd


def test_zipcrypto_manifest_verifies_decrypted_payload_crc(tmp_path):
    payload = b"zipcrypto payload " * 4096
    for deflate in (False, True):
        path = tmp_path / f"enc-{deflate}.zip"
        path.write_bytes(_zipcrypto_zip("secret.txt", payload, b"right", deflate=deflate))

        manifest = archive_input_manifest(_input(path), password="right")

        assert manifest.ok is True, (deflate, manifest.message)
        assert manifest.archive_walk_complete is True
        assert manifest.verified_item_count == 1


def test_zipcrypto_manifest_reports_wrong_password_instead_of_damage(tmp_path):
    path = tmp_path / "enc.zip"
    path.write_bytes(_zipcrypto_zip("secret.txt", b"payload" * 100, b"right", deflate=True))

    manifest = archive_input_manifest(_input(path), password="wrong")

    assert manifest.status == 1
    assert manifest.damaged is False
    assert manifest.checksum_error is False
    assert manifest.archive_walk_complete is False
    assert "password" in manifest.message


def test_zipcrypto_manifest_detects_corruption_after_decryption(tmp_path):
    path = tmp_path / "enc-corrupt.zip"
    path.write_bytes(_zipcrypto_zip("secret.txt", b"x" * 4096, b"right", deflate=False, corrupt=True))

    manifest = archive_input_manifest(_input(path), password="right")

    assert manifest.damaged is True
    assert manifest.checksum_error is True


def test_zipcrypto_manifest_without_password_keeps_entries_unchecked(tmp_path):
    path = tmp_path / "enc.zip"
    path.write_bytes(_zipcrypto_zip("secret.txt", b"payload", b"right", deflate=False))

    manifest = archive_input_manifest(_input(path))

    assert manifest.ok is True
    assert manifest.expected_names == ["secret.txt"]
