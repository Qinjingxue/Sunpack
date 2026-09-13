import struct
from binascii import crc32
from types import SimpleNamespace

from sunpack.analysis.view import MultiVolumeBinaryView
from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.modules.format_structure import rar as rar_processor
from sunpack.detection.pipeline.processors.modules.format_structure.rar import process_rar_structure
from sunpack.detection.pipeline.processors.modules.format_structure import seven_zip as seven_zip_processor
from sunpack.detection.pipeline.processors.modules.format_structure.seven_zip import process_seven_zip_structure
from sunpack.detection.pipeline.processors.modules.format_structure.zip_eocd import process_zip_eocd_structure


def _context(paths, style, output_fact):
    bag = FactBag()
    bag.set("file.path", str(paths[0]))
    bag.set("candidate.member_paths", [str(path) for path in paths])
    bag.set("relation.split_volumes", [
        {"path": str(path), "number": index + 1, "style": style}
        for index, path in enumerate(paths)
    ])
    return FactProcessorContext(bag, output_fact, {}, {}, None)


def _seven_zip_bytes():
    next_header = b"\x01\x00"
    start_header = struct.pack("<QQI", 0, len(next_header), crc32(next_header) & 0xFFFFFFFF)
    return b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", crc32(start_header) & 0xFFFFFFFF) + start_header + next_header


def _rar4_block(header_type, flags=0):
    body = bytes([header_type]) + struct.pack("<HH", flags, 7)
    return struct.pack("<H", crc32(body) & 0xFFFF) + body


def _fake_probe_result(**values):
    return SimpleNamespace(to_raw_dict=lambda: dict(values))


def test_rar_single_input_magic_miss_skips_strict_probe(tmp_path, monkeypatch):
    part = tmp_path / "ordinary.bin"
    part.write_bytes(b"ordinary data")
    context = _context([part], "", "rar.structure")
    context.fact_bag.set("file.magic_bytes", b"ordinary-data")

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("RAR strict probe should be skipped after a definite magic miss")

    monkeypatch.setattr(rar_processor, "ArchiveAnalyzer", fail_if_called)

    result = process_rar_structure(context)

    assert result == {
        "magic_matched": False,
        "plausible": False,
        "strong_accept": False,
        "detected_ext": "",
        "confidence": "none",
        "error": "bad_signature",
        "evidence": [],
        "damage_flags": [],
    }


def test_seven_zip_single_input_magic_miss_skips_strict_probe(tmp_path, monkeypatch):
    part = tmp_path / "ordinary.bin"
    part.write_bytes(b"ordinary data")
    context = _context([part], "", "7z.structure")
    context.fact_bag.set("file.magic_bytes", b"ordinary-data")

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("7z strict probe should be skipped after a definite magic miss")

    monkeypatch.setattr(seven_zip_processor, "ArchiveAnalyzer", fail_if_called)

    result = process_seven_zip_structure(context)

    assert result["magic_matched"] is False
    assert result["plausible"] is False
    assert result["strong_accept"] is False
    assert result["error"] == "bad_signature"


def test_rar_multi_input_magic_miss_keeps_strict_probe(tmp_path, monkeypatch):
    parts = [tmp_path / "part.001", tmp_path / "part.002"]
    for part in parts:
        part.write_bytes(b"ordinary data")
    context = _context(parts, "numeric_suffix", "rar.structure")
    context.fact_bag.set("file.magic_bytes", b"ordinary-data")
    calls = []

    class FakeAnalyzer:
        def __init__(self, *_args, **_kwargs):
            calls.append("init")

        def probe_rar(self, *_args, **_kwargs):
            calls.append("probe")
            return _fake_probe_result(plausible=False, strong_accept=False)

    monkeypatch.setattr(rar_processor, "ArchiveAnalyzer", FakeAnalyzer)

    result = process_rar_structure(context)

    assert calls == ["init", "probe"]
    assert result == {"plausible": False, "strong_accept": False}


def test_seven_zip_short_magic_keeps_strict_probe(tmp_path, monkeypatch):
    part = tmp_path / "short.bin"
    part.write_bytes(b"short")
    context = _context([part], "", "7z.structure")
    context.fact_bag.set("file.magic_bytes", b"short")
    calls = []

    class FakeAnalyzer:
        def __init__(self, *_args, **_kwargs):
            calls.append("init")

        def probe_seven_zip(self, *_args, **_kwargs):
            calls.append("probe")
            return _fake_probe_result(plausible=False, strong_accept=False)

    monkeypatch.setattr(seven_zip_processor, "ArchiveAnalyzer", FakeAnalyzer)

    result = process_seven_zip_structure(context)

    assert calls == ["init", "probe"]
    assert result == {"plausible": False, "strong_accept": False}


def test_seven_zip_detection_reads_next_header_from_later_volume(tmp_path):
    archive = _seven_zip_bytes()
    parts = [tmp_path / "a.7z.001", tmp_path / "a.7z.002"]
    parts[0].write_bytes(archive[:32])
    parts[1].write_bytes(archive[32:])

    result = process_seven_zip_structure(_context(parts, "numeric_suffix", "7z.structure"))

    assert result["plausible"] is True
    assert result["strong_accept"] is True
    assert result["next_header_semantic_ok"] is True
    assert result["password_required"] is False
    assert result["password_state"] == "not_required"
    assert result["encryption_scan_complete"] is True


def test_seven_zip_detection_preserves_magic_for_truncated_logical_volume(tmp_path):
    part = tmp_path / "missing.7z.001"
    part.write_bytes(b"7z\xbc\xaf\x27\x1cpartial")

    result = process_seven_zip_structure(_context([part], "numeric_suffix", "7z.structure"))

    assert result["magic_matched"] is True
    assert result["plausible"] is False
    assert result["error"] in {"file_too_small", "unsupported_version"}


def test_rar_detection_walks_blocks_across_raw_volume_boundary(tmp_path):
    archive = b"Rar!\x1a\x07\x00" + _rar4_block(0x73) + _rar4_block(0x7B)
    parts = [tmp_path / "a.rar.001", tmp_path / "a.rar.002"]
    parts[0].write_bytes(archive[:14])
    parts[1].write_bytes(archive[14:])

    result = process_rar_structure(_context(parts, "numeric_suffix", "rar.structure"))

    assert result["plausible"] is True
    assert result["strong_accept"] is True
    assert result["block_walk_ok"] is True


def test_rar4_header_encryption_is_accepted_by_rust_probe(tmp_path):
    # RAR4 -hp leaves the plaintext main header and marks every following
    # header as encrypted.  The following bytes are ciphertext and must not
    # be interpreted as another RAR block.
    archive = (
        b"Rar!\x1a\x07\x00"
        + _rar4_block(0x73, flags=0x0080)
        + b"\xd6\xd3\x77\xb9\xf7\x5d\xe8"
    )
    part = tmp_path / "encrypted.rar.001"
    part.write_bytes(archive)

    result = process_rar_structure(_context([part], "numeric_suffix", "rar.structure"))

    assert result["magic_matched"] is True
    assert result["header_crc_ok"] is True
    assert result["header_encrypted"] is True
    assert result["password_required"] is True
    assert result["strong_accept"] is True
    assert result["block_walk_ok"] is True
    assert result["error"] == ""


def test_zip_detection_finds_directory_and_eocd_in_later_volume(tmp_path):
    name = b"a"
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, 0, 0, 0, 1, 0) + name
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0,
    ) + name
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    parts = [tmp_path / "a.zip.0000", tmp_path / "a.zip.0001"]
    parts[0].write_bytes(local + central[:5])
    parts[1].write_bytes(central[5:] + eocd)

    result = process_zip_eocd_structure(_context(parts, "zip_zero_numbered", "zip.eocd_structure"))

    assert result["plausible"] is True
    assert result["archive_starts_at_zero"] is True
    assert result["archive_start_kind"] == "local_header"
    assert result["central_directory_walk_ok"] is True
    assert result["local_header_links_ok"] is True
    assert result["password_required"] is False
    assert result["password_state"] == "not_required"
    assert result["encryption_scan_complete"] is True


def test_zip_detection_accepts_spanned_split_marker_at_logical_zero(tmp_path):
    marker = b"PK\x07\x08"
    name = b"a"
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, 0, 0, 0, 1, 0) + name
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, len(marker),
    ) + name
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 1, 1, 1, 1, len(central), 0, 0)
    parts = [tmp_path / "a.z01", tmp_path / "a.zip"]
    parts[0].write_bytes(marker + local)
    parts[1].write_bytes(central + eocd)

    result = process_zip_eocd_structure(_context(parts, "zip_spanned", "zip.eocd_structure"))

    assert result["plausible"] is True
    assert result["is_multi_disk"] is True
    assert result["archive_starts_at_zero"] is True
    assert result["archive_start_kind"] == "split_marker"


def test_zip_detection_accepts_empty_eocd_at_logical_zero(tmp_path):
    part = tmp_path / "empty.zip"
    part.write_bytes(struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0))

    result = process_zip_eocd_structure(_context([part], "", "zip.eocd_structure"))

    assert result["plausible"] is True
    assert result["archive_starts_at_zero"] is True
    assert result["archive_start_kind"] == "empty_eocd"


def test_zip_start_probe_reuses_multivolume_native_reader_cache(tmp_path):
    part = tmp_path / "cached.zip"
    part.write_bytes(b"PK\x03\x04payload")

    with MultiVolumeBinaryView([part], cache_bytes=1024) as view:
        first = dict(view._native.probe_zip_archive_start(False, False, None))
        first_stats = view.stats()
        second = dict(view._native.probe_zip_archive_start(False, False, None))
        second_stats = view.stats()

    assert first == second == {
        "archive_starts_at_zero": True,
        "archive_start_kind": "local_header",
    }
    assert first_stats.read_bytes == 8
    assert second_stats.read_bytes == first_stats.read_bytes
    assert second_stats.cache_hits == first_stats.cache_hits + 1


def test_zip_detection_does_not_treat_prefixed_absolute_offsets_as_zero_start(tmp_path):
    prefix = b"MZ" + (b"\x00" * 30)
    name = b"a"
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, 0, 0, 0, 1, 0) + name
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, len(prefix),
    ) + name
    eocd = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1,
        len(central), len(prefix) + len(local), 0,
    )
    part = tmp_path / "application.exe"
    part.write_bytes(prefix + local + central + eocd)

    result = process_zip_eocd_structure(_context([part], "", "zip.eocd_structure"))

    assert result["plausible"] is True
    assert result["archive_offset"] == 0
    assert result["archive_starts_at_zero"] is False
    assert result["archive_start_kind"] == ""


def test_zip_detection_emits_password_required_for_encrypted_central_entry(tmp_path):
    name = b"a"
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 1, 0, 0, 0, 0, 0, 0, 1, 0) + name
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 1, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0,
    ) + name
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    part = tmp_path / "encrypted.zip"
    part.write_bytes(local + central + eocd)

    result = process_zip_eocd_structure(_context([part], "", "zip.eocd_structure"))

    assert result["plausible"] is True
    assert result["central_directory_encrypted_entries"] == 1
    assert result["password_required"] is True
    assert result["password_state"] == "required"
    assert result["encryption_scan_complete"] is True
