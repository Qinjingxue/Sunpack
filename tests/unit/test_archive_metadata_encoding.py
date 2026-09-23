import binascii
import struct
from types import SimpleNamespace

import pytest

from sunpack.pipeline.extraction.internal.sevenzip.metadata import ArchiveMetadataScanner


@pytest.mark.parametrize(
    ("name", "encoding", "expected_codepage"),
    [
        ("日本語.txt", "cp932", "932"),
        ("説明書/第一章.txt", "cp932", "932"),
        ("日本語/説明.txt", "utf-8", "65001"),
        ("ﾃｽﾄ.txt", "cp932", "932"),
        ("中文说明资料.txt", "cp936", "936"),
        ("繁體中文說明資料檔案測試.txt", "cp950", "950"),
    ],
)
def test_codepage_selection_preserves_known_unicode_families(name, encoding, expected_codepage):
    selected = ArchiveMetadataScanner()._select_codepage([name.encode(encoding)])

    assert selected["codepage"] == expected_codepage


def test_repeated_shift_jis_parent_is_not_misclassified_as_gbk():
    scanner = ArchiveMetadataScanner()
    parent = "無知ロリと化け物_製品0519c"
    raw_names = [f"{parent}/assets/file_{index:04d}.bin".encode("cp932") for index in range(2500)]

    selected = scanner._select_codepage(raw_names)

    assert selected["codepage"] == "932"


def test_shift_jis_kanji_only_name_is_not_rejected_as_ambiguous_gbk():
    selected = ArchiveMetadataScanner()._select_codepage(["更新履歴.txt".encode("cp932")])

    assert selected["codepage"] == "932"


def test_shift_jis_kanji_only_zip_scan_uses_cp932(tmp_path):
    archive = tmp_path / "shift-jis-kanji-only.zip"
    expected_name = "Warrior Girl ver2.01/更新履歴.txt"
    _write_stored_zip(archive, expected_name.encode("cp932"), b"payload")

    result = ArchiveMetadataScanner().scan(str(archive))

    assert result.selected_codepage == "932"
    assert result.decoded_names == [expected_name]
    assert result.confidence > 0.5


def test_shift_jis_zip_scan_returns_decoded_item_paths(tmp_path):
    archive = tmp_path / "shift-jis.zip"
    expected_name = "日本語/説明.txt"
    _write_stored_zip(archive, expected_name.encode("cp932"), b"payload")

    result = ArchiveMetadataScanner().scan(str(archive))

    assert result.selected_codepage == "932"
    assert result.decoded_names == [expected_name]
    assert result.confidence > 0.5


def test_format_hint_scans_disguised_zip_without_renaming_it(tmp_path):
    archive = tmp_path / "downloaded.data"
    expected_name = "日本語.txt"
    _write_stored_zip(archive, expected_name.encode("cp932"), b"payload")

    result = ArchiveMetadataScanner().scan(str(archive), format_hint="zip")

    assert archive.is_file()
    assert not (tmp_path / "downloaded.zip").exists()
    assert result.archive_type == "zip"
    assert result.decoded_names == [expected_name]


def test_unicode_native_archive_formats_do_not_receive_zip_codepage_override():
    scanner = ArchiveMetadataScanner()

    for archive_type in ("7z", "rar"):
        result = scanner.scan(f"unused.{archive_type}", format_hint=archive_type)

        assert result.archive_type == archive_type
        assert result.selected_codepage is None
        assert result.decoded_names == []
        assert result.warnings == []


def test_task_metadata_cache_survives_scanner_instance_change(tmp_path):
    archive = tmp_path / "cached.zip"
    _write_stored_zip(archive, b"plain.txt", b"payload")
    task = SimpleNamespace(runtime={})

    first = ArchiveMetadataScanner().scan_for_task(task, str(archive), format_hint="zip")
    second_scanner = ArchiveMetadataScanner()
    second_scanner._scan_uncached = lambda *_args, **_kwargs: pytest.fail("metadata was rescanned")
    second = second_scanner.scan_for_task(task, str(archive), format_hint="zip")

    assert second.decoded_names == first.decoded_names
    assert second.sample_count == first.sample_count


def test_unicode_path_extra_field_takes_precedence_over_codepage_guess(tmp_path):
    archive = tmp_path / "unicode-extra.zip"
    raw_name = "【サンプル】テスト素材.psd".encode("cp932")
    expected_name = "【サンプル】テスト素材.psd"
    _write_stored_zip(archive, raw_name, b"payload", unicode_name=expected_name)

    result = ArchiveMetadataScanner().scan(str(archive))

    assert result.error is None
    assert result.selected_codepage is None
    assert result.decoded_names == [expected_name]
    assert result.confidence == 1.0
    assert any("0x7075" in reason for reason in result.reasons)


def test_ambiguous_codepage_does_not_block_extraction():
    scanner = ArchiveMetadataScanner()
    scanner._select_codepage = lambda _names: {
        "encoding": "cp932", "codepage": None, "confidence": 0.167,
        "label": "Shift-JIS/CP932", "reasons": ["ambiguous"],
    }
    scanner._scan_zip_name_samples = lambda _path: ([b"\x82\xa0.txt"], [False], [None], False, "")

    result = scanner._scan_zip_central_directory("unused.zip")

    assert result.error is None
    assert result.selected_codepage is None
    assert result.confidence == 0.167
    assert result.warnings


def _write_stored_zip(path, raw_name: bytes, payload: bytes, unicode_name: str | None = None) -> None:
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    extra = b""
    if unicode_name is not None:
        encoded_unicode_name = unicode_name.encode("utf-8")
        extra_payload = b"\x01" + struct.pack("<I", binascii.crc32(raw_name) & 0xFFFFFFFF) + encoded_unicode_name
        extra = struct.pack("<HH", 0x7075, len(extra_payload)) + extra_payload
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name), len(extra),
    ) + raw_name + extra + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name),
        len(extra), 0, 0, 0, 0, 0,
    ) + raw_name + extra
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50, 0, 0, 1, 1, len(central), len(local), 0,
    )
    path.write_bytes(local + central + eocd)
