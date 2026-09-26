import binascii
import struct
from types import SimpleNamespace

import pytest

from sunpack.core.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    InputExtent,
)
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
def test_native_codepage_selection_preserves_known_unicode_families(
    tmp_path, name, encoding, expected_codepage
):
    archive = tmp_path / f"sample-{expected_codepage}.zip"
    _write_stored_zip(archive, name.encode(encoding), b"payload")

    result = ArchiveMetadataScanner().scan(str(archive), format_hint="zip")

    assert result.selected_codepage == expected_codepage
    assert result.confidence > 0.0


def test_shift_jis_kanji_only_zip_scan_uses_cp932(tmp_path):
    archive = tmp_path / "shift-jis-kanji-only.zip"
    expected_name = "Warrior Girl ver2.01/更新履歴.txt"
    _write_stored_zip(archive, expected_name.encode("cp932"), b"payload")

    result = ArchiveMetadataScanner().scan(str(archive), format_hint="zip")

    assert result.selected_codepage == "932"
    assert result.confidence > 0.5


def test_shift_jis_zip_scan_selects_cp932(tmp_path):
    archive = tmp_path / "shift-jis.zip"
    expected_name = "日本語/説明.txt"
    _write_stored_zip(archive, expected_name.encode("cp932"), b"payload")

    result = ArchiveMetadataScanner().scan(str(archive), format_hint="zip")

    assert result.selected_codepage == "932"
    assert result.confidence > 0.5


def test_format_hint_scans_disguised_zip_without_renaming_it(tmp_path):
    archive = tmp_path / "downloaded.data"
    expected_name = "日本語.txt"
    _write_stored_zip(archive, expected_name.encode("cp932"), b"payload")

    result = ArchiveMetadataScanner().scan(str(archive), format_hint="zip")

    assert archive.is_file()
    assert not (tmp_path / "downloaded.zip").exists()
    assert result.archive_type == "zip"


def test_sfx_prefix_uses_physical_central_directory(tmp_path):
    expected_name = "日本語/説明.txt"
    archive_bytes = _stored_zip_bytes(expected_name.encode("cp932"), b"payload")
    sfx = tmp_path / "self-extracting.exe"
    sfx.write_bytes(b"MZ" + b"stub" * 97 + archive_bytes)

    result = ArchiveMetadataScanner().scan(str(sfx), format_hint="zip")

    assert result.selected_codepage == "932"


def test_carrier_range_uses_canonical_archive_input(tmp_path):
    expected_name = "日本語/説明.txt"
    archive_bytes = _stored_zip_bytes(expected_name.encode("cp932"), b"payload")
    prefix = b"carrier-prefix" * 17
    suffix = b"carrier-suffix"
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(prefix + archive_bytes + suffix)
    descriptor = ArchiveInputDescriptor(
        entry_path=str(carrier),
        open_mode="file_range",
        format_hint="zip",
        logical_name="embedded.zip",
        parts=[
            ArchiveInputPart(
                extent=InputExtent(
                    path=str(carrier),
                    start=len(prefix),
                    end=len(prefix) + len(archive_bytes),
                ),
                role="main",
            )
        ],
    )

    result = ArchiveMetadataScanner().scan(
        str(carrier),
        format_hint="zip",
        archive_input=descriptor,
    )

    assert result.selected_codepage == "932"


def test_raw_multivolume_zip_uses_one_logical_input(tmp_path):
    expected_name = "中文说明资料.txt"
    archive_bytes = _stored_zip_bytes(expected_name.encode("cp936"), b"x" * 4096)
    split = len(archive_bytes) // 2
    first = tmp_path / "archive.0000"
    second = tmp_path / "archive.0001"
    first.write_bytes(archive_bytes[:split])
    second.write_bytes(archive_bytes[split:])
    descriptor = ArchiveInputDescriptor(
        entry_path=str(first),
        open_mode="native_volumes",
        format_hint="zip",
        logical_name="archive.zip",
        volume_style="zip_zero_numbered",
        parts=[
            ArchiveInputPart(
                extent=InputExtent(str(first)),
                role="first",
                volume_number=1,
                canonical_name="archive.0000",
            ),
            ArchiveInputPart(
                extent=InputExtent(str(second)),
                role="member",
                volume_number=2,
                canonical_name="archive.0001",
            ),
        ],
    )

    result = ArchiveMetadataScanner().scan(
        str(first),
        format_hint="zip",
        archive_input=descriptor,
    )

    assert result.selected_codepage == "936"


def test_unicode_native_archive_formats_do_not_receive_zip_codepage_override():
    scanner = ArchiveMetadataScanner()

    for archive_type in ("7z", "rar"):
        result = scanner.scan(f"unused.{archive_type}", format_hint=archive_type)

        assert result.archive_type == archive_type
        assert result.selected_codepage is None
        assert result.warnings == []


def test_task_metadata_cache_survives_scanner_instance_change(tmp_path):
    archive = tmp_path / "cached.zip"
    _write_stored_zip(archive, b"plain.txt", b"payload")
    descriptor = ArchiveInputDescriptor.from_parts(
        archive_path=str(archive),
        format_hint="zip",
    )
    task = SimpleNamespace(runtime={}, archive_input=lambda: descriptor)

    first = ArchiveMetadataScanner().scan_for_task(task, str(archive), format_hint="zip")
    second_scanner = ArchiveMetadataScanner()
    second_scanner._scan_descriptor = lambda *_args, **_kwargs: pytest.fail(
        "metadata was rescanned"
    )
    second = second_scanner.scan_for_task(task, str(archive), format_hint="zip")
    assert second.sample_count == first.sample_count


def test_unicode_path_extra_field_needs_no_python_name_copy(tmp_path):
    archive = tmp_path / "unicode-extra.zip"
    raw_name = "【サンプル】テスト素材.psd".encode("cp932")
    expected_name = "【サンプル】テスト素材.psd"
    _write_stored_zip(archive, raw_name, b"payload", unicode_name=expected_name)

    result = ArchiveMetadataScanner().scan(str(archive), format_hint="zip")

    assert result.error is None
    assert result.selected_codepage is None
    assert result.confidence == 1.0
    assert any("0x7075" in reason for reason in result.reasons)


def test_ambiguous_codepage_does_not_block_extraction(tmp_path):
    archive = tmp_path / "ambiguous.zip"
    _write_stored_zip(archive, b"\x82.txt", b"payload")

    result = ArchiveMetadataScanner().scan(str(archive), format_hint="zip")

    assert result.error is None
    assert result.selected_codepage is None
    assert result.warnings


def _write_stored_zip(
    path,
    raw_name: bytes,
    payload: bytes,
    unicode_name: str | None = None,
) -> None:
    path.write_bytes(_stored_zip_bytes(raw_name, payload, unicode_name=unicode_name))


def _stored_zip_bytes(
    raw_name: bytes,
    payload: bytes,
    unicode_name: str | None = None,
) -> bytes:
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    extra = b""
    if unicode_name is not None:
        encoded_unicode_name = unicode_name.encode("utf-8")
        extra_payload = (
            b"\x01"
            + struct.pack("<I", binascii.crc32(raw_name) & 0xFFFFFFFF)
            + encoded_unicode_name
        )
        extra = struct.pack("<HH", 0x7075, len(extra_payload)) + extra_payload
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0,
        0,
        0,
        0,
        crc,
        len(payload),
        len(payload),
        len(raw_name),
        len(extra),
    ) + raw_name + extra + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0,
        0,
        0,
        0,
        crc,
        len(payload),
        len(payload),
        len(raw_name),
        len(extra),
        0,
        0,
        0,
        0,
        0,
    ) + raw_name + extra
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        1,
        1,
        len(central),
        len(local),
        0,
    )
    return local + central + eocd
