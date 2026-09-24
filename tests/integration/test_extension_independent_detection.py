from pathlib import Path
import struct
from binascii import crc32

import pytest

from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.detection_probe import detect_archive_hits, detection_pipeline_config
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar


@pytest.mark.parametrize("archive_format", ["zip", "7z"])
def test_archive_embedded_in_middle_is_found_by_selected_embedded_deep_scan(tmp_path, archive_format):
    case = ArchiveFixtureFactory().create(tmp_path, f"middle_{archive_format}", archive_format)
    archive_bytes = case.entry_path.read_bytes()
    carrier = tmp_path / f"middle_{archive_format}.video"
    prefix = b"carrier-prefix\0" + b"A" * (2 * 1024 * 1024)
    suffix = b"carrier-suffix\0" + b"B" * (2 * 1024 * 1024)
    carrier.write_bytes(prefix + archive_bytes + suffix)

    detected = detect_archive_hits(carrier)

    assert len(detected) == 1
    resolved = detected[0]
    assert resolved.discovery_source == "embedded"
    assert resolved.archive_input().format_hint == archive_format
    segment = resolved.knowledge().get("source.selected_segment")
    assert segment["format"] == archive_format
    assert segment["start_offset"] == len(prefix)


@pytest.mark.skipif(get_optional_rar() is None, reason="RAR generator is not configured")
def test_header_encrypted_rar_is_confirmed_from_crc_valid_encryption_header(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "encrypted_rar_chaos",
        "rar",
        password="secret",
        disguise_ext=".unrelated",
    )

    detected = detect_archive_hits(case.entry_path)

    assert len(detected) == 1
    resolved = detected[0]
    assert resolved.discovery_source == "relations"
    assert resolved.archive_input().format_hint == "rar"
    assert resolved.knowledge().get("discovery.evidence.relation_confirmed") is True
    assert resolved.knowledge().get("discovery.evidence.needs_password") is True


def test_header_encrypted_rar4_primary_uses_relations_identity(tmp_path):
    body = bytes([0x73]) + struct.pack("<HH", 0x0080, 7)
    main_header = struct.pack("<H", crc32(body) & 0xFFFF) + body
    path = tmp_path / "header_encrypted_rar4.rar"
    path.write_bytes(
        b"Rar!\x1a\x07\x00"
        + main_header
        + b"\xd6\xd3\x77\xb9\xf7\x5d\xe8"
    )

    result = ArchiveTaskProvider(detection_pipeline_config()).discover_targets([str(path)])

    assert len(result.resolved_tasks) == 1
    resolved = result.resolved_tasks[0]
    assert resolved.discovery_source == "relations"
    assert resolved.archive_input().format_hint == "rar"
    assert resolved.knowledge().get("discovery.evidence.needs_password") is True
    assert resolved.knowledge().get("discovery.evidence.relation_confirmed") is True


def test_signature_bytes_without_valid_structure_are_not_accepted(tmp_path):
    fake = tmp_path / "random.payload"
    fake.write_bytes(b"noise" * 100 + b"7z\xbc\xaf\x27\x1c" + b"not-a-seven-zip" * 100)

    assert detect_archive_hits(fake) == []
