import struct
import zipfile
from binascii import crc32
from io import BytesIO
from pathlib import Path

import pytest

from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.target_groups import relation_group_to_candidate
from sunpack.pipeline.coordinator.target_scan import build_candidates_for_target
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.discovery.relations import RelationsScheduler
from sunpack.pipeline.discovery.relations.internal.archive_input import (
    archive_input_for_group,
)
from tests.helpers.config_factory import make_config
from tests.helpers.fs_builder import make_minimal_7z, make_minimal_pe


def _groups(tmp_path: Path):
    return RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path), config=make_config()).scan())


def test_deleted_lz4_wrapped_head_cannot_join_readable_split_family(tmp_path):
    from tests.helpers.native_fixture import create_lz4_frames

    first = tmp_path / "archive.7z.001"
    second = tmp_path / "archive.7z.002"
    wrapped = tmp_path / "archive.7z.001.lz4"
    payload = make_minimal_7z()
    first.write_bytes(payload[:32])
    second.write_bytes(payload[32:])
    create_lz4_frames(wrapped, [first])
    snapshot = DirectoryScanner(str(tmp_path), config=make_config()).scan()
    wrapped.unlink()

    groups = RelationsScheduler().build_candidate_groups(snapshot)

    group = next(group for group in groups if group.kind == "split_archive")
    assert group.input_paths == [str(first), str(second)]
    assert group.head_metadata["relation_confirmed"] is True
    assert all(str(wrapped) not in item.input_paths for item in groups if item.kind == "split_archive")


def test_plain_file_relation_omits_empty_volume_anchor(tmp_path):
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"ordinary data")

    candidates = build_candidates_for_target(str(path), session=DiscoveryScanSession(config=make_config()))

    assert candidates
    assert all(candidate.relation_anchor == {} for candidate in candidates)


def _minimal_pe_image(marker: bytes = b"") -> tuple[bytes, int]:
    image = make_minimal_pe(marker)
    return image, len(image)


def _minimal_zip_single() -> bytes:
    buffer = BytesIO()
    info = zipfile.ZipInfo("inside.txt", date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(buffer, "w") as stream:
        stream.writestr(info, "hello")
    return buffer.getvalue()


def test_truncated_7z_sfx_is_confirmed_by_relations_and_projected_to_declared_range(tmp_path):
    image, pe_end = _minimal_pe_image(b"7-Zip SFX")
    payload = make_minimal_7z()
    truncated = payload[:-1]
    path = tmp_path / "truncated_7z_sfx.exe"
    path.write_bytes(image + truncated)

    group = next(group for group in _groups(tmp_path) if Path(group.head_path) == path)
    metadata = group.head_metadata

    assert metadata["format"] == "7z"
    assert metadata["relation_confirmed"] is True
    assert metadata["sfx"] is True
    assert metadata["pe_structure"] is True
    assert metadata["standalone"] is False
    assert metadata["multivolume"] is True
    assert metadata["structure_offset"] == pe_end
    assert metadata["expected_logical_size"] == pe_end + len(payload)
    assert metadata["expected_logical_size"] > path.stat().st_size

    descriptor = archive_input_for_group(group)
    assert descriptor is not None
    assert descriptor.open_mode == "file_range"
    assert descriptor.format_hint == "7z"
    assert descriptor.primary_extent is not None
    assert descriptor.primary_extent.start == pe_end
    assert descriptor.primary_extent.end == pe_end + len(payload)

    result = ArchiveTaskProvider(make_config({
        "detection": {"enabled": True},
        "embedded_scan": {"enabled": True},
    })).discover_targets([str(path)])

    assert len(result.resolved_tasks) == 1
    task = result.resolved_tasks[0]
    assert task.discovery_source == "relations"
    assert task.archive_input().primary_extent is not None
    assert task.archive_input().primary_extent.start == pe_end
    assert task.archive_input().primary_extent.end == pe_end + len(payload)


def test_arbitrary_pe_zip_overlay_requires_deep_detect_for_embedded_discovery(tmp_path):
    image, pe_end = _minimal_pe_image()
    path = tmp_path / "game.exe"
    path.write_bytes(image + _minimal_zip_single())

    group = next(group for group in _groups(tmp_path) if Path(group.head_path) == path)
    assert group.head_metadata.get("relation_confirmed") is not True

    config = make_config({
        "detection": {"enabled": True},
        "embedded_scan": {"enabled": True},
    })
    default_result = ArchiveTaskProvider(config).discover_targets([str(path)])
    assert default_result.resolved_tasks == []

    deep_result = ArchiveTaskProvider(
        config,
        EmbeddedOptions(force_scan=True),
    ).discover_targets([str(path)])

    assert len(deep_result.resolved_tasks) == 1
    task = deep_result.resolved_tasks[0]
    assert task.discovery_source == "embedded"
    descriptor = task.archive_input()
    assert descriptor.format_hint == "zip"
    assert descriptor.open_mode == "file_range"
    assert descriptor.primary_extent is not None
    assert descriptor.primary_extent.start == pe_end


@pytest.mark.parametrize(
    "names",
    [
        ["movie.part1.photo", "movie.part2.document"],
        ["movie.7z.001.noise.bin", "movie.7z.002.noise.bin"],
        ["movie.volume_1.fake", "movie.volume_2.fake"],
        ["setup.exe", "setup.001", "setup.002"],
        ["archive.7z.001", "archive.7z.002", "archive.7z.003"],
        ["payload.exe", "payload.7z.001", "payload.7z.002"],
        ["payload.exe", "payload.zip.001", "payload.zip.002"],
        ["payload.part1.exe", "payload.part2.rar"],
        ["same.7z.001", "same.7z.002", "same.zip.001", "same.zip.002", "same.part1.rar", "same.part2.rar"],
    ],
)
def test_filename_camouflage_without_structure_never_builds_a_group(tmp_path, names):
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = _groups(tmp_path)

    assert all(group.kind == "file" for group in groups)
    assert all(len(group.input_paths) == 1 for group in groups)


@pytest.mark.parametrize(
    ("name", "number", "style"),
    [
        ("archive.7z.001", 1, "numeric_suffix"),
        ("archive.zip.002", 2, "numeric_suffix"),
        ("archive.part03.rar", 3, "rar_part"),
        ("archive.part1.exe", 1, "rar_sfx_part"),
        ("archive.r00", 2, "rar_oldstyle"),
        ("archive.001", 1, "plain_numeric_suffix"),
        ("photo.part2.7z", 2, "part_numbered"),
        ("a.part1.zip", 1, "part_numbered"),
    ],
)
def test_public_parser_exposes_only_strict_names(name, number, style):
    parsed = RelationsScheduler().parse_numbered_volume(name)

    assert parsed is not None
    assert parsed["number"] == number
    assert parsed["style"] == style


@pytest.mark.parametrize(
    "name",
    [
        "archive.7z.001.noise.bin",
        "archive.volume_1.fake",
        "archive.[z-02]~",
    ],
)
def test_public_parser_rejects_camouflage(name):
    scheduler = RelationsScheduler()

    assert scheduler.parse_numbered_volume(name) is None
    assert scheduler.detect_split_role(name) is None


@pytest.mark.parametrize("name", [
    "Counterpart2.zip", "Counterpart3.zip", "Rampart1.rar", "Rampart2.rar",
    "apart10.bin", "report_part3_final.docx",
    "release.Counterpart2.rar", "release.report_part3_final.rar",
    "a.part0.rar", "a.rar.part0.hidden", "a.part4294967296.rar",
    "a.part4294967296.rar.hidden", "a.rar.part4294967296.hidden",
])
def test_public_parser_rejects_embedded_words_and_invalid_part_numbers(name):
    scheduler = RelationsScheduler()
    assert scheduler.parse_numbered_volume(name) is None
    assert scheduler.detect_split_role(name) is None


@pytest.mark.parametrize("name,expected", [
    ("Counterpart2.zip", "Counterpart2"),
    ("Counterpart3.zip", "Counterpart3"),
    ("Rampart1.rar", "Rampart1"),
    ("Rampart2.rar", "Rampart2"),
    ("a.part0.rar", "a.part0"),
    ("a.part4294967296.rar", "a.part4294967296"),
])
def test_ordinary_part_words_keep_their_output_name(name, expected):
    assert RelationsScheduler().logical_name_for_archive(name) == expected


@pytest.mark.parametrize("name,expected", [
    ("release.v2.tar.gz", "release.v2"),
    ("release.v2.tar.xz", "release.v2"),
    ("release.v2.tar.gz.001", "release.v2"),
    ("release.v2.zip.txt", "release.v2"),
    ("release.v2.zip.001", "release.v2"),
    ("release.v2.part1.rar.001", "release.v2"),
    ("release.v2.TAR.ZST", "release.v2"),
    ("release.v2.lz4", "release.v2"),
    ("版本.v2.tar.bz2", "版本.v2"),
    (".zip", ".zip"),
])
def test_archive_filename_excludes_format_suffixes_and_keeps_name_dots(name, expected):
    assert RelationsScheduler().logical_name_for_archive(name) == expected


@pytest.mark.parametrize("suffix", ["z", "zx", "ZX"])
def test_public_parser_accepts_modern_split_zip_members(suffix):
    scheduler = RelationsScheduler()

    first = scheduler.parse_numbered_volume(f"archive.{suffix}01")
    later = scheduler.parse_numbered_volume(f"archive.{suffix}12")

    assert first is not None
    assert first["number"] == 1
    assert first["style"] == "zip_spanned"
    assert later is not None
    assert later["number"] == 12
    assert later["style"] == "zip_spanned"


@pytest.mark.parametrize("name", ["archive.zipx.part02.zipx", "archive.part02.zipx"])
def test_public_parser_normalizes_zipx_marker_family(name):
    parsed = RelationsScheduler().parse_numbered_volume(name)

    assert parsed is not None
    assert parsed["prefix"] == "archive"
    assert parsed["style"] == "part_numbered"
    assert parsed["number"] == 2


@pytest.mark.parametrize(
    ("name", "number"),
    [
        ("archive.part1.rar.hidden", 1),
        ("archive.part2.rar123", 2),
    ],
)
def test_public_parser_accepts_decorated_rar_part_marker(name, number):
    parsed = RelationsScheduler().parse_numbered_volume(name)

    assert parsed is not None
    assert parsed["number"] == number
    assert parsed["style"] == "rar_part"
    assert parsed["decorated"] is True


def test_split_zip_structure_anchor_recovers_decorated_middle_member(tmp_path):
    first = tmp_path / "modern.z01"
    disguised_second = tmp_path / "modern.z02.useless.bin"
    terminal = tmp_path / "modern.zip"
    first.write_bytes(_split_zip_first_bytes())
    disguised_second.write_bytes(b"opaque-middle-volume")
    terminal.write_bytes(_split_zip_terminal_bytes(disk=2, cd_disk=2))

    group = next(group for group in _groups(tmp_path) if group.logical_name == "modern")

    assert [Path(path).name for path in group.input_paths] == [
        first.name,
        disguised_second.name,
        terminal.name,
    ]
    assert [volume.number for volume in group.split_volumes] == [1, 2, 3]
    assert [volume.role for volume in group.split_volumes] == ["first", "member", "terminal"]
    assert all(volume.style == "zip_spanned" for volume in group.split_volumes)
    expected_size = sum(path.stat().st_size for path in (first, disguised_second, terminal))
    assert group.logical_size == expected_size
    assert relation_group_to_candidate(group).logical_size == expected_size


@pytest.mark.parametrize("suffix", ["z", "zx"])
def test_split_zip_without_terminal_reports_strong_missing_tail(tmp_path, suffix):
    first = tmp_path / f"modern.{suffix}01"
    second = tmp_path / f"modern.{suffix}02"
    first.write_bytes(_split_zip_first_bytes())
    second.write_bytes(b"opaque-middle-volume")

    groups = _groups(tmp_path)

    # No complete relation may form, but the structurally proven head must
    # still be reported instead of silently disappearing from discovery.
    assert len(groups) == 1
    assert groups[0].is_split_candidate is True
    assert groups[0].input_paths == [str(first), str(second)]
    assert groups[0].head_metadata["volume_set_incomplete"] is True
    assert groups[0].head_metadata["relation_failure_reason"] == "missing_volume"


def _split_zip_first_bytes() -> bytes:
    name = b"x"
    local = struct.pack(
        "<4s5H3L2H",
        b"PK\x03\x04",
        20,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        len(name),
        0,
    )
    return b"PK\x07\x08" + local + name


def _split_zip_terminal_bytes(*, disk: int, cd_disk: int) -> bytes:
    return struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        disk,
        cd_disk,
        0,
        0,
        0,
        0,
        0,
    )


def test_standalone_tbz2_cannot_become_zip_volume_two(tmp_path):
    (tmp_path / "payload.tbz2").write_bytes(b"BZh9" + b"standalone")
    (tmp_path / "payload.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)

    groups = _groups(tmp_path)
    by_name = {Path(group.head_path).name: group for group in groups}

    assert set(by_name) == {"payload.tbz2", "payload.zip"}
    assert by_name["payload.tbz2"].kind == "file"
    assert by_name["payload.tbz2"].head_metadata["format"] == "bzip2"
    assert by_name["payload.tbz2"].head_metadata["standalone"] is True


def test_raw_zip_numeric_tail_name_stays_in_split_relation(tmp_path):
    first = tmp_path / "raw.zip.001"
    tail = tmp_path / "raw.zip.003"
    first.write_bytes(b"raw first volume")
    tail.write_bytes(b"raw tail volume")

    groups = _groups(tmp_path)

    assert all(group.kind == "file" for group in groups)
    assert all(len(group.input_paths) == 1 for group in groups)


def test_middle_gap_keeps_structured_missing_index(tmp_path):
    for name in ("gap.7z.001", "gap.7z.003"):
        (tmp_path / name).write_bytes(name.encode())

    groups = _groups(tmp_path)

    assert all(group.kind == "file" for group in groups)
    assert all(len(group.input_paths) == 1 for group in groups)

def test_plain_numbered_file_does_not_gain_archive_split_identity(tmp_path):
    path = tmp_path / "notes.001"
    path.write_bytes(b"plain data")

    group = next(group for group in _groups(tmp_path) if Path(group.head_path) == path)

    assert group.is_split_candidate is False
    assert group.relation.is_split_related is False


def test_only_head_7z_keeps_incomplete_split_identity(tmp_path):
    start_header = (
        (0).to_bytes(8, "little")
        + (4096).to_bytes(8, "little")
        + (0).to_bytes(4, "little")
    )
    path = tmp_path / "only-head.7z.001"
    path.write_bytes(
        b"7z\xbc\xaf\x27\x1c"
        + b"\x00\x04"
        + (crc32(start_header) & 0xFFFFFFFF).to_bytes(4, "little")
        + start_header
    )

    group = next(group for group in _groups(tmp_path) if Path(group.head_path) == path)
    candidate = relation_group_to_candidate(group)

    assert group.is_split_candidate is True
    assert group.head_metadata["volume_set_incomplete"] is True
    assert group.relation.is_split_related is True
    assert group.relation.split_role == "first"
    assert group.relation.split_index == 1
    assert group.head_metadata["format"] == "7z"
    assert group.head_metadata["relation_confirmed"] is True
    assert candidate.is_split is True


def test_raw_zip_relation_uses_bounded_anchors_not_full_directory_revalidation(tmp_path):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("payload.txt", "hello")
    data = bytearray(archive.read_bytes())
    archive.unlink()

    cd_offset = data.index(b"PK\x01\x02")
    eocd_offset = data.index(b"PK\x05\x06")
    data[cd_offset:cd_offset + 2] = b"XX"

    first = tmp_path / "bounded.zip.001"
    terminal = tmp_path / "bounded.zip.002"
    first.write_bytes(data[:eocd_offset])
    terminal.write_bytes(data[eocd_offset:])

    group = next(group for group in _groups(tmp_path) if group.logical_name == "bounded")

    assert group.kind == "split_archive"
    assert [Path(path).name for path in group.input_paths] == [first.name, terminal.name]
    assert group.head_metadata["format"] == "zip"
    assert group.head_metadata["relation_confirmed"] is True
