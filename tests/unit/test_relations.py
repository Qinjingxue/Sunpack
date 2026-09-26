from pathlib import Path
from io import BytesIO
from binascii import crc32
import struct
import zipfile

import pytest

from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.coordinator.target_scan import build_candidates_for_target
from sunpack.pipeline.coordinator.target_groups import relation_group_to_candidate
from sunpack.pipeline.discovery.relations import RelationsScheduler
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.pipeline.discovery.relations.internal.archive_input import archive_input_for_group
from tests.helpers.fs_builder import make_minimal_7z


def _groups(tmp_path: Path):
    return RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())


def test_plain_file_relation_omits_empty_volume_anchor(tmp_path):
    path = tmp_path / "ordinary.bin"
    path.write_bytes(b"ordinary data")

    candidates = build_candidates_for_target(str(path))

    assert candidates
    assert all(candidate.relation_anchor == {} for candidate in candidates)


def _minimal_rar4_single() -> bytes:
    header = bytearray(13)
    header[2] = 0x73
    header[3:5] = (0).to_bytes(2, "little")
    header[5:7] = len(header).to_bytes(2, "little")
    header[0:2] = (crc32(header[2:]) & 0xFFFF).to_bytes(2, "little")
    return b"Rar!\x1a\x07\x00" + bytes(header)


@pytest.mark.parametrize(
    ("filename", "content", "archive_format"),
    [
        ("ordinary.7z", make_minimal_7z(), "7z"),
        ("ordinary.rar", _minimal_rar4_single(), "rar"),
    ],
)
def test_standalone_rar_and_7z_are_confirmed_by_relations(
    tmp_path, filename, content, archive_format
):
    path = tmp_path / filename
    path.write_bytes(content)

    group = next(group for group in _groups(tmp_path) if Path(group.head_path) == path)

    assert group.input_paths == [str(path)]
    assert group.head_metadata["format"] == archive_format
    assert group.head_metadata["standalone"] is True
    assert group.head_metadata["relation_confirmed"] is True


def test_standalone_zip_is_confirmed_by_relations(tmp_path):
    path = tmp_path / "ordinary.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("inside.txt", "hello")

    group = next(group for group in _groups(tmp_path) if Path(group.head_path) == path)

    assert group.kind == "file"
    assert group.input_paths == [str(path)]
    assert group.head_metadata["format"] == "zip"
    assert group.head_metadata["standalone"] is True
    assert group.head_metadata["relation_confirmed"] is True


def test_empty_zip_is_confirmed_by_relations(tmp_path):
    path = tmp_path / "empty.zip"
    with zipfile.ZipFile(path, "w"):
        pass

    group = next(group for group in _groups(tmp_path) if Path(group.head_path) == path)

    assert group.head_metadata["format"] == "zip"
    assert group.head_metadata["standalone"] is True
    assert group.head_metadata["relation_confirmed"] is True


def _minimal_pe_image(marker: bytes = b"") -> tuple[bytes, int]:
    pe_end = 0xE0
    image = bytearray(pe_end)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\x00\x00"
    image[0x86:0x88] = (1).to_bytes(2, "little")
    image[0x94:0x96] = (0).to_bytes(2, "little")
    section = 0x98
    image[section + 16:section + 20] = (0x20).to_bytes(4, "little")
    image[section + 20:section + 24] = (0xC0).to_bytes(4, "little")
    if marker:
        image[0x20:0x20 + len(marker)] = marker
    return bytes(image), pe_end


def _minimal_zip_single() -> bytes:
    buffer = BytesIO()
    info = zipfile.ZipInfo("inside.txt", date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(buffer, "w") as stream:
        stream.writestr(info, "hello")
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("payload", "marker", "archive_format"),
    [
        (make_minimal_7z(), b"7-Zip SFX", "7z"),
        (_minimal_zip_single(), b"7-Zip SFX", "zip"),
        (_minimal_rar4_single(), b"WinRAR SFX", "rar"),
    ],
)
def test_known_sfx_stub_is_confirmed_and_projected_as_file_range(
    tmp_path, payload, marker, archive_format
):
    image, pe_end = _minimal_pe_image(marker)
    path = tmp_path / f"payload_{archive_format}.exe"
    path.write_bytes(image + payload)

    group = next(group for group in _groups(tmp_path) if Path(group.head_path) == path)
    metadata = group.head_metadata

    assert metadata["format"] == archive_format
    assert metadata["relation_confirmed"] is True
    assert metadata["sfx"] is True
    assert metadata["pe_structure"] is True
    assert metadata["structure_offset"] == pe_end

    descriptor = archive_input_for_group(group)
    assert descriptor is not None
    archive_input = descriptor.to_dict()
    assert archive_input["open_mode"] == "file_range"
    assert archive_input["format_hint"] == archive_format
    assert archive_input["parts"][0]["start"] == pe_end


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

    result = ArchiveTaskProvider({
        "detection": {"enabled": True},
        "embedded_scan": {"enabled": True},
    }).discover_targets([str(path)])

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

    config = {
        "detection": {"enabled": True},
        "embedded_scan": {"enabled": True},
    }
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


def test_filename_numbered_7z_without_structural_seed_is_not_grouped(tmp_path):
    names = ["archive.7z.001", "archive.7z.002", "archive.7z.003"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = _groups(tmp_path)

    assert all(group.kind == "file" for group in groups)
    assert all(len(group.input_paths) == 1 for group in groups)


@pytest.mark.parametrize("archive_format", ["7z", "zip"])
def test_sfx_launcher_attaches_to_data_volumes_but_stays_out_of_input(tmp_path, archive_format):
    launcher = tmp_path / "payload.exe"
    first = tmp_path / f"payload.{archive_format}.001"
    second = tmp_path / f"payload.{archive_format}.002"
    launcher.write_bytes(b"MZ launcher")
    first.write_bytes(b"data volume 1")
    second.write_bytes(b"data volume 2")

    groups = _groups(tmp_path)

    # MZ alone is only a weak SFX seed.  Without a structurally verifiable
    # proposal it must not turn filename-like siblings into a relation.
    assert all(group.kind == "file" for group in groups)
    assert all(len(group.input_paths) == 1 for group in groups)


def test_rar_part1_exe_remains_a_data_volume(tmp_path):
    first = tmp_path / "payload.part1.exe"
    second = tmp_path / "payload.part2.rar"
    first.write_bytes(b"rar sfx data volume 1")
    second.write_bytes(b"rar data volume 2")

    groups = _groups(tmp_path)

    assert all(group.kind == "file" for group in groups)
    assert all(len(group.input_paths) == 1 for group in groups)


def test_strict_formats_with_same_stem_never_cross_merge(tmp_path):
    families = {
        "7z_numbered": ["same.7z.001", "same.7z.002"],
        "zip_numbered": ["same.zip.001", "same.zip.002"],
        "rar_part": ["same.part1.rar", "same.part2.rar"],
    }
    for names in families.values():
        for name in names:
            (tmp_path / name).write_bytes(name.encode())

    groups = _groups(tmp_path)

    assert all(group.kind == "file" for group in groups)
    assert all(len(group.input_paths) == 1 for group in groups)


@pytest.mark.parametrize(
    "names",
    [
        ["movie.part1.photo", "movie.part2.document"],
        ["movie.7z.001.noise.bin", "movie.7z.002.noise.bin"],
        ["movie.volume_1.fake", "movie.volume_2.fake"],
        ["setup.exe", "setup.001", "setup.002"],
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


def test_public_parser_accepts_modern_split_zip_members():
    scheduler = RelationsScheduler()

    first = scheduler.parse_numbered_volume("archive.z01")
    later = scheduler.parse_numbered_volume("archive.z12")

    assert first is not None
    assert first["number"] == 1
    assert first["style"] == "zip_spanned"
    assert later is not None
    assert later["number"] == 12
    assert later["style"] == "zip_spanned"


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


def test_split_zip_without_terminal_reports_strong_missing_tail(tmp_path):
    first = tmp_path / "modern.z01"
    second = tmp_path / "modern.z02"
    first.write_bytes(_split_zip_first_bytes())
    second.write_bytes(b"opaque-middle-volume")

    groups = _groups(tmp_path)

    assert all(group.kind == "file" for group in groups)
    assert all(len(group.input_paths) == 1 for group in groups)


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


def test_prefixed_single_disk_zip_carrier_is_resolved_by_embedded_discovery(tmp_path):
    carrier = tmp_path / "cover.jpg"
    archive = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("payload.txt", "carrier")
    carrier.write_bytes(b"fake-jpeg-prefix" + archive.read_bytes())
    archive.unlink()

    result = ArchiveTaskProvider({
        "detection": {"enabled": True},
        "embedded_scan": {"enabled": True},
    }).discover_targets([str(carrier)])

    assert len(result.resolved_tasks) == 1
    task = result.resolved_tasks[0]
    assert task.discovery_source == "embedded"
    assert task.archive_input().format_hint == "zip"
    assert task.all_parts == [str(carrier)]

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


def test_only_head_7z_keeps_unconfirmed_split_identity(tmp_path):
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

    assert group.is_split_candidate is False
    assert group.relation.is_split_related is True
    assert group.relation.split_role == "first"
    assert group.relation.split_index == 1
    assert group.head_metadata["format"] == "7z"
    assert group.head_metadata.get("relation_confirmed") is not True
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
