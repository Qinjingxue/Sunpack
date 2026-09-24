from pathlib import Path
from io import BytesIO
from binascii import crc32
import struct
import zipfile

import pytest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.coordinator.target_scan import build_candidates_for_target
from sunpack.pipeline.coordinator.target_groups import relation_group_to_candidate
from sunpack.pipeline.discovery.relations import RelationsScheduler
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


def test_pe_zip_sfx_is_confirmed_and_projected_as_file_range(tmp_path):
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_STORED) as stream:
        stream.writestr("inside.txt", "hello")

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

    path = tmp_path / "payload.exe"
    path.write_bytes(bytes(image) + zip_buffer.getvalue())

    group = next(group for group in _groups(tmp_path) if Path(group.head_path) == path)
    metadata = group.head_metadata

    assert metadata["format"] == "zip"
    assert metadata["relation_confirmed"] is True
    assert metadata["sfx"] is True
    assert metadata["pe_structure"] is True
    assert metadata["structure_offset"] == pe_end

    candidate = relation_group_to_candidate(group)
    assert candidate.archive_input is not None
    archive_input = candidate.archive_input.to_dict()
    assert archive_input["open_mode"] == "file_range"
    assert archive_input["format_hint"] == "zip"
    assert archive_input["parts"][0]["start"] == pe_end

    password_descriptor = archive_input_for_group(group)
    assert password_descriptor is not None
    password_input = password_descriptor.to_dict()
    assert password_input["open_mode"] == "file_range"
    assert password_input["parts"][0]["start"] == pe_end


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
