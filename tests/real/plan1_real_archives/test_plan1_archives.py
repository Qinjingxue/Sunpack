"""Real format, codec and layout interoperability through the installed launcher."""

import shutil
from collections import Counter

import pytest

from tests.helpers.native_fixture import file_inventory, native_fixture
from tests.helpers.real_archives import (
    ARCHIVE_EXTENSIONS,
    ArchiveFixtureFactory,
    create_multi_member_stream_archive,
    create_rar4_archive,
    create_stream_variant_archive,
    create_streaming_zip_archive,
    create_zip64_archive,
    create_zip_multidisk_archive,
    run_cmd,
)
from tests.helpers.seven_zip_lz4 import create_7z_lz4_case
from tests.helpers.tool_config import get_optional_rar, require_7z, require_7z_zstd
from tests.real.archive_boundary import (
    assert_archive_round_trip,
    assert_extracted,
    assert_scan_parts,
    detected_archive_format,
    extract_report,
    require_generator,
    scan_case,
)
from tests.real.split_cases import SPLIT_NAMING_CASES, rename_split_parts


FACTORY = ArchiveFixtureFactory()


@pytest.mark.parametrize("archive_format", ARCHIVE_EXTENSIONS)
@pytest.mark.parametrize("disguised", [False, True], ids=["ordinary", "disguised"])
def test_plain_formats(package, tmp_path, archive_format, disguised):
    require_generator(archive_format)
    case = FACTORY.create(
        tmp_path, "plain", archive_format, disguise_ext=".unrecognized" if disguised else None,
        payload_size=256, payload_profile="structured",
    )
    assert_archive_round_trip(package, case, tmp_path / "out")


@pytest.mark.parametrize(("create_archive", "payload_size"), [
    pytest.param(create_streaming_zip_archive, 16 * 1024, id="zip-descriptor"),
    pytest.param(create_zip64_archive, 4096, id="zip64"),
    pytest.param(create_zip_multidisk_archive, 512, id="pkzip-disks"),
    pytest.param(create_rar4_archive, 16 * 1024, id="rar4"),
])
def test_structural_variants(package, tmp_path, create_archive, payload_size):
    if create_archive is create_rar4_archive:
        require_generator("rar")
    case = create_archive(tmp_path, "structure", payload_size=payload_size)
    if case.metadata.get("data_descriptor"):
        with case.entry_path.open("rb") as stream:
            header = stream.read(8)
        assert int.from_bytes(header[6:8], "little") & 0x08
    if case.metadata.get("zip64"):
        data = case.entry_path.read_bytes()
        assert b"PK\x06\x06" in data and b"PK\x06\x07" in data
    item = assert_archive_round_trip(package, case, tmp_path / "out")
    if case.split:
        assert_scan_parts(case, item)


@pytest.mark.parametrize("naming", SPLIT_NAMING_CASES, ids=lambda item: item.case_id)
def test_split_volume_names(package, tmp_path, naming):
    require_generator(naming.archive_format)
    case = FACTORY.create(
        tmp_path, naming.case_id, naming.archive_format, split=True, payload_size=420 * 1024,
    )
    rename_split_parts(case, naming)
    assert_scan_parts(case, assert_archive_round_trip(package, case, tmp_path / "out"))


@pytest.mark.parametrize("archive_format", ["zip", "7z", "rar"])
def test_disguised_split_is_one_archive(package, tmp_path, archive_format):
    require_generator(archive_format)
    case = FACTORY.create(
        tmp_path, "split", archive_format, split=True,
        disguise_ext=".unrelated", payload_size=260 * 1024,
    )
    assert_scan_parts(case, assert_archive_round_trip(package, case, tmp_path / "out"))


@pytest.mark.parametrize("archive_format", ["zip", "7z", "rar"])
@pytest.mark.parametrize("layout", ["sfx", "split", "sfx-split"])
@pytest.mark.parametrize("compressed", [False, True], ids=["stored", "compressed"])
def test_sfx_and_split_layouts(package, tmp_path, archive_format, layout, compressed):
    sfx = "sfx" in layout
    split = "split" in layout
    require_generator(archive_format, sfx=sfx)
    method = {"zip": "Deflate", "7z": "LZMA2", "rar": None}[archive_format] if compressed else None
    payload_kib = 420 if split else 32
    if compressed:
        payload_kib = 96
    case = FACTORY.create(
        tmp_path, "layout", archive_format, sfx=sfx, split=split,
        compression_method=method, compression_level=5 if compressed else 0,
        solid=True if compressed else None, split_volume_size=(32 if compressed else 100) * 1024,
        payload_size=payload_kib * 1024,
        payload_profile="structured" if compressed else "default",
    )
    item = assert_archive_round_trip(package, case, tmp_path / "out")
    if layout == "sfx":
        assert item["offset"] > 0, item


@pytest.mark.parametrize(("level", "solid"), [(0, False), (5, True)])
def test_rar4_split(package, tmp_path, level, solid):
    require_generator("rar")
    case = create_rar4_archive(
        tmp_path, "rar4", split=True, payload_size=(96 if solid else 420) * 1024,
        split_volume_size=(32 if solid else 100) * 1024,
        payload_profile="structured" if solid else "default", compression_level=level, solid=solid,
    )
    assert_scan_parts(case, assert_archive_round_trip(package, case, tmp_path / "out"))


CODEC_CASES = [
    *[
        pytest.param("zip", method, level, None, False, listed, id=f"zip-{method.lower()}")
        for method, level, listed in [
            ("Copy", 0, "Store"), ("Deflate", 5, "Deflate"), ("Deflate64", 5, "Deflate64"),
            ("BZip2", 5, "BZip2"), ("LZMA", 5, "LZMA"), ("PPMd", 5, "PPMd"),
        ]
    ],
    *[
        pytest.param("7z", method, level, solid, False, listed, id=f"7z-{method.lower()}-{solid}")
        for method, level, solid, listed in [
            ("Copy", 0, False, "Copy"), ("LZMA2", 5, True, "LZMA2"), ("LZMA2", 5, False, "LZMA2"),
            ("LZMA", 5, True, "LZMA"), ("PPMd", 5, True, "PPMd"), ("BZip2", 5, True, "BZip2"),
            ("Deflate", 5, True, "Deflate"), ("LZ4", 1, True, "04F71104"),
            ("LZ4", 1, False, "04F71104"),
        ]
    ],
    *[
        pytest.param("rar", None, level, solid, rar4, f"m{level}", id=f"rar{4 if rar4 else 5}-m{level}-{solid}")
        for level, solid, rar4 in [(0, False, False), (5, False, False), (5, True, False),
                                  (1, False, True), (5, True, True)]
    ],
]


@pytest.mark.parametrize(("archive_format", "method", "level", "solid", "rar4", "listed"), CODEC_CASES)
def test_container_codecs(package, tmp_path, archive_format, method, level, solid, rar4, listed):
    require_generator(archive_format, seven_zip_lz4=method == "LZ4")
    options = dict(payload_size=256, payload_profile="structured", compression_level=level, solid=solid)
    case = (
        create_rar4_archive(tmp_path, "codec", **options) if rar4
        else FACTORY.create(tmp_path, "codec", archive_format, compression_method=method, **options)
    )
    listing = run_cmd([str(require_7z()), "l", "-slt", str(case.entry_path)], case.archive_dir).stdout
    methods = [line.removeprefix("Method = ").casefold() for line in listing.splitlines()
               if line.startswith("Method = ")]
    assert any(listed.casefold() in value for value in methods), (listed, methods)
    assert_archive_round_trip(package, case, tmp_path / "out")


@pytest.mark.parametrize("archive_format", ["gzip", "bzip2", "xz", "zstd", "lz4"])
def test_concatenated_stream_members(package, tmp_path, archive_format):
    require_generator(archive_format)
    case = create_multi_member_stream_archive(tmp_path, "concatenated", archive_format, payload_size=256)
    scan_case(package, case)
    output = tmp_path / "out"
    extract_report(package, case.archive_dir, output)
    expected = (case.marker_text + case.metadata["second_member_content"]).encode("utf-8")
    assert [path.read_bytes() for path in output.rglob("*") if path.is_file()] == [expected]


@pytest.mark.parametrize(("archive_format", "level", "options"), [
    ("gzip", 1, {"gzip_filename": ""}), ("gzip", 9, {"gzip_filename": "member.txt"}),
    ("bzip2", 1, {}), ("bzip2", 9, {}),
    ("xz", 1, {"xz_check": "crc32"}), ("xz", 6, {"xz_check": "crc64"}),
    ("xz", 9, {"xz_check": "sha256"}), ("zstd", 1, {"zstd_checksum": False}),
    ("zstd", 19, {"zstd_checksum": True}),
])
def test_stream_codec_headers(package, tmp_path, archive_format, level, options):
    require_generator(archive_format)
    case = create_stream_variant_archive(
        tmp_path, "header", archive_format, compression_level=level, **options,
    )
    assert_archive_round_trip(package, case, tmp_path / "out")


@pytest.mark.parametrize("options", [
    {}, {"solid": False}, {"branch": "BCJ"}, {"branch": "BCJ2"},
    {"password": "secret", "header_encrypt": False},
    {"password": "secret"}, {"split": True}, {"split": True, "password": "secret"},
    {"disguise": True}, {"payload_size": 16}, {"payload_size": 9 * 1024 * 1024},
], ids=["solid", "nonsolid", "bcj", "bcj2", "encrypted-data", "encrypted-header",
        "split", "encrypted-split", "disguised", "small", "multichunk-large"])
def test_7z_lz4_interoperability(package, tmp_path, options):
    require_generator("7z", seven_zip_lz4=True)
    case = create_7z_lz4_case(tmp_path, "interop", **options)
    password_args = ["-psecret"] if case.password else []
    run_cmd([str(require_7z_zstd()), "t", "-y", *password_args, str(case.entry_path)], case.archive_dir)
    assert_archive_round_trip(package, case, tmp_path / "out", passwords=("wrong", "secret"))


def test_7z_lz4_encoded_header(package, tmp_path):
    require_generator("7z", seven_zip_lz4=True)
    case = create_7z_lz4_case(tmp_path, "raw_header", header_compress=False)
    encoded = case.entry_path.with_name("lz4_header.7z")
    native_fixture("seven_zip_lz4_header", source=str(case.entry_path), output=str(encoded))
    case.entry_path.unlink()
    case.entry_path = encoded
    run_cmd([str(require_7z_zstd()), "t", str(encoded)], case.archive_dir)
    assert_archive_round_trip(package, case, tmp_path / "out")


@pytest.mark.parametrize("layout", ["plain", "compressed", "split"])
def test_mixed_same_stem_archives(package, tmp_path, layout):
    common = tmp_path / "mixed"
    common.mkdir()
    formats = ["zip", "7z"]
    if get_optional_rar():
        formats.append("rar")
    if layout != "split":
        formats.extend(["tar.gz", "lz4", "tar.lz4"])
    cases = []
    for archive_format in formats:
        options = {}
        if layout == "compressed" and archive_format in {"zip", "7z", "rar"}:
            options["compression_method"] = {"zip": "Deflate", "7z": "LZMA2", "rar": None}[archive_format]
            options["compression_level"] = 5
        case = FACTORY.create(
            tmp_path, f"member-{archive_format}", archive_format, split=layout == "split",
            payload_size=260 * 1024 if layout == "split" else 4096, **options,
        )
        if layout == "split":
            for path in case.archive_dir.iterdir():
                shutil.move(path, common / path.name.replace(case.case_id, "same", 1))
        else:
            shutil.move(case.entry_path, common / ("same" + ARCHIVE_EXTENSIONS[archive_format]))
        cases.append(case)
    scan = package.json("scan", "-d", common)
    assert scan["summary"]["archive_count"] == len(cases), scan
    assert Counter(detected_archive_format(item["format"]) for item in scan["items"]) == Counter(
        detected_archive_format(case.archive_format) for case in cases
    ), scan
    output = tmp_path / "out"
    report = extract_report(package, common, output)
    assert report["summary"]["success_count"] >= len(cases), report
    assert len(file_inventory(output)) == sum(len(case.metadata["expected_files"]) for case in cases)
    for case in cases:
        assert_extracted(case, output)
