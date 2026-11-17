"""Real payload-only encryption: coder selection must not reject valid passwords.

The existing encryption matrix mostly encrypts 7z headers. These cases instead
exercise payload prefilters, their unsupported-method fallback, and real member
CRC confirmation. Candidate collisions/order are covered by the native units.
"""

import pytest

from tests.helpers.native_fixture import assemble_carrier, file_inventory
from tests.helpers.real_archives import ArchiveCase, run_cmd, write_payload
from tests.helpers.tool_config import require_7z, require_7z_zstd
from tests.real.archive_boundary import (
    assert_archive_round_trip, assert_extracted, assert_scan_parts, extract_report, require_generator,
)
from tests.real.split_cases import SPLIT_NAMING_CASES, rename_split_parts


PASSWORD = "payload-only-密码"
WRONG = [f"payload-wrong-{index}" for index in range(4)]

# One case per decoder, plus orthogonal stream-layout/filter cases, rather than
# multiplying every method by every layout and candidate position.
CASES = [
    pytest.param(method.lower(), (f"-m0={method}",), True, False, index % 3,
                 id=method.lower())
    for index, method in enumerate((
        "Copy", "LZMA", "LZMA2", "PPMd", "BZip2", "Deflate", "Deflate64", "ZSTD", "LZ4",
    ))
] + [
    pytest.param("lzma2-nonsolid", ("-m0=LZMA2",), False, False, 2, id="lzma2-nonsolid"),
    pytest.param("lzma2-random", ("-m0=LZMA2",), True, True, 1, id="lzma2-random-chunks"),
    pytest.param("bcj", ("-m0=BCJ", "-m1=LZMA2"), True, False, 1, id="bcj-lzma2"),
    pytest.param("delta", ("-m0=Delta:4", "-m1=LZMA2"), True, False, 1, id="delta-lzma2"),
    pytest.param("bcj2", ("-m0=BCJ2", "-m1=LZMA2", "-m2=LZMA2", "-m3=LZMA2",
                         "-mb0:1", "-mb0s1:2", "-mb0s2:3"), True, False, 2, id="bcj2-multistream"),
]


def create_payload_case(root, case_id, methods, solid, random_only, *, split=False):
    extended = case_id in {"zstd", "lz4"}
    require_generator("7z", seven_zip_lz4=extended)
    tool = require_7z_zstd() if extended else require_7z()
    source = root / "source"
    payload = write_payload(source, case_id, size_bytes=64 * 1024, profile="default")
    if random_only:
        # No small text member can hide an invalid assumption that LZMA2 always
        # starts with a compressed chunk. Incompressible data uses copy chunks.
        (source / payload["marker_name"]).unlink()
    else:
        (source / "a-small.bin").write_bytes(b"small CRC-bearing member\n")
        (source / "empty.bin").write_bytes(b"")
    expected = file_inventory(source)
    archive_dir = root / "archives"
    archive_dir.mkdir(parents=True)
    archive = archive_dir / "payload.7z"
    run_cmd([str(tool), "a", str(archive), str(source), "-y", "-mx=1", "-mhe=off",
             f"-p{PASSWORD}", f"-ms={'on' if solid else 'off'}", *methods,
             *(["-v16k"] if split else [])], archive_dir)
    if split:
        archive = archive.with_name(archive.name + ".001")
    return ArchiveCase(case_id, archive_dir, archive, payload["marker_name"],
                       payload["marker_text"], "7z", password=PASSWORD, split=split,
                       metadata={"expected_files": expected})


@pytest.mark.parametrize("case_id,methods,solid,random_only,position", CASES)
def test_payload_only_passwords(package, tmp_path, case_id, methods, solid, random_only, position):
    case = create_payload_case(tmp_path, case_id, methods, solid, random_only)
    rejected = package.json("scan", "-d", *[arg for value in WRONG for arg in ("-p", value)],
                            case.entry_path, code=1)
    assert rejected["summary"]["failed_count"] == 1, rejected
    assert rejected["items"][0]["error_kind"] == "wrong_password", rejected

    candidates = WRONG.copy()
    candidates.insert((0, 2, len(candidates))[position], PASSWORD)
    item = assert_archive_round_trip(package, case, tmp_path / "output", passwords=candidates)
    assert item["password_used"] == PASSWORD, item


def test_payload_only_disguised_volumes(package, tmp_path):
    # Prefix material and the public header reside in different physical parts.
    # Reuse the real split-name mapping instead of assuming a .7z suffix.
    case = create_payload_case(tmp_path, "split", ("-m0=LZMA2",), True, False, split=True)
    naming = next(item for item in SPLIT_NAMING_CASES if item.case_id == "7z-format-before-part-marker")
    rename_split_parts(case, naming)
    item = assert_archive_round_trip(package, case, tmp_path / "output", passwords=[*WRONG, PASSWORD])
    assert item["password_used"] == PASSWORD, item
    assert_scan_parts(case, item)


def test_payload_only_nested_carrier(package, tmp_path):
    # Both encrypted layers use payload probes. The outer layer is also an
    # exact range inside a disguised carrier, not an archive-to-EOF input.
    inner = create_payload_case(tmp_path / "inner", "nested", ("-m0=LZMA2",), True, False)
    outer = tmp_path / "outer.7z"
    run_cmd([str(require_7z()), "a", str(outer), str(inner.archive_dir), "-y", "-mx=1",
             "-m0=LZMA2", "-mhe=off", f"-p{PASSWORD}"], tmp_path)
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    carrier = inputs / "holiday.jpg"
    assemble_carrier(carrier, [outer], prefix_lengths=[137], junk_min=97, junk_max=193)
    item, = package.json("scan", "-d", "-p", WRONG[0], "-p", PASSWORD, carrier)["items"]
    assert item["offset"] == 137 and item["password_used"] == PASSWORD, item
    output = tmp_path / "output"
    report = extract_report(package, carrier, output, passwords=[WRONG[0], PASSWORD], recursive=True)
    assert report["summary"]["failed_count"] == 0, report
    assert_extracted(inner, output)


@pytest.mark.parametrize("fixture,bad,expected", [
    ("7z_tiny_crc_collision.7z", "collision-49", {"a.bin": b"K", "z.bin": b"Z" * 2048}),
    # Explicit AES direct-key coder, three tiny folders, validated by 7-Zip.
    # First and last use identical ciphertext/IV. Their CRC information is not
    # independent; a middle CRC failure must not be erased by the last success.
    ("7z_all_tiny_crc_collision.7z", "tiny-99", {"a.bin": b"K", "b.bin": b"ABC", "c.bin": b"K"}),
])
def test_payload_tiny_crc_collision_does_not_confirm_password(package, tmp_path, repo_root, fixture, bad, expected):
    # Generated by 7-Zip: Copy, non-solid, -mhe=off -mhc=off -psecret.
    # a.bin is b"K", z.bin is b"Z" * 2048. The wrong key collision-49
    # decrypts a.bin to K too: its 1-byte CRC is only eight bits of evidence.
    # Keep this real fixture fixed so the collision is deterministic, not a
    # probabilistic brute-force search in every acceptance run.
    source = repo_root / "tests/data" / fixture
    archive = tmp_path / "tiny-crc.7z"
    archive.write_bytes(source.read_bytes())
    rejected = package.json("scan", "-d", "-p", bad, archive, code=1)
    assert rejected["items"][0]["error_kind"] == "wrong_password", rejected
    scan = package.json("scan", "-d", "-p", bad, "-p", "secret", archive)
    assert scan["items"][0]["password_used"] == "secret", scan
    # Fresh extraction confirms while writing; an existing output switches to
    # the read-only confirmation path and must preserve the user's sentinel.
    package.configure(post_extract={"flatten_single_directory": False})
    for existing in (False, True):
        # A previous successful scan/extract must not prioritize its recent
        # secret ahead of the intentionally first colliding candidate.
        assert package.run("--persistent-shutdown").returncode == 0
        output = tmp_path / ("existing" if existing else "fresh")
        sentinel = output / "tiny-crc" / "keep.txt"
        if existing:
            sentinel.parent.mkdir(parents=True)
            sentinel.write_text("user content", encoding="utf-8")
        report = package.json("extract", "-d", "-nf", "-c", "k", "-o", output,
                              "-p", bad, "-p", "secret", archive)
        assert report["summary"]["success_count"] == 1, report
        for name, content in expected.items():
            assert [path.read_bytes() for path in output.rglob(name)] == [content]
        if existing:
            assert sentinel.read_text(encoding="utf-8") == "user content"
