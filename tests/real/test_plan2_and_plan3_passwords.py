"""Exercise real encryption and reject the same fixtures with wrong candidates."""

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.real.archive_boundary import (
    assert_archive_round_trip,
    assert_scan_parts,
    extract_report,
    failure_kinds,
    require_generator,
)
from tests.real.enc_support import create_enc_case
from tests.real.encrypted_cases import ENCRYPTED_CASES, SFX_FORMATS
from tests.real.split_cases import SPLIT_NAMING_CASES, rename_split_parts


FACTORY = ArchiveFixtureFactory()
PASSWORD = "real-archive-password"
WRONG = [f"wrong-password-{index:03d}" for index in range(100)]


def assert_password_outcomes(package, case, tmp_path, *, wrong=WRONG, candidates=None):
    original_parts = {path.name for path in case.archive_dir.iterdir() if path.is_file()}
    rejected_output = tmp_path / "rejected"
    rejected = extract_report(
        package, case.archive_dir, rejected_output, passwords=wrong, cleanup="d", code=1,
    )
    assert rejected["summary"]["success_count"] == 0, rejected
    assert rejected["summary"]["partial_success_count"] == 0, rejected
    assert "wrong_password" in failure_kinds(rejected), rejected
    assert not any(path.is_file() for path in rejected_output.rglob("*"))
    assert {path.name for path in case.archive_dir.iterdir() if path.is_file()} == original_parts

    if candidates is None:
        candidates = [*WRONG[:63], case.password, *WRONG[63:-1]]
    item = assert_archive_round_trip(package, case, tmp_path / "recovered", passwords=candidates)
    assert item["password_used"] == case.password, item
    if case.split and not case.sfx:
        assert_scan_parts(case, item)
    if case.sfx and not case.split:
        assert item["offset"] > 0, item


@pytest.mark.parametrize(("archive_format", "case_id", "create_archive", "options"), ENCRYPTED_CASES)
def test_encrypted_archive_candidates(package, tmp_path, archive_format, case_id, create_archive, options):
    require_generator(archive_format)
    case = create_archive(tmp_path, case_id, password=PASSWORD, **options)
    case.password = PASSWORD
    assert_password_outcomes(package, case, tmp_path)


@pytest.mark.parametrize("archive_format", SFX_FORMATS)
@pytest.mark.parametrize("split", [False, True], ids=["single", "split"])
def test_encrypted_sfx_candidates(package, tmp_path, archive_format, split):
    require_generator(archive_format, sfx=True)
    case = FACTORY.create(
        tmp_path, f"sfx-{archive_format}", archive_format, password=PASSWORD,
        sfx=True, split=split, payload_size=(420 if split else 16) * 1024,
    )
    assert_password_outcomes(package, case, tmp_path)


@pytest.mark.parametrize("naming", SPLIT_NAMING_CASES, ids=lambda item: item.case_id)
def test_encrypted_disguised_volume_candidates(package, tmp_path, naming):
    require_generator(naming.archive_format)
    case = FACTORY.create(
        tmp_path, naming.case_id, naming.archive_format, password=PASSWORD,
        split=True, payload_size=420 * 1024,
    )
    rename_split_parts(case, naming)
    assert_password_outcomes(package, case, tmp_path)


def test_official_enc_vector_candidates(package, tmp_path):
    case = create_enc_case(tmp_path, "official-vector", input_suffix=".mov")
    assert_password_outcomes(
        package, case, tmp_path, wrong=[WRONG[0]], candidates=[WRONG[0], case.password, WRONG[1]],
    )


def test_empty_zipcrypto_header_match_does_not_erase_rejected_candidates(package, tmp_path, repo_root):
    # 7-Zip 26.03 created this stored ZipCrypto archive from payload.txt. Its first
    # encrypted member uses a fixed header nonce (39, little-endian) that lets
    # the empty password pass the one-byte header verifier. Every supplied
    # wrong candidate fails that verifier, and only PASSWORD decodes the file.
    archive = (repo_root / "tests/data/zipcrypto_empty_header_match.bin").read_bytes()
    inputs = tmp_path / "volumes"
    inputs.mkdir()
    for index, start in enumerate(range(0, len(archive), 1024), start=1):
        (inputs / f"archive.zip.{index:03d}").write_bytes(archive[start:start + 1024])
    output = tmp_path / "out"
    rejected = extract_report(package, inputs, output, passwords=WRONG, code=1)
    assert failure_kinds(rejected) == {"wrong_password"}, rejected
    assert not any(path.is_file() for path in output.rglob("*"))

    extract_report(package, inputs, output, passwords=[PASSWORD])
    member, = output.rglob("payload.txt")
    assert member.read_bytes() == b"valid zipcrypto payload\n" * 192
