import pytest

from sunpack.config.loader import load_config
from sunpack.coordinator.task_scan import direct_file_task
from sunpack.detection.input_planning import ArchiveInputPlanningStage
from sunpack.passwords.archive_tester import ArchivePasswordTester
from sunpack.passwords.verifier.rar_fast import RarFastVerifier
from sunpack.passwords.verifier.seven_zip_fast import SevenZipFastVerifier
from sunpack.passwords.verifier.zip_fast import ZipFastVerifier
from sunpack.support.sevenzip_bridge import get_native_password_tester
from sunpack.support import archive_knowledge_projection as knowledge_view
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar, get_optional_rar_sfx, require_7z


PASSWORD = "sfx-split-secret"
WRONG_PASSWORD = "wrong-sfx-password"

FAST_VERIFIERS = {
    "7z": SevenZipFastVerifier,
    "zip": ZipFastVerifier,
    "rar": RarFastVerifier,
}


def _parts(case):
    return sorted(str(path) for path in case.archive_dir.iterdir() if path.is_file())


def _remove_last_data_part(case):
    parts = sorted(
        path for path in case.archive_dir.iterdir()
        if path.is_file() and not path.name.lower().endswith(".exe")
    )
    if not parts:
        pytest.skip("generated SFX archive has no separate data volumes")
    parts[-1].unlink()


@pytest.mark.parametrize("archive_format", ["7z", "zip", "rar"])
def test_input_planned_single_sfx_uses_format_fast_password_probe(tmp_path, archive_format):
    require_7z()
    if archive_format == "rar" and not get_optional_rar_sfx():
        pytest.skip("RAR SFX generator is not configured")
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"fast_probe_{archive_format}_single",
        archive_format,
        split=False,
        sfx=True,
        password=PASSWORD,
    )
    parts = _parts(case)
    task = direct_file_task(str(case.entry_path), all_parts=parts)
    extraction_mode = task.split_info.archive_input.open_mode

    ArchiveInputPlanningStage(load_config()).plan_task(task)
    probe_input = knowledge_view.source_password_probe_input(task)
    outcome = FAST_VERIFIERS[archive_format]().verify_batch(
        str(case.entry_path),
        [WRONG_PASSWORD, PASSWORD],
        part_paths=parts,
        archive_input=probe_input,
    )

    assert outcome.ok is True, outcome
    # A fast probe is a hint, not a verdict: zipcrypto validates a single header byte, so an
    # unrelated password may be reported next to the real one (matched_indices=(0, 1)). The
    # contract is that the real password is among the reported candidates.
    matched_indices = outcome.matched_indices or (outcome.matched_index,)
    assert 1 in matched_indices, outcome
    if archive_format == "zip":
        assert outcome.match_evidence == "zipcrypto_header_byte", outcome
        assert outcome.final_confirmation_required is True, outcome
    assert probe_input["open_mode"] in {"file_range", "concat_ranges"}
    assert task.split_info.archive_input.open_mode == extraction_mode

    # The verification chain the pipeline builds must confirm the real password instead of
    # settling for the first candidate a weak fast probe reported.
    chain = ArchivePasswordTester().password_scheduler.verifier
    confirmed = chain.verify_batch(
        str(case.entry_path),
        [WRONG_PASSWORD, PASSWORD],
        part_paths=parts,
        archive_input=probe_input,
    )

    assert confirmed.ok is True, confirmed
    assert confirmed.final_confirmation_required is False, confirmed
    assert confirmed.matched_index == 1, confirmed


@pytest.mark.parametrize(
    ("case_kwargs", "password"),
    [
        ({"sfx": True}, None),
        ({"sfx": True}, PASSWORD),
        ({"carrier": "jpg"}, None),
        ({"carrier": "jpg"}, PASSWORD),
    ],
)
def test_native_probe_identifies_embedded_7z_payload_offset(tmp_path, case_kwargs, password):
    require_7z()
    kwargs = dict(case_kwargs)
    if password:
        kwargs["password"] = password
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"native_embedded_7z_probe_{'_'.join(case_kwargs)}_{bool(password)}",
        "7z",
        **kwargs,
    )
    tester = get_native_password_tester()
    parts = _parts(case)

    probe = tester.probe_archive(str(case.entry_path), part_paths=parts)

    assert probe.is_archive
    assert probe.archive_type == "7z"
    assert probe.offset > 0
    if password:
        assert probe.is_encrypted
        assert tester.test_archive(str(case.entry_path), part_paths=parts).encrypted
        assert tester.test_archive(str(case.entry_path), password=password, part_paths=parts).ok
    else:
        assert not probe.is_encrypted
        assert tester.test_archive(str(case.entry_path), part_paths=parts).ok


def test_native_password_attempts_use_dll_ranges_for_archive_input(tmp_path):
    require_7z()
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "native_password_dll_archive_input_range",
        "7z",
        password=PASSWORD,
        carrier="jpg",
    )
    tester = get_native_password_tester()
    probe = tester.probe_archive(str(case.entry_path), part_paths=_parts(case))
    archive_input = {
        "kind": "archive_input",
        "entry_path": str(case.entry_path),
        "open_mode": "file_range",
        "format_hint": "7z",
        "parts": [{"path": str(case.entry_path), "start": probe.offset}],
    }

    range_probe = tester.probe_archive(str(case.entry_path), archive_input=archive_input)
    assert range_probe.is_archive
    assert range_probe.is_encrypted
    assert range_probe.archive_type == "7z"
    assert tester.test_archive(str(case.entry_path), password=PASSWORD, archive_input=archive_input).ok

    attempt = tester.try_passwords(
        str(case.entry_path),
        [WRONG_PASSWORD, PASSWORD],
        archive_input=archive_input,
    )

    assert attempt.ok
    assert attempt.matched_index == 1


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_native_wrapper_handles_7z_sfx_split_probe_password_and_resources(tmp_path, password):
    require_7z()
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"native_7z_sfx_split_pwd_{bool(password)}",
        "7z",
        split=True,
        sfx=True,
        password=password,
    )
    tester = get_native_password_tester()
    parts = _parts(case)

    probe = tester.probe_archive(str(case.entry_path), part_paths=parts)
    if password:
        assert probe.is_encrypted
        assert tester.test_archive(str(case.entry_path), password=password, part_paths=parts).ok
        attempt = tester.try_passwords(str(case.entry_path), [WRONG_PASSWORD, password], part_paths=parts)
        assert attempt.ok
        assert attempt.matched_index == 1
    else:
        assert probe.ok
        assert tester.test_archive(str(case.entry_path), part_paths=parts).ok

    analysis = tester.analyze_archive_resources(str(case.entry_path), password or "", part_paths=parts)
    assert analysis.ok
    assert analysis.file_count >= 1


def test_native_wrapper_detects_missing_7z_sfx_split_tail(tmp_path):
    require_7z()
    case = ArchiveFixtureFactory().create(tmp_path, "native_7z_sfx_missing_tail", "7z", split=True, sfx=True)
    _remove_last_data_part(case)

    probe = get_native_password_tester().probe_archive(str(case.entry_path), part_paths=_parts(case))

    assert probe.missing_volume


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_native_wrapper_handles_zip_sfx_split_probe_password_and_resources(tmp_path, password):
    require_7z()
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"native_zip_sfx_split_pwd_{bool(password)}",
        "zip",
        split=True,
        sfx=True,
        password=password,
    )
    tester = get_native_password_tester()
    parts = _parts(case)

    probe = tester.probe_archive(str(case.entry_path), part_paths=parts)
    if password:
        assert probe.is_encrypted
        assert tester.test_archive(str(case.entry_path), password=password, part_paths=parts).ok
        attempt = tester.try_passwords(str(case.entry_path), [WRONG_PASSWORD, password], part_paths=parts)
        assert attempt.ok
        assert attempt.matched_index == 1
    else:
        assert probe.ok
        assert tester.test_archive(str(case.entry_path), part_paths=parts).ok

    analysis = tester.analyze_archive_resources(str(case.entry_path), password or "", part_paths=parts)
    assert analysis.ok
    assert analysis.file_count >= 1


def test_native_wrapper_detects_zip_sfx_missing_tail_from_eocd_requirement(tmp_path):
    require_7z()
    case = ArchiveFixtureFactory().create(tmp_path, "native_zip_sfx_missing_tail", "zip", split=True, sfx=True)
    _remove_last_data_part(case)

    probe = get_native_password_tester().probe_archive(str(case.entry_path), part_paths=_parts(case))

    assert probe.missing_volume
    assert probe.missing_volume_evidence == "zip_eocd_unavailable"


def test_native_wrapper_detects_damaged_zip_sfx_split_tail(tmp_path):
    require_7z()
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "native_zip_sfx_damaged_tail",
        "zip",
        split=True,
        sfx=True,
        payload_size=350_000,
    )
    parts = sorted(
        path for path in case.archive_dir.iterdir()
        if path.is_file() and not path.name.lower().endswith(".exe")
    )
    if len(parts) < 2:
        pytest.skip("generated ZIP SFX archive has no tail data volume")
    parts[-1].write_bytes(b"\0" * parts[-1].stat().st_size)

    tester = get_native_password_tester()
    probe = tester.probe_archive(str(case.entry_path), part_paths=_parts(case))

    assert probe.missing_volume
    assert probe.missing_volume_evidence == "zip_eocd_unavailable"
    full_test = tester.test_archive(str(case.entry_path), part_paths=_parts(case))
    assert full_test.checksum_error or not full_test.ok


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_native_wrapper_handles_rar_sfx_split_probe_password_and_resources(tmp_path, password):
    require_7z()
    if not get_optional_rar_sfx():
        pytest.skip("RAR SFX generator is not configured")
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"native_rar_sfx_split_pwd_{bool(password)}",
        "rar",
        split=True,
        sfx=True,
        password=password,
    )
    tester = get_native_password_tester()
    parts = _parts(case)

    probe = tester.probe_archive(str(case.entry_path), part_paths=parts)
    if password:
        assert probe.is_encrypted
        assert tester.test_archive(str(case.entry_path), password=password, part_paths=parts).ok
        attempt = tester.try_passwords(str(case.entry_path), [WRONG_PASSWORD, password], part_paths=parts)
        assert attempt.ok
        assert attempt.matched_index == 1
    else:
        assert probe.ok
        assert tester.test_archive(str(case.entry_path), part_paths=parts).ok

    analysis = tester.analyze_archive_resources(str(case.entry_path), password or "", part_paths=parts)
    assert analysis.ok
    assert analysis.file_count >= 1


def test_native_wrapper_detects_missing_rar_sfx_split_tail(tmp_path):
    require_7z()
    if not get_optional_rar_sfx():
        pytest.skip("RAR SFX generator is not configured")
    case = ArchiveFixtureFactory().create(tmp_path, "native_rar_sfx_missing_tail", "rar", split=True, sfx=True)
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    parts[-1].unlink()

    probe = get_native_password_tester().probe_archive(str(case.entry_path), part_paths=_parts(case))

    assert probe.missing_volume


@pytest.mark.parametrize(
    ("archive_format", "case_kwargs"),
    [
        ("7z", {"sfx": True}),
        ("7z", {"carrier": "jpg"}),
        ("rar", {}),
        ("rar", {"split": True}),
    ],
)
def test_native_password_retry_reaches_correct_password_after_wrong_passwords(tmp_path, archive_format, case_kwargs):
    require_7z()
    if archive_format == "rar" and not get_optional_rar():
        pytest.skip("RAR generator is not configured")
    case = ArchiveFixtureFactory().create(
        tmp_path,
        f"native_retry_after_wrong_{archive_format}_{'_'.join(case_kwargs) or 'plain'}",
        archive_format,
        password=PASSWORD,
        **case_kwargs,
    )

    attempt = get_native_password_tester().try_passwords(
        str(case.entry_path),
        [WRONG_PASSWORD, "still-wrong", PASSWORD],
        part_paths=_parts(case),
    )

    assert attempt.ok
    assert attempt.matched_index == 2
