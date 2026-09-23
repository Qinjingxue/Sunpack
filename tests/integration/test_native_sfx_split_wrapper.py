import pytest

from sunpack.core.config.loader import load_config
from sunpack.pipeline.coordinator.task_scan import direct_file_task
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.core.passwords.verifier.rar_fast import RarFastVerifier
from sunpack.core.passwords.verifier.seven_zip_fast import SevenZipFastVerifier
from sunpack.core.passwords.verifier.zip_fast import ZipFastVerifier
from sunpack.core.support import archive_knowledge_projection as knowledge_view
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar_sfx, require_7z


PASSWORD = "sfx-split-secret"
WRONG_PASSWORD = "wrong-sfx-password"

FAST_VERIFIERS = {
    "7z": SevenZipFastVerifier,
    "zip": ZipFastVerifier,
    "rar": RarFastVerifier,
}


def _parts(case):
    return sorted(str(path) for path in case.archive_dir.iterdir() if path.is_file())


@pytest.mark.parametrize("archive_format", ["7z", "zip", "rar"])
def test_input_planned_sfx_uses_rust_password_verifier(tmp_path, archive_format):
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

    ArchiveInputPlanningStage(load_config()).plan_task(task)
    probe_input = knowledge_view.source_password_probe_input(task)
    outcome = FAST_VERIFIERS[archive_format]().verify_batch(
        str(case.entry_path),
        [WRONG_PASSWORD, PASSWORD],
        part_paths=parts,
        archive_input=probe_input,
    )

    assert outcome.status == "match", outcome
    matched_indices = outcome.matched_indices or (outcome.matched_index,)
    assert 1 in matched_indices, outcome
    assert probe_input["open_mode"] in {"file_range", "concat_ranges"}

    if archive_format == "zip":
        assert outcome.match_evidence == "zipcrypto_header_byte", outcome
        assert outcome.final_confirmation_required is True, outcome
    elif archive_format == "7z":
        assert outcome.final_confirmation_required is False, outcome
