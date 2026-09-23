import zipfile

from tests.helpers.archive_tasks import make_archive_task
from sunpack.contracts.extraction import ExtractionResult
from sunpack.verification import VerificationScheduler


def test_expected_name_matching_is_case_and_path_normalized(tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("docs/readme.txt", "hello")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "Docs").mkdir()
    (out_dir / "Docs" / "Readme.TXT").write_text("hello", encoding="utf-8")
    task = make_archive_task(archive, key="sample", format_hint="zip")
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])

    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "expected_name_presence"}],
        }
    }).verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.assessment_status == "complete"
    assert verification.completeness == 1.0
