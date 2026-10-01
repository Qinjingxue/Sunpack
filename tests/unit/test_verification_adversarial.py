import zipfile

from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.pipeline.verification import VerificationScheduler
from tests.helpers.archive_tasks import make_archive_task
from tests.helpers.config_factory import make_config


def test_manifest_matching_is_case_and_path_normalized(tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("docs/readme.txt", "hello")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "Docs").mkdir()
    (out_dir / "Docs" / "Readme.TXT").write_text("hello", encoding="utf-8")
    task = make_archive_task(archive, key="sample", format_hint="zip")
    result = ExtractionResult(success=True, out_dir=str(out_dir))

    verification = VerificationScheduler(make_config({
        "verification": {
            "enabled": True,
            "methods": [{"name": "manifest_size_match"}],
        }
    })).verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.assessment_status == "complete"
    assert verification.completeness == 1.0
