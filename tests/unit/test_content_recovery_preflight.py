from sunpack.extraction.internal.workflow.preflight import PreExtractInspector
from tests.helpers.archive_tasks import make_archive_task


def _task(tmp_path, *, status: str, confidence: str):
    del status, confidence
    archive = tmp_path / "sample.part1.123"
    archive.write_bytes(b"archive")
    return make_archive_task(
        archive,
        key=archive.name,
        logical_name="sample",
        format_hint="7z",
    )


def test_complete_mode_ignores_removed_scan_time_missing_volume_facts(tmp_path):
    task = _task(tmp_path, status="middle_gap", confidence="proven")

    result = PreExtractInspector(None, None, {"content_requirement": "complete"}).inspect(
        task,
        str(tmp_path / "out"),
    )

    assert result.skip_result is None


def test_complete_mode_does_not_convict_from_strong_name_evidence_alone(tmp_path):
    task = _task(tmp_path, status="tail_missing", confidence="strong")

    result = PreExtractInspector(None, None, {"content_requirement": "complete"}).inspect(
        task,
        str(tmp_path / "out"),
    )

    assert result.skip_result is None


def test_allow_partial_mode_does_not_preflight_reject_proven_missing_volume(tmp_path):
    task = _task(tmp_path, status="middle_gap", confidence="proven")

    result = PreExtractInspector(None, None, {"content_requirement": "allow_partial"}).inspect(
        task,
        str(tmp_path / "out"),
    )

    assert result.skip_result is None
