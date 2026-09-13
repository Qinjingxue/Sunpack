from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.internal.workflow.preflight import PreExtractInspector


def _task(tmp_path, *, status: str, confidence: str) -> ArchiveTask:
    archive = tmp_path / "sample.part1.123"
    archive.write_bytes(b"archive")
    facts = FactBag()
    facts.set("relation.split_completeness_status", status)
    facts.set("relation.split_completeness_confidence", confidence)
    facts.set("relation.split_completeness_basis", ["observed_number_gap"])
    facts.set("relation.split_missing_indices", [2])
    return ArchiveTask(
        fact_bag=facts,
        key=archive.name,
        main_path=str(archive),
        all_parts=[str(archive)],
        logical_name="sample",
        detected_ext="7z",
    )


def test_complete_mode_preflight_rejects_only_proven_missing_volume(tmp_path):
    task = _task(tmp_path, status="middle_gap", confidence="proven")

    result = PreExtractInspector(None, None, {"content_requirement": "complete"}).inspect(
        task,
        str(tmp_path / "out"),
    )

    assert result.skip_result is not None
    assert result.skip_result.failure is not None
    assert result.skip_result.failure.kind.value == "missing_volume"
    assert result.skip_result.failure.details["missing_indices"] == [2]


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
