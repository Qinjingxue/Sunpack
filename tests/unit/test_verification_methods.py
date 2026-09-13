import json
import zlib
import zipfile

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.contracts.extraction import ExtractionResult
from sunpack.verification import VerificationScheduler
from sunpack.verification import archive_state_manifest as archive_state_manifest_module


@pytest.mark.parametrize(
    ("success", "progress", "expected_issue"),
    [
        (False, None, "fail.extraction_failed"),
        (True, {"files_written": 0, "bytes_written": 0, "files": []}, "fail.extraction_success_empty"),
    ],
    ids=["failed", "success-empty"],
)
def test_extraction_exit_signal_reports_unusable_extraction(tmp_path, success, progress, expected_issue):
    task = _task(tmp_path)
    out_dir = tmp_path / "out"
    result = ExtractionResult(
        success=success,
        archive=task.main_path,
        out_dir=str(out_dir),
        all_parts=task.all_parts,
        error="boom" if not success else None,
        progress_manifest_payload=progress,
    )
    if success:
        out_dir.mkdir()

    verification = _scheduler([{"name": "extraction_exit_signal"}]).verify(task, result)

    assert verification.decision_hint == "retry_extract"
    assert verification.assessment_status == "unusable"
    assert verification.completeness == 0.0
    assert verification.issues[0].code == expected_issue


def test_output_presence_reports_missing_or_empty_output_as_unusable(tmp_path):
    task = _task(tmp_path)
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(tmp_path / "missing"), all_parts=task.all_parts)

    missing = _scheduler([{"name": "output_presence"}]).verify(task, result)

    assert missing.decision_hint == "fail"
    assert missing.assessment_status == "unusable"
    assert missing.issues[0].code == "fail.output_missing"

    out_dir = tmp_path / "empty"
    out_dir.mkdir()
    result.out_dir = str(out_dir)
    empty = _scheduler([{"name": "output_presence"}]).verify(task, result)

    assert empty.decision_hint == "fail"
    assert empty.issues[0].code == "fail.output_empty"


def test_manifest_size_match_reports_complete_when_expected_size_matches(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "a.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {"file_count": 1, "total_unpacked_size": 5})
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "manifest_size_match"}]).verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.assessment_status == "complete"
    assert verification.completeness == 1.0


def test_manifest_size_match_reports_retry_for_large_manifest_gap(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "a.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {"file_count": 10, "total_unpacked_size": 10 * 1024 * 1024})
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "manifest_size_match"}]).verify(task, result)

    assert verification.decision_hint == "retry_extract"
    assert verification.assessment_status == "partial"
    assert verification.completeness < 1.0
    assert {issue.code for issue in verification.issues} == {
        "fail.manifest_file_count_under",
        "fail.manifest_size_under",
    }


def test_expected_name_presence_reports_missing_entries(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "actual.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {
        "expected_names": ["expected.txt", "missing.bin"],
        "expected_names_source": "manifest",
    })
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "expected_name_presence"}]).verify(task, result)

    assert verification.decision_hint == "retry_extract"
    assert verification.missing_files == 2
    assert verification.issues[0].code == "fail.expected_names_all_missing"


def test_expected_name_presence_skips_without_manifest_names(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "actual.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path)
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "expected_name_presence"}]).verify(task, result)


def test_oracle_expected_output_match_reports_complete_crc_and_size_match(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    payload = b"hello oracle"
    (out_dir / "a.txt").write_bytes(payload)
    task = _task(tmp_path, oracle={
        "expected_files": {
            "a.txt": {
                "name": "a.txt",
                "size": len(payload),
                "crc32": zlib.crc32(payload) & 0xFFFFFFFF,
            }
        },
        "oracle_strength": "entry_hash",
    })
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "oracle_expected_output_match"}]).verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.archive_coverage.expected_files == 1
    assert verification.archive_coverage.complete_files == 1
    assert verification.archive_coverage.completeness == 1.0


def test_oracle_expected_output_match_reports_missing_and_crc_failure(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "bad.bin").write_bytes(b"wrong")
    task = _task(tmp_path, oracle={
        "expected_files": {
            "bad.bin": {"name": "bad.bin", "size": 5, "crc32": zlib.crc32(b"right") & 0xFFFFFFFF},
            "missing.bin": {"name": "missing.bin", "size": 4, "crc32": 1234},
        }
    })
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "oracle_expected_output_match"}]).verify(task, result)

    assert verification.decision_hint == "retry_extract"
    assert verification.archive_coverage.expected_files == 2
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.missing_files == 1
    assert verification.archive_coverage.completeness < 1.0


def test_oracle_expected_output_match_skips_without_oracle_expected_files(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    task = _task(tmp_path)
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "oracle_expected_output_match"}]).verify(task, result)

    assert verification.methods_run == ["oracle_expected_output_match"]
    assert verification.archive_coverage.expected_files == 0
    assert verification.steps[0].status == "skipped"


def test_expected_name_presence_weak_damaged_source_sets_recoverable_upper_bound(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "present.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {
        "status": "damaged",
        "expected_names": ["present.txt", "maybe-missing.bin"],
        "expected_names_source": "local_header_recovery",
    })
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "expected_name_presence"}]).verify(task, result)

    assert verification.content_integrity == "unknown"
    assert verification.completeness == 0.5
    assert verification.recoverable_upper_bound == 0.5
    assert verification.decision_hint == "accept_partial"


def test_archive_test_crc_compares_archive_state_manifest_to_output_files(tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("good.txt", "hello")
        zf.writestr("bad.txt", "expected")
        zf.writestr("missing.txt", "not extracted")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "good.txt").write_text("hello", encoding="utf-8")
    (out_dir / "bad.txt").write_text("oops", encoding="utf-8")
    task = ArchiveTask(fact_bag=FactBag(), key="sample", main_path=str(archive), all_parts=[str(archive)], detected_ext="zip")
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])

    verification = _scheduler([{"name": "archive_test_crc"}]).verify(task, result)

    assert verification.decision_hint == "retry_extract"
    assert verification.complete_files == 1
    assert verification.failed_files == 1
    assert verification.missing_files == 1
    assert 0.0 < verification.completeness < 1.0
    coverage = [issue for issue in verification.issues if issue.code == "info.archive_output_coverage"][0]
    assert coverage.actual["expected_files"] == 3
    assert coverage.actual["matched_files"] == 2
    assert verification.archive_coverage.expected_files == 3
    assert verification.archive_coverage.matched_files == 2
    assert verification.archive_coverage.complete_files == 1
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.missing_files == 1
    assert verification.archive_coverage.sources[0]["code"] == "info.archive_output_coverage"


def test_zip_verification_methods_share_one_full_archive_manifest(tmp_path, monkeypatch):
    archive = tmp_path / "shared-manifest.zip"
    expected = {"one.txt": b"one", "two.txt": b"two", "three.txt": b"three"}
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, payload in expected.items():
            zf.writestr(name, payload)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    for name, payload in expected.items():
        (out_dir / name).write_bytes(payload)
    task = ArchiveTask(
        fact_bag=FactBag(), key="shared", main_path=str(archive),
        all_parts=[str(archive)], detected_ext="zip",
    )
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])
    calls = []
    native_manifest = archive_state_manifest_module._native_archive_state_zip_manifest

    def counted_manifest(source, max_items, password, codepage):
        calls.append(max_items)
        return native_manifest(source, max_items, password, codepage)

    monkeypatch.setattr(archive_state_manifest_module, "_native_archive_state_zip_manifest", counted_manifest)
    verification = _scheduler([
        {"name": "expected_name_presence", "max_expected_names": 1},
        {"name": "manifest_size_match", "max_expected_names": 2},
        {"name": "archive_test_crc", "max_items": 3},
    ]).verify(task, result)

    assert verification.decision_hint == "accept"
    assert calls == [3]


def test_archive_test_crc_unsupported_empty_failed_extraction_is_not_complete(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"7z damaged")
    out_dir = tmp_path / "missing-output"
    task = ArchiveTask(
        fact_bag=FactBag(),
        key="sample-7z",
        main_path=str(archive),
        all_parts=[str(archive)],
        detected_ext="7z",
    )
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        error="extract failed",
    )

    verification = _scheduler([{"name": "archive_test_crc"}]).verify(task, result)

    assert verification.steps[0].status == "skipped"
    assert verification.issues[0].code == "warning.archive_crc_state_unsupported"
    assert verification.completeness == 0.0
    assert verification.assessment_status != "complete"
    assert verification.decision_hint != "accept"
    assert verification.output_empty is True


def test_output_presence_uses_worker_manifest_progress_as_completeness(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    complete = out_dir / "complete.txt"
    partial = out_dir / "partial.bin"
    complete.write_text("ok", encoding="utf-8")
    partial.write_bytes(b"12345")
    manifest = out_dir / ".sunpack" / "extraction_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({
        "files": [
            {"path": str(complete), "archive_path": "complete.txt", "status": "complete", "bytes_written": 2, "expected_size": 2},
            {"path": str(partial), "archive_path": "partial.bin", "status": "partial", "bytes_written": 5, "expected_size": 10},
            {"path": "missing.bin", "archive_path": "missing.bin", "status": "failed", "bytes_written": 0, "expected_size": 10},
        ],
        "summary": {"complete": 1, "partial": 1, "failed": 1, "total": 3},
    }), encoding="utf-8")
    task = _task(tmp_path)
    result = ExtractionResult(
        success=True,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        progress_manifest=str(manifest),
    )

    verification = _scheduler([{"name": "output_presence"}]).verify(task, result)

    assert verification.complete_files == 1
    assert verification.partial_files == 1
    assert verification.failed_files == 1
    assert round(verification.completeness, 3) == 0.5
    assert verification.archive_coverage.expected_files == 3
    assert verification.archive_coverage.matched_files == 2
    assert verification.archive_coverage.expected_bytes == 22
    assert verification.archive_coverage.matched_bytes == 7
    assert round(verification.archive_coverage.completeness, 3) == 0.5


def _task(tmp_path, analysis=None, oracle=None):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    bag = FactBag()
    task = ArchiveTask(fact_bag=bag, key="sample", main_path=str(archive), all_parts=[str(archive)])
    knowledge = task.knowledge()
    if analysis is not None:
        knowledge.set("resource.analysis", analysis, source_layer="test", source_module="fixture")
        knowledge.set("inspection.prepass", analysis, source_layer="test", source_module="fixture")
        if analysis.get("expected_names"):
            knowledge.set("verification.expected_names", analysis["expected_names"], source_layer="test", source_module="fixture")
    if oracle is not None:
        knowledge.set("verification.oracle", oracle, source_layer="test", source_module="fixture")
    task.set_knowledge(knowledge)
    return task


def _scheduler(methods):
    return VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": methods,
        }
    })
