import json
from pathlib import Path

from sunpack.contracts.detection import FactBag
from sunpack.contracts.run_context import RunContext
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner, _proves_content_loss
from tests.helpers.async_batch import run_extract_verify
from sunpack.contracts.extraction import ExtractionResult
from sunpack.contracts.results import OutcomeKind
from sunpack.repair.result import RepairResult
from sunpack.verification import VerificationScheduler
from sunpack.contracts.verification import (
    CONTAINER_INTEGRITY_STRUCTURALLY_DAMAGED,
    DECISION_REPAIR,
    VerificationResult,
)


def test_partial_extraction_manifest_produces_accept_partial_assessment(tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"broken")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    good = out_dir / "good.txt"
    bad = out_dir / "bad.bin"
    good.write_text("ok", encoding="utf-8")
    bad.write_bytes(b"partial")
    manifest = _write_manifest(
        out_dir,
        archive,
        [
            {"path": str(good), "archive_path": "good.txt", "status": "complete", "bytes_written": 2, "expected_size": 2},
            {"path": str(bad), "archive_path": "bad.bin", "status": "failed", "bytes_written": 0, "expected_size": 20},
        ],
    )
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        error="crc error",
        partial_outputs=True,
        progress_manifest=str(manifest),
        diagnostics={"result": {"failure_stage": "item_extract", "failure_kind": "checksum_error", "native_status": "damaged"}},
    )

    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "extraction_exit_signal"}],
        }
    }).verify(_task(archive), result)

    assert verification.decision_hint == "accept_partial"
    assert verification.assessment_status == "partial"
    assert verification.content_integrity == "payload_damaged"
    assert verification.completeness == 0.5
    assert verification.complete_files == 1
    assert verification.failed_files == 1


def test_repair_loop_keeps_original_partial_when_repaired_attempt_is_worse(tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"broken")
    out_dir = tmp_path / "out"
    extractor = _TwoPartialResultsExtractor(archive)
    runner = ExtractionBatchRunner(
        RunContext(),
        extractor,
        _FakeOutputScanPolicy(),
        config={
            "extraction": {"content_requirement": "allow_partial"},
            "repair": {"enabled": True, "workspace": str(tmp_path / "repair"), "max_repair_rounds_per_task": 1},
            "verification": {
                "enabled": True,
                "methods": [{"name": "extraction_exit_signal"}, {"name": "output_presence"}],
                "recovery_min_improvement": 0.0,
            },
        },
    )
    runner.repair_stage = _OneShotRepairStage()

    outcome = run_extract_verify(runner, _task(archive), str(out_dir))

    assert outcome.outcome_kind == OutcomeKind.PARTIAL_SUCCESS
    assert outcome.verification is not None
    assert outcome.verification.archive_coverage.complete_files == 3
    assert (out_dir / "good-0.txt").exists()
    assert (out_dir / "good-1.txt").exists()
    assert (out_dir / "good-2.txt").exists()
    assert not (out_dir / "worse-only.txt").exists()


def test_output_presence_ignores_sunpack_manifest_files(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    out_dir = tmp_path / "out"
    (out_dir / ".sunpack").mkdir(parents=True)
    (out_dir / ".sunpack" / "extraction_manifest.json").write_text("{}", encoding="utf-8")
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])

    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "output_presence"}],
        }
    }).verify(_task(archive), result)

    assert verification.decision_hint == "fail"
    assert verification.issues[0].code == "fail.output_empty"


def test_main_flow_accepts_recoverable_partial_after_repair_has_no_candidate(tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"broken")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    good = out_dir / "good.txt"
    partial = out_dir / "partial.bin"
    failed = out_dir / "failed.bin"
    good.write_text("ok", encoding="utf-8")
    partial.write_bytes(b"half")
    failed.write_bytes(b"bad")
    manifest = _write_manifest(
        out_dir,
        archive,
        [
            {"path": str(good), "archive_path": "good.txt", "status": "complete", "bytes_written": 2, "expected_size": 2},
            {"path": str(partial), "archive_path": "partial.bin", "status": "partial", "bytes_written": 4, "expected_size": 8},
            {"path": str(failed), "archive_path": "failed.bin", "status": "failed", "bytes_written": 0, "expected_size": 10},
        ],
    )
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        error="crc error",
        partial_outputs=True,
        progress_manifest=str(manifest),
        diagnostics={"result": {"failure_stage": "item_extract", "failure_kind": "checksum_error", "native_status": "damaged"}},
    )
    runner = ExtractionBatchRunner(
        RunContext(),
        _SingleResultExtractor(result),
        _FakeOutputScanPolicy(),
            config={
                "extraction": {"content_requirement": "allow_partial"},
                "repair": {"enabled": True, "workspace": str(tmp_path / "repair"), "max_repair_rounds_per_task": 1},
            "verification": {
                "enabled": True,
                "methods": [{"name": "extraction_exit_signal"}],
                "recovery_min_improvement": 0.0,
            },
        },
    )
    runner.repair_stage = _NoCandidateRepairStage()

    task = _task(archive)
    outcome = run_extract_verify(runner, task, str(out_dir))

    assert outcome.outcome_kind == OutcomeKind.PARTIAL_SUCCESS
    assert outcome.verification is not None
    assert outcome.verification.decision_hint == "accept_partial"
    assert good.exists()
    assert not partial.exists()
    assert not failed.exists()
    assert runner.collect_result(task, outcome) == str(out_dir)
    assert runner.context.partial_success_count == 1
    assert runner.context.success_count == 0
    assert runner.context.flatten_candidates == set()
    recovered = runner.context.recovered_outputs[0]
    assert recovered["archive_coverage"]["expected_files"] == 3
    report_text = (out_dir / ".sunpack" / "recovery_report.json").read_text(encoding="utf-8")
    assert "\n" not in report_text
    report = json.loads(report_text)
    assert report["success_kind"] == "partial"
    assert report["archive_coverage"]["expected_files"] == 3
    file_statuses = {item["archive_path"]: item["status"] for item in report["files"]}
    assert file_statuses["good.txt"] == "complete"
    assert file_statuses["partial.bin"] == "discarded"
    assert file_statuses["failed.bin"] == "failed"
    assert {item["user_action"] for item in report["files"]} >= {"safe_to_use", "discarded_low_quality", "not_recovered"}
    manifest_text = manifest.read_text(encoding="utf-8")
    assert "\n" not in manifest_text
    manifest_payload = json.loads(manifest_text)
    assert manifest_payload["recovery"]["verification"]["decision_hint"] == "accept_partial"


def test_complete_mode_stops_before_repair_on_proven_payload_damage_and_cleans_output(
    tmp_path,
):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"broken")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    recovered = out_dir / "recovered.txt"
    recovered.write_text("partial", encoding="utf-8")
    manifest = _write_manifest(
        out_dir,
        archive,
        [{
            "path": str(recovered),
            "archive_path": "recovered.txt",
            "status": "complete",
            "bytes_written": 7,
            "expected_size": 7,
        }, {
            "path": str(out_dir / "lost.bin"),
            "archive_path": "lost.bin",
            "status": "failed",
            "bytes_written": 0,
            "expected_size": 10,
        }],
    )
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        error="crc error",
        partial_outputs=True,
        progress_manifest=str(manifest),
        diagnostics={
            "result": {
                "failure_stage": "item_extract",
                "failure_kind": "checksum_error",
            }
        },
    )

    class CountingRepairStage(_NoCandidateRepairStage):
        def __init__(self):
            self.calls = 0

        def repair_after_verification_assessment_result(self, task, result, verification):
            self.calls += 1
            return None

    runner = ExtractionBatchRunner(
        RunContext(),
        _SingleResultExtractor(result),
        _FakeOutputScanPolicy(),
        config={
            "extraction": {"content_requirement": "complete"},
            "repair": {
                "enabled": True,
                "workspace": str(tmp_path / "repair"),
                "max_repair_rounds_per_task": 5,
            },
            "verification": {
                "enabled": True,
                "methods": [{"name": "extraction_exit_signal"}],
            },
        },
    )
    repair_stage = CountingRepairStage()
    runner.repair_stage = repair_stage
    task = _task(archive)

    outcome = run_extract_verify(runner, task, str(out_dir))

    assert repair_stage.calls == 0
    assert outcome.outcome_kind == OutcomeKind.FAILURE
    outcome.planned_out_dir = str(out_dir)
    assert runner.collect_result(task, outcome) is None
    assert not out_dir.exists()


def test_structural_container_error_alone_does_not_prove_content_loss(tmp_path):
    archive = tmp_path / "broken.zip"
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(tmp_path / "out"),
        all_parts=[str(archive)],
        error="headers error",
        diagnostics={
            "result": {
                "failure_stage": "archive_open",
                "failure_kind": "headers_error",
            }
        },
    )
    verification = VerificationResult(
        container_integrity=CONTAINER_INTEGRITY_STRUCTURALLY_DAMAGED,
        decision_hint=DECISION_REPAIR,
    )

    assert _proves_content_loss(result, verification) is False


class _SingleResultExtractor:
    password_session = None

    def __init__(self, result):
        self.result = result

    def default_output_dir_for_task(self, task):
        return self.result.out_dir

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, *, phase_timer=None, phase_prefix="extract"):
        return self.result


class _TwoPartialResultsExtractor:
    password_session = None

    def __init__(self, archive):
        self.archive = archive
        self.calls = 0

    def default_output_dir_for_task(self, task):
        return str(self.archive.with_suffix(""))

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, *, phase_timer=None, phase_prefix="extract"):
        self.calls += 1
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        if self.calls == 1:
            files = []
            for index in range(3):
                path = out_path / f"good-{index}.txt"
                path.write_text(f"good-{index}", encoding="utf-8")
                files.append({
                    "path": str(path),
                    "archive_path": f"good-{index}.txt",
                    "status": "complete",
                    "bytes_written": 6,
                    "expected_size": 6,
                })
            files.append({
                "path": str(out_path / "bad.bin"),
                "archive_path": "bad.bin",
                "status": "failed",
                "bytes_written": 0,
                "expected_size": 10,
            })
        else:
            path = out_path / "worse-only.txt"
            path.write_text("worse", encoding="utf-8")
            files = [
                {"path": str(path), "archive_path": "worse-only.txt", "status": "complete", "bytes_written": 5, "expected_size": 5},
                {"path": str(out_path / "missing-1.bin"), "archive_path": "missing-1.bin", "status": "failed", "bytes_written": 0, "expected_size": 10},
                {"path": str(out_path / "missing-2.bin"), "archive_path": "missing-2.bin", "status": "failed", "bytes_written": 0, "expected_size": 10},
                {"path": str(out_path / "missing-3.bin"), "archive_path": "missing-3.bin", "status": "failed", "bytes_written": 0, "expected_size": 10},
            ]
        manifest = _write_manifest(out_path, self.archive, files)
        return ExtractionResult(
            success=False,
            archive=str(self.archive),
            out_dir=str(out_path),
            all_parts=[str(self.archive)],
            error="crc error",
            partial_outputs=True,
            progress_manifest=str(manifest),
            diagnostics={"result": {"failure_stage": "item_extract", "failure_kind": "checksum_error", "native_status": "damaged"}},
        )


class _OneShotRepairStage:
    config = {
        "max_repair_rounds_per_task": 1,
        "max_repair_seconds_per_task": 120.0,
        "max_repair_generated_files_per_task": 16,
        "max_repair_generated_mb_per_task": 2048.0,
    }

    def __init__(self):
        self.calls = 0
        self.scheduler = None

    def repair_after_verification_assessment_result(self, task, result, verification):
        self.calls += 1
        if self.calls > 1:
            return None
        repaired_input = {"kind": "file", "path": task.main_path, "format_hint": task.detected_ext}
        return RepairResult(
            status="repaired",
            confidence=0.5,
            format=task.detected_ext,
            repaired_input=repaired_input,
            module_name="fake_worse_repair",
        )


class _FakeOutputScanPolicy:
    def scan_roots_from_outputs(self, outputs):
        return list(outputs)


class _NoCandidateRepairStage:
    config = {
        "max_repair_rounds_per_task": 1,
        "max_repair_seconds_per_task": 120.0,
        "max_repair_generated_files_per_task": 16,
        "max_repair_generated_mb_per_task": 2048.0,
    }

    scheduler = None

    def repair_after_verification_assessment_result(self, task, result, verification):
        return None


def _task(path):
    return ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        key=path.name,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
        detected_ext=path.suffix.lstrip("."),
    )


def _write_manifest(out_dir, archive, files):
    summary = {"complete": 0, "partial": 0, "failed": 0, "skipped": 0, "unverified": 0, "total": len(files)}
    for item in files:
        summary[item["status"]] += 1
    manifest = out_dir / ".sunpack" / "extraction_manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({
        "version": 1,
        "archive": str(archive),
        "out_dir": str(out_dir),
        "partial_outputs": True,
        "failure_stage": "item_extract",
        "failure_kind": "checksum_error",
        "native_status": "damaged",
        "summary": summary,
        "files": files,
    }, ensure_ascii=False), encoding="utf-8")
    return manifest
