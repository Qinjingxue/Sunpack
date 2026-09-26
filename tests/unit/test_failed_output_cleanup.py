from __future__ import annotations

import pytest

from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.run_state import RunState
from sunpack.core.contracts.verification import VerificationResult
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.archive_job import ArchiveJobOutcome, ArchiveJobExecutor
from sunpack.pipeline.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.pipeline.postprocess.failed_output_cleanup import cleanup_failed_output_if_eligible
from tests.helpers.archive_tasks import make_archive_task


@pytest.mark.parametrize("with_zero_file", [False, True])
def test_cleanup_removes_failed_output_with_no_payload_bytes(tmp_path, with_zero_file):
    output = tmp_path / "output"
    metadata = output / ".sunpack"
    metadata.mkdir(parents=True)
    (metadata / "diagnostic.json").write_text('{"error": true}', encoding="utf-8")
    if with_zero_file:
        (output / "empty.txt").write_bytes(b"")

    result = cleanup_failed_output_if_eligible(
        str(output),
        planned_output_dir=str(output),
        failed=True,
    )

    assert result.cleaned is True
    assert not output.exists()


@pytest.mark.parametrize(
    ("failed", "planned_matches", "expected_reason"),
    [
        (False, True, "task_not_failed"),
        (True, False, "unowned_output_dir"),
    ],
)
def test_cleanup_preserves_output_when_gate_is_not_satisfied(
    tmp_path,
    failed,
    planned_matches,
    expected_reason,
):
    output = tmp_path / "output"
    output.mkdir()

    result = cleanup_failed_output_if_eligible(
        str(output),
        planned_output_dir=str(output if planned_matches else tmp_path / "different"),
        failed=failed,
    )

    assert result.reason == expected_reason
    assert output.is_dir()


def test_cleanup_preserves_failed_output_with_nonzero_payload(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "payload.bin").write_bytes(b"x")

    result = cleanup_failed_output_if_eligible(
        str(output),
        planned_output_dir=str(output),
        failed=True,
    )

    assert result.reason == "nonempty_payload"
    assert result.payload_bytes == 1
    assert output.is_dir()


def test_complete_embedded_children_are_not_policy_rejected_with_failed_siblings():
    child = ExtractionResult(True, "child")
    failure = FailureInfo(
        kind=FailureKind.EMBEDDED_SEGMENTS_FAILED,
        stage="embedded_segments",
        message="one encrypted child failed",
    )
    outer = ExtractionResult(
        success=False,

        out_dir="output",

        failure=failure,
        partial_outputs=True,
        embedded_results=[({"segment_id": "plain"}, child)],
    )

    assert ArchiveJobOutcome(result=outer).policy_rejected_partial_output is False


def test_collect_result_applies_main_pipeline_cleanup_after_diagnostics(tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"broken")
    output = tmp_path / "broken"
    output.mkdir()
    (output / "empty.txt").write_bytes(b"")
    task = make_archive_task(
        archive,
        logical_name="broken",
        format_hint="zip",
    )
    extraction = ExtractionResult(
        success=False,

        out_dir=str(output),

        error="damaged",
    )
    outcome = ArchiveJobOutcome(result=extraction, planned_out_dir=str(output))
    runner = object.__new__(ArchiveJobExecutor)
    runner.context = RunState()
    runner.config = {}

    returned = runner.collect_result(task, outcome)

    assert returned.outcome_kind == OutcomeKind.FAILURE
    assert returned.output_dir == str(output)
    assert not output.exists()
    assert extraction.diagnostics["failed_output_cleanup"]["cleaned"] is True
    assert [item.failure_message for item in runner.context.target_results] == [
        "broken.zip [damaged]"
    ]
