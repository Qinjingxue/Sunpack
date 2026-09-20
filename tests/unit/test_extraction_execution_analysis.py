from sunpack.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence, ArchiveSegment
from sunpack.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart
from sunpack.contracts.archive_state import ArchiveState
from sunpack.detection.input_planning import ArchiveInputPlanningStage


def test_archive_state_projects_analysis_into_execution_descriptor():
    descriptor = ArchiveInputDescriptor.from_parts(
        archive_path="payload.7z",
        format_hint="7z",
    )
    state = ArchiveState.from_archive_input(
        descriptor,
        analysis={
            "status": "extractable",
            "execution": {"missing_volume_evidence": "seven_zip_start_header_length"},
        },
    )

    projected = state.to_archive_input_descriptor()

    assert projected.analysis["status"] == "extractable"
    assert projected.analysis["execution"]["missing_volume_evidence"] == "seven_zip_start_header_length"


def test_planning_projects_proven_7z_split_tail_without_native_rescan():
    descriptor = ArchiveInputDescriptor(
        entry_path="payload.7z.001",
        open_mode="native_volumes",
        format_hint="7z",
        logical_name="payload",
        volume_style="numeric_suffix",
        parts=[
            ArchiveInputPart(
                path="payload.7z.001",
                role="first",
                volume_number=1,
                canonical_name="payload.7z.001",
            ),
            ArchiveInputPart(
                path="payload.7z.002",
                role="member",
                volume_number=2,
                canonical_name="payload.7z.002",
            ),
        ],
    )
    state = ArchiveState.from_archive_input(descriptor)
    evidence = ArchiveFormatEvidence(
        format="7z",
        confidence=0.80,
        status="damaged",
        segments=[
            ArchiveSegment(
                start_offset=0,
                end_offset=None,
                confidence=0.80,
                damage_flags=["next_header_out_of_range"],
            )
        ],
        details={
            "start_header_crc_ok": True,
            "archive_offset": 0,
            "next_header_offset": 80,
            "next_header_size": 16,
            "error": "next_header_out_of_range",
        },
    )
    report = ArchiveAnalysisReport(
        path="payload.7z.001",
        size=100,
        evidences=[evidence],
        selected=[],
    )

    execution = ArchiveInputPlanningStage._execution_analysis_for_report(state, report)

    assert execution == {"missing_volume_evidence": "seven_zip_start_header_length"}


def test_planning_does_not_label_single_truncated_7z_as_missing_volume():
    descriptor = ArchiveInputDescriptor.from_parts(
        archive_path="payload.7z",
        format_hint="7z",
    )
    state = ArchiveState.from_archive_input(descriptor)
    evidence = ArchiveFormatEvidence(
        format="7z",
        confidence=0.80,
        status="damaged",
        details={
            "start_header_crc_ok": True,
            "archive_offset": 0,
            "next_header_offset": 80,
            "next_header_size": 16,
            "error": "next_header_out_of_range",
        },
    )
    report = ArchiveAnalysisReport(
        path="payload.7z",
        size=100,
        evidences=[evidence],
        selected=[],
    )

    assert ArchiveInputPlanningStage._execution_analysis_for_report(state, report) == {}
