from sunpack.contracts.verification import (
    ASSESSMENT_COMPLETE,
    ASSESSMENT_PARTIAL,
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_VERIFIED_COMPLETE,
    DECISION_ACCEPT,
    DECISION_ACCEPT_PARTIAL,
    DECISION_FAIL,
    DECISION_RETRY_EXTRACT,
    VERIFICATION_STRENGTH_CRC,
    ArchiveCoverageSummary,
    VerificationResult,
)
from sunpack.verification.pipeline import aggregate_payload_verifications


def _verification(*, decision, integrity, completeness, complete=0, failed=0):
    return VerificationResult(
        completeness=completeness,
        recoverable_upper_bound=completeness,
        assessment_status=ASSESSMENT_COMPLETE if decision == DECISION_ACCEPT else ASSESSMENT_PARTIAL,
        content_integrity=integrity,
        verification_strength=VERIFICATION_STRENGTH_CRC,
        decision_hint=decision,
        complete_files=complete,
        failed_files=failed,
        output_file_count=complete,
        output_empty=complete == 0,
        output_quality_score=completeness,
        output_confidence=1.0,
        archive_coverage=ArchiveCoverageSummary(
            completeness=completeness,
            expected_files=complete + failed,
            matched_files=complete,
            complete_files=complete,
            failed_files=failed,
            confidence=1.0,
        ),
    )


def test_all_embedded_payloads_complete_make_carrier_complete():
    result = aggregate_payload_verifications([
        ({"segment_id": "zip", "format": "zip", "success": True}, _verification(
            decision=DECISION_ACCEPT,
            integrity=CONTENT_INTEGRITY_VERIFIED_COMPLETE,
            completeness=1.0,
            complete=2,
        )),
        ({"segment_id": "rar", "format": "rar", "success": True}, _verification(
            decision=DECISION_ACCEPT,
            integrity=CONTENT_INTEGRITY_VERIFIED_COMPLETE,
            completeness=1.0,
            complete=3,
        )),
    ])

    assert result.decision_hint == DECISION_ACCEPT
    assert result.assessment_status == ASSESSMENT_COMPLETE
    assert result.content_integrity == CONTENT_INTEGRITY_VERIFIED_COMPLETE
    assert result.archive_coverage.expected_files == 5
    assert result.archive_coverage.complete_files == 5


def test_one_damaged_embedded_payload_keeps_carrier_partial():
    result = aggregate_payload_verifications([
        ({"segment_id": "zip", "format": "zip", "success": True}, _verification(
            decision=DECISION_ACCEPT,
            integrity=CONTENT_INTEGRITY_VERIFIED_COMPLETE,
            completeness=1.0,
            complete=2,
        )),
        ({
            "segment_id": "rar",
            "format": "rar",
            "success": False,
            "partial_outputs": True,
        }, _verification(
            decision=DECISION_RETRY_EXTRACT,
            integrity=CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
            completeness=0.5,
            complete=1,
            failed=1,
        )),
    ])

    assert result.decision_hint == DECISION_ACCEPT_PARTIAL
    assert result.assessment_status == ASSESSMENT_PARTIAL
    assert result.content_integrity == CONTENT_INTEGRITY_PAYLOAD_DAMAGED
    assert result.completeness == 0.75
    assert result.archive_coverage.failed_files == 1


def test_verifier_accept_does_not_hide_embedded_extraction_failure():
    result = aggregate_payload_verifications([
        ({
            "segment_id": "zip",
            "format": "zip",
            "success": False,
            "partial_outputs": False,
        }, _verification(
            decision=DECISION_ACCEPT,
            integrity=CONTENT_INTEGRITY_VERIFIED_COMPLETE,
            completeness=1.0,
            complete=1,
        )),
    ])

    assert result.decision_hint == DECISION_FAIL
    assert result.assessment_status != ASSESSMENT_COMPLETE
