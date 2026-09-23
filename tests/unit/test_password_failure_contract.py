import pytest

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.extraction import ExtractionResult
from tests.helpers.archive_tasks import make_archive_task
from sunpack.core.passwords.candidates import PasswordCandidatePipeline
from sunpack.core.passwords.job import PasswordJob
from sunpack.core.passwords.scheduler import PasswordScheduler, PasswordSearchStatus
from sunpack.core.passwords.verifier import PasswordBatchVerification
from sunpack.core.passwords.verifier.base import VERIFIER_STATUSES, normalize_verifier_status
from sunpack.core.passwords.verifier.zip_fast import ZipFastVerifier
from sunpack.pipeline.verification import VerificationScheduler
from sunpack.core.contracts.verification import DECISION_REQUEST_PASSWORD, CONTENT_INTEGRITY_UNKNOWN


@pytest.mark.parametrize("status", sorted(VERIFIER_STATUSES))
def test_verifier_statuses_accept_only_canonical_values(status):
    assert normalize_verifier_status(status) == status


@pytest.mark.parametrize(
    "status",
    [
        "unencrypted",
        "not_encrypted",
        "unknown_need_fallback",
        "unknown_needs_fallback",
        "inconclusive",
        "unsupported",
        "unexpected_backend_value",
    ],
)
def test_verifier_statuses_reject_legacy_and_unknown_values(status):
    with pytest.raises(ValueError, match="invalid verifier status"):
        normalize_verifier_status(status)


def test_scheduler_uses_no_match_status_not_backend_message(tmp_path):
    archive = tmp_path / "sample.rar"
    archive.write_bytes(b"rar")
    scheduler = PasswordScheduler(_StaticVerifier(PasswordBatchVerification(
        ok=False,
        status="no_match",
        attempts=2,
        error_text="rar5 password check did not match",
    )))

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad-1", "bad-2"]),
    ))

    assert result.status == PasswordSearchStatus.EXHAUSTED
    assert result.password is None


def test_scheduler_stops_password_batch_on_unavailable_tail_without_negative_result(tmp_path):
    archive = tmp_path / "sample.7z.001"
    archive.write_bytes(b"7z")
    scheduler = PasswordScheduler(_StaticVerifier(PasswordBatchVerification(
        ok=False,
        status="needs_volume_or_tail_damaged",
        attempts=0,
        error_text="missing volume or damaged next-header offset",
        terminal=True,
    )))

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values([f"bad-{index}" for index in range(50)]),
    ))

    assert result.status == PasswordSearchStatus.NEEDS_VOLUME_OR_TAIL_DAMAGED
    assert result.attempts == 0
    assert result.exhausted is False


def test_fast_verifier_preserves_native_field_read_diagnostics():
    outcome = {
        "status": "needs_volume_or_tail_damaged",
        "attempts": 0,
        "message": "tail unavailable",
        "read_error": {
            "field": "zip.eocd",
            "location": "tail",
            "possible_missing_volume": True,
        },
    }

    verification = ZipFastVerifier._from_outcome(outcome)

    assert verification.test_result is outcome
    assert verification.test_result["read_error"]["field"] == "zip.eocd"


def test_embedded_failure_retains_nested_password_cause():
    password = FailureInfo(
        kind=FailureKind.WRONG_PASSWORD,
        stage="password_resolution",
        message="password rejected",
        user_action="request_password",
    )
    embedded = FailureInfo(
        kind=FailureKind.EMBEDDED_SEGMENTS_FAILED,
        stage="embedded_segments",
        message="segment failed",
        causes=(password,),
    )

    restored = FailureInfo.from_dict(embedded.to_dict())

    assert restored is not None
    assert restored.is_password_failure
    assert restored.contains(FailureKind.WRONG_PASSWORD)


def test_password_failure_bypasses_verification(tmp_path):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(b"encrypted")
    failure = FailureInfo(
        kind=FailureKind.PASSWORD_REQUIRED,
        stage="password_resolution",
        message="password required",
        user_action="request_password",
    )
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(tmp_path / "out"),
        all_parts=[str(archive)],
        error=failure.message,
        failure=failure,
    )

    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "extraction_exit_signal"}],
        }
    }).verify(_task(archive), result)

    assert verification.decision_hint == DECISION_REQUEST_PASSWORD
    assert verification.content_integrity == CONTENT_INTEGRITY_UNKNOWN
    assert verification.failures[0].code == "fail.password_required"


class _StaticVerifier:
    def __init__(self, result):
        self.result = result

    def verify_batch(self, archive_path, passwords, *, part_paths=None, archive_input=None):
        return self.result


def _task(path):
    return make_archive_task(path, key=str(path))
