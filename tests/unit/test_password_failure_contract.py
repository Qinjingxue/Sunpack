from types import SimpleNamespace

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.contracts.tasks import ArchiveTask
from sunpack.contracts.extraction import ExtractionResult
from sunpack.passwords.candidates import PasswordCandidatePipeline
from sunpack.passwords.job import PasswordJob
from sunpack.passwords.scheduler import PasswordScheduler, PasswordSearchStatus
from sunpack.passwords.verifier import PasswordBatchVerification
from sunpack.passwords.verifier.base import VERIFIER_STATUSES, normalize_verifier_status
from sunpack.passwords.verifier.sevenzip_dll import SevenZipDllVerifier
from sunpack.passwords.verifier.registry import PasswordVerifierChain
from sunpack.passwords.verifier.zip_fast import ZipFastVerifier
from sunpack.support.sevenzip_bridge import (
    OPERATION_RESULT_HEADERS_ERROR,
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_DAMAGED,
    STATUS_NEEDS_VOLUME_OR_TAIL_DAMAGED,
    STATUS_UNSUPPORTED,
    STATUS_WRONG_PASSWORD,
)
from sunpack.verification import VerificationScheduler
from sunpack.contracts.verification import DECISION_REQUEST_PASSWORD, CONTENT_INTEGRITY_UNKNOWN


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


def test_final_confirmation_tail_failure_does_not_reject_fast_match():
    fast = _StaticVerifier(PasswordBatchVerification(
        ok=True,
        status="match",
        matched_index=0,
        attempts=1,
        final_confirmation_required=True,
        match_evidence="bounded_header",
    ))
    final = _StaticVerifier(PasswordBatchVerification(
        ok=False,
        status="needs_volume_or_tail_damaged",
        attempts=1,
        error_text="next volume unavailable",
        terminal=True,
    ))

    result = PasswordVerifierChain([fast], final).verify_batch(
        "sample.rar",
        ["candidate", "later-candidate"],
    )

    assert result.status == "needs_volume_or_tail_damaged"
    assert result.terminal is True
    assert result.final_confirmation_required is False


def test_headers_error_confirmation_rejects_only_weak_rar_candidate():
    fast = _SequencedVerifier([
        PasswordBatchVerification(
            ok=True,
            status="match",
            matched_index=0,
            attempts=1,
            final_confirmation_required=True,
            match_evidence="rar4_hp_header",
        ),
        PasswordBatchVerification(
            ok=False,
            status="no_match",
            attempts=1,
            error_text="RAR4 -hp header did not match",
        ),
    ])
    final = _StaticVerifier(PasswordBatchVerification(
        ok=False,
        status="damaged",
        attempts=1,
        error_text="archive appears damaged [operation_result=headers_error]",
        test_result=SimpleNamespace(operation_result=OPERATION_RESULT_HEADERS_ERROR),
        terminal=True,
    ))

    result = PasswordVerifierChain([fast], final).verify_batch(
        "sample.rar",
        ["weak-match", "later-wrong-password"],
    )

    assert result.status == "no_match"
    assert result.attempts == 2
    assert fast.batches == [["weak-match", "later-wrong-password"], ["later-wrong-password"]]


def test_non_header_damage_after_weak_match_remains_terminal():
    fast = _StaticVerifier(PasswordBatchVerification(
        ok=True,
        status="match",
        matched_index=0,
        attempts=1,
        final_confirmation_required=True,
    ))
    final = _StaticVerifier(PasswordBatchVerification(
        ok=False,
        status="damaged",
        attempts=1,
        error_text="archive appears damaged [operation_result=data_error]",
        terminal=True,
    ))

    result = PasswordVerifierChain([fast], final).verify_batch(
        "sample.rar",
        ["weak-match", "later-password"],
    )

    assert result.status == "damaged"
    assert result.terminal is True


@pytest.mark.parametrize(
    ("native_status", "expected"),
    [
        (STATUS_WRONG_PASSWORD, "no_match"),
        (STATUS_DAMAGED, "damaged"),
        (STATUS_UNSUPPORTED, "unsupported_method"),
        (STATUS_BACKEND_UNAVAILABLE, "backend_unavailable"),
        (STATUS_NEEDS_VOLUME_OR_TAIL_DAMAGED, "needs_volume_or_tail_damaged"),
    ],
)
def test_dll_verifier_preserves_native_failure_status(native_status, expected):
    native = _NativeTester(native_status)
    result = SevenZipDllVerifier(native_password_tester=native).verify_batch("sample.7z", ["bad"])

    assert result.status == expected


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


class _SequencedVerifier:
    def __init__(self, results):
        self.results = list(results)
        self.batches = []

    def verify_batch(self, archive_path, passwords, *, part_paths=None, archive_input=None):
        self.batches.append(list(passwords))
        return self.results.pop(0)


class _NativeTester:
    def __init__(self, status):
        self.status = status

    def try_passwords(self, archive_path, passwords, *, part_paths=None, archive_input=None):
        return SimpleNamespace(
            status=self.status,
            ok=False,
            matched_index=-1,
            attempts=len(passwords),
            message="native diagnostic",
            operation_result=0,
        )


def _task(path) -> ArchiveTask:
    return ArchiveTask(
        fact_bag=FactBag(),
        key=str(path),
        main_path=str(path),
        all_parts=[str(path)],
        decision="archive",
    )
