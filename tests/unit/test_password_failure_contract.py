import pytest

from sunpack.core.contracts.extraction import ExtractionResult
from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.contracts.verification import (
    CONTENT_INTEGRITY_UNKNOWN,
    DECISION_REQUEST_PASSWORD,
)
from sunpack.core.passwords.candidates import PasswordCandidatePipeline
from sunpack.core.passwords.job import PasswordJob
from sunpack.core.passwords.scheduler import PasswordScheduler, PasswordSearchStatus
from sunpack.core.passwords.verifier import PasswordBatchVerification
from sunpack.core.passwords.verifier.base import (
    normalize_verifier_status,
)
from sunpack.core.passwords.verifier.zip_fast import ZipFastVerifier
from sunpack.pipeline.verification import VerificationScheduler
from tests.helpers.archive_tasks import make_archive_task
from tests.helpers.config_factory import make_config


def test_verifier_statuses_reject_unknown_values():
    with pytest.raises(ValueError, match="invalid verifier status"):
        normalize_verifier_status("unexpected_backend_value")


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


@pytest.mark.parametrize("planning", [False, True], ids=["search", "extraction-plan"])
@pytest.mark.parametrize("evidence", ["ambiguous-tail", "native-missing-proof", "native-volume-gap"])
def test_scheduler_stops_password_batch_on_unavailable_tail_without_negative_result(tmp_path, planning, evidence):
    # Both scheduler entry points consume one native verdict. Without this
    # distinction a truncated standalone file becomes a Watch volume blocker;
    # without the proof case real missing sets would lose their recovery path.
    archive = tmp_path / "sample.7z.001"
    archive.write_bytes(b"7z")
    scheduler = PasswordScheduler(_StaticVerifier(PasswordBatchVerification(
        ok=False,
        status="missing_volume" if evidence == "native-volume-gap" else "needs_volume_or_tail_damaged",
        attempts=0,
        error_text="missing volume or damaged next-header offset",
        terminal=True,
    )))

    run = scheduler.plan_for_extraction if planning else scheduler.run
    result = run(PasswordJob(
        archive_path=str(archive),
        archive_input={"analysis": {"execution": {"missing_volume_evidence": "relation_missing_volume"}}} if evidence == "native-missing-proof" else None,
        candidates=PasswordCandidatePipeline.from_values([f"bad-{index}" for index in range(50)]),
    ))

    assert result.status == (PasswordSearchStatus.NEEDS_VOLUME_OR_TAIL_DAMAGED if evidence == "ambiguous-tail" else PasswordSearchStatus.MISSING_VOLUME)
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

        out_dir=str(tmp_path / "out"),

        error=failure.message,
        failure=failure,
    )

    verification = VerificationScheduler(make_config({
        "verification": {
            "enabled": True,
            "methods": [{"name": "extraction_exit_signal"}],
        }
    })).verify(_task(archive), result)

    assert verification.decision_hint == DECISION_REQUEST_PASSWORD
    assert verification.content_integrity == CONTENT_INTEGRITY_UNKNOWN
    assert verification.failures[0].code == "fail.password_required"


def test_terminal_archive_jobs_report_one_start_and_finish_even_with_volume_retry(tmp_path):
    # Existing reporter tests call notifications themselves. Only executor-level
    # coverage catches discovery short-circuits losing start or retries emitting
    # it twice; concurrent terminal jobs cover both with no archive IO.
    import asyncio
    from types import SimpleNamespace
    from sunpack.core.i18n import I18nContext
    from sunpack.pipeline.coordinator.archive_job import ArchiveJobExecutor
    from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker, CancellationToken

    events, inspected, retries = [], [], []
    tasks = [make_archive_task(tmp_path / f"{name}.opaque") for name in ("damaged", "password", "missing", "ordinary")]
    for task, kind in zip(tasks, (FailureKind.DAMAGED, FailureKind.WRONG_PASSWORD, FailureKind.MISSING_VOLUME)):
        task.discovery_failure = FailureInfo(kind, "relations", kind.value)

    executor = object.__new__(ArchiveJobExecutor)
    executor.request_id = "terminal-lifecycle"
    executor.i18n = I18nContext("en")
    executor.progress_reporter = SimpleNamespace(
        task_started=lambda task, depth: events.append((task.key, "started", depth)),
        task_finished=lambda task, outcome, depth: events.append((task.key, "finished", depth)),
    )

    def inspect(task, output_dir):
        assert task.discovery_failure is None
        inspected.append(task.key)
        return SimpleNamespace(skip_result=ExtractionResult(False, output_dir, error="terminal inspection"))

    def retry(task, outcome):
        retries.append(task.key)
        return make_archive_task(task.main_path)

    def output_dir(task):
        assert task.discovery_failure is None
        return str(tmp_path / "out")

    executor.extractor = SimpleNamespace(inspect=inspect)

    async def scenario():
        broker = AsyncWorkBroker(thread_capacity=3)
        try:
            await asyncio.gather(*(executor._execute_one_async(
                task, output_dir, depth=index + 1, broker=broker,
                cancellation=CancellationToken(), missing_volume_retry=retry,
            ) for index, task in enumerate(tasks)))
        finally:
            await broker.close()

    asyncio.run(scenario())
    for index, task in enumerate(tasks):
        assert [event[1:] for event in events if event[0] == task.key] == [
            ("started", index + 1), ("finished", index + 1),
        ]
    assert retries == [tasks[2].key]
    assert set(inspected) == {tasks[2].key, tasks[3].key}


class _StaticVerifier:
    def __init__(self, result):
        self.result = result

    def verify_batch(self, archive_path, passwords, *, part_paths=None, archive_input=None):
        return self.result

    verify_fast_batch = verify_batch


def _task(path):
    return make_archive_task(path, key=str(path))
