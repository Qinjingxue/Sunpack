from types import SimpleNamespace

import sunpack.passwords.scheduler as password_scheduler_module
from sunpack.passwords.cache import (
    MAX_CACHED_NEGATIVE_ATTEMPTS,
    MAX_CACHED_SUCCESSES,
    PasswordAttemptCache,
)
from sunpack.passwords.candidates import PasswordCandidatePipeline
from sunpack.passwords.fingerprint import build_archive_fingerprint
from sunpack.passwords.job import PasswordJob
from sunpack.passwords.scheduler import PasswordScheduler, PasswordSearchStatus
from sunpack.passwords.verifier import PasswordBatchVerification, PasswordVerifierChain


class FakeVerifier:
    def __init__(self, correct_password: str):
        self.correct_password = correct_password
        self.batches: list[list[str]] = []

    def verify_batch(self, archive_path, passwords, *, part_paths=None, archive_input=None):
        self.batches.append(list(passwords))
        if self.correct_password in passwords:
            return PasswordBatchVerification(
                ok=True,
                matched_index=passwords.index(self.correct_password),
                attempts=passwords.index(self.correct_password) + 1,
                test_result=SimpleNamespace(returncode=0),
                final_confirmation_required=False,
            )
        return PasswordBatchVerification(
            ok=False,
            attempts=len(passwords),
            test_result=SimpleNamespace(returncode=2),
            error_text="wrong password",
        )


class StaticVerifier:
    def __init__(self, outcome: PasswordBatchVerification):
        self.outcome = outcome
        self.batches: list[list[str]] = []

    def verify_batch(self, archive_path, passwords, *, part_paths=None, archive_input=None):
        self.batches.append(list(passwords))
        return self.outcome


class FormatVerifier(StaticVerifier):
    def __init__(self, format_hint: str, outcome: PasswordBatchVerification):
        super().__init__(outcome)
        self.format_hint = format_hint


def test_password_scheduler_batches_lazy_candidates_and_stops_on_match(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, default_batch_size=2)

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad1", "bad2", "secret", "unused"]),
        batch_size=2,
    ))

    assert result.password == "secret"
    assert result.test_result.returncode == 0
    assert verifier.batches == [["bad1", "bad2"], ["secret", "unused"]]


def test_password_scheduler_skips_negative_cache_and_reuses_success(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    cache = PasswordAttemptCache()
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, cache=cache, default_batch_size=1)

    first = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad", "secret"]),
    ))
    second = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad", "secret"]),
    ))

    assert first.password == "secret"
    assert second.password == "secret"
    assert second.stopped_reason == "cache_hit"
    assert verifier.batches == [["bad"], ["secret"]]


def test_password_fingerprint_separates_embedded_ranges(tmp_path):
    archive = tmp_path / "carrier.bin"
    archive.write_bytes(b"carrier")
    first = build_archive_fingerprint(
        str(archive),
        [str(archive)],
        archive_input={
            "open_mode": "file_range",
            "format_hint": "zip",
            "parts": [{"path": str(archive), "start": 100, "end": 200}],
        },
    )
    second = build_archive_fingerprint(
        str(archive),
        [str(archive)],
        archive_input={
            "open_mode": "file_range",
            "format_hint": "zip",
            "parts": [{"path": str(archive), "start": 300, "end": 400}],
        },
    )

    assert first.key != second.key


def test_password_attempt_cache_bounds_successes_and_negative_attempts():
    cache = PasswordAttemptCache()

    for index in range(MAX_CACHED_SUCCESSES + 1):
        cache.remember_success(f"fingerprint-{index}", "secret")
    assert cache.get_success("fingerprint-0") is None
    assert cache.get_success(f"fingerprint-{MAX_CACHED_SUCCESSES}") == "secret"

    for index in range(MAX_CACHED_NEGATIVE_ATTEMPTS + 1):
        cache.remember_negative("fingerprint", f"password-{index}")
    assert cache.has_negative("fingerprint", "password-0") is False
    assert cache.has_negative("fingerprint", f"password-{MAX_CACHED_NEGATIVE_ATTEMPTS}") is True


def test_password_scheduler_caps_batch_to_max_attempts(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, default_batch_size=10)

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad1", "bad2", "secret"]),
        max_attempts=2,
    ))

    assert result.password is None
    assert result.attempts == 2
    assert result.stopped_reason == "max_attempts"
    assert verifier.batches == [["bad1", "bad2"]]


def test_password_scheduler_reports_progress_events(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, default_batch_size=1)
    events = []

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad", "secret"]),
        progress_callback=events.append,
    ))

    assert result.password == "secret"
    assert [event.stage for event in events] == [
        "started",
        "batch_started",
        "batch_finished",
        "batch_started",
        "batch_finished",
        "finished",
    ]
    assert events[-1].password_found is True
    assert events[-1].attempts == 2


def test_password_scheduler_honors_timeout_before_verifying_more_candidates(tmp_path):
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"archive")
    verifier = FakeVerifier("secret")
    scheduler = PasswordScheduler(verifier, default_batch_size=1)

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad", "secret"]),
        timeout_seconds=0,
    ))

    assert result.password is None
    assert result.stopped_reason == "timeout"
    assert verifier.batches == []


def test_password_scheduler_does_not_cache_weak_fast_match_as_success(tmp_path):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(b"archive")
    verifier = StaticVerifier(PasswordBatchVerification(
        ok=True,
        status="match",
        matched_index=0,
        matched_indices=(0,),
        attempts=1,
        final_confirmation_required=True,
        match_evidence="zipcrypto_header_byte",
    ))
    scheduler = PasswordScheduler(verifier)

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["collision"]),
    ))

    assert result.status == PasswordSearchStatus.INCONCLUSIVE
    assert result.password is None
    assert result.extraction_candidates == ("collision",)
    assert scheduler.cache.get_success(build_archive_fingerprint(str(archive)).key) is None


def test_verifier_chain_preserves_weak_candidate_evidence():
    fast = StaticVerifier(PasswordBatchVerification(
        ok=True,
        status="match",
        matched_index=0,
        matched_indices=(0, 2),
        attempts=3,
        final_confirmation_required=True,
        match_evidence="zipcrypto_header_byte",
    ))
    chain = PasswordVerifierChain([fast])

    outcome = chain.verify_batch("sample.zip", ["collision", "rejected", "secret"])

    assert outcome.ok is True
    assert outcome.status == "match"
    assert outcome.final_confirmation_required is True
    assert outcome.matched_indices == (0, 2)
    assert outcome.match_evidence == "zipcrypto_header_byte"


def test_production_scheduler_uses_only_bounded_fast_verifiers(
    tmp_path,
    monkeypatch,
):
    archive = tmp_path / "renamed.bin"
    archive.write_bytes(b"archive")

    zip_fast = FormatVerifier("zip", PasswordBatchVerification(
        ok=False,
        status="unsupported_method",
        attempts=0,
    ))
    rar_fast = FormatVerifier("rar", PasswordBatchVerification(
        ok=False,
        status="unknown_needs_final_verifier",
        attempts=0,
    ))
    seven_zip_fast = FormatVerifier("7z", PasswordBatchVerification(
        ok=False,
        status="unsupported_method",
        attempts=0,
    ))

    monkeypatch.setattr(password_scheduler_module, "ZipFastVerifier", lambda: zip_fast)
    monkeypatch.setattr(password_scheduler_module, "RarFastVerifier", lambda: rar_fast)
    monkeypatch.setattr(password_scheduler_module, "SevenZipFastVerifier", lambda: seven_zip_fast)

    scheduler = PasswordScheduler.with_fast_verifiers()

    result = scheduler.plan_for_extraction(PasswordJob(
        archive_path=str(archive),
        archive_input={"format_hint": "rar"},
        candidates=PasswordCandidatePipeline.from_values(["one", "two", "three"]),
    ))

    assert result.password is None
    assert result.extraction_candidates == ("one", "two", "three")
    assert isinstance(scheduler.verifier, PasswordVerifierChain)
    assert zip_fast.batches == []
    assert rar_fast.batches == [["one", "two", "three"]]
    assert seven_zip_fast.batches == []


def test_extraction_plan_accepts_strong_fast_proof_and_caches_it(tmp_path):
    archive = tmp_path / "confused.extension"
    archive.write_bytes(b"archive")
    fast = StaticVerifier(PasswordBatchVerification(
        ok=True,
        status="match",
        matched_index=1,
        attempts=2,
        final_confirmation_required=False,
    ))
    scheduler = PasswordScheduler(PasswordVerifierChain([fast]))
    job = PasswordJob(
        archive_path=str(archive),
        archive_input={"format_hint": "7z"},
        candidates=PasswordCandidatePipeline.from_values(["bad", "secret"]),
    )

    first = scheduler.plan_for_extraction(job)
    second = scheduler.plan_for_extraction(job)

    assert first.password == "secret"
    assert first.stopped_reason == "fast_proof"
    assert second.password == "secret"
    assert second.stopped_reason == "cache_hit"
    assert fast.batches == [["bad", "secret"]]


def test_extraction_plan_accepts_not_required_fast_result(tmp_path):
    archive = tmp_path / "plain.embedded"
    archive.write_bytes(b"archive")
    fast = StaticVerifier(PasswordBatchVerification(
        ok=True,
        status="not_required",
        matched_index=-1,
        attempts=0,
        final_confirmation_required=False,
    ))
    scheduler = PasswordScheduler(PasswordVerifierChain([fast]))
    job = PasswordJob(
        archive_path=str(archive),
        archive_input={"open_mode": "file_range", "format_hint": "zip"},
        candidates=PasswordCandidatePipeline.from_values(["", "secret"]),
    )

    result = scheduler.plan_for_extraction(job)
    cached = scheduler.plan_for_extraction(job)

    assert result.password == ""
    assert result.status == PasswordSearchStatus.UNENCRYPTED
    assert result.stopped_reason == "fast_not_required"
    assert cached.password == ""
    assert cached.status == PasswordSearchStatus.UNENCRYPTED
    assert cached.stopped_reason == "cache_hit"
    assert scheduler.cache.get_success(build_archive_fingerprint(
        str(archive), archive_input=job.archive_input,
    ).key) == ""
    assert fast.batches == [["", "secret"]]


def test_extraction_plan_preserves_zipcrypto_candidate_evidence(tmp_path):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(b"archive")
    fast = StaticVerifier(PasswordBatchVerification(
        ok=True,
        status="match",
        matched_index=0,
        matched_indices=(0, 2),
        attempts=3,
        final_confirmation_required=True,
        match_evidence="zipcrypto_header_byte",
    ))
    scheduler = PasswordScheduler(PasswordVerifierChain([fast]))

    result = scheduler.plan_for_extraction(PasswordJob(
        archive_path=str(archive),
        archive_input={"format_hint": "zip"},
        candidates=PasswordCandidatePipeline.from_values(["collision", "rejected", "secret"]),
    ))

    assert result.password is None
    assert result.extraction_candidates == ("collision", "secret")
    assert result.extraction_candidate_evidence == "zipcrypto_header_byte"
    assert scheduler.cache.has_negative(build_archive_fingerprint(str(archive)).key, "rejected") is True


def test_verifier_chain_prioritizes_fast_verifier_from_extension():
    zip_fast = FormatVerifier("zip", PasswordBatchVerification(ok=False, status="unsupported_method"))
    rar_fast = FormatVerifier("rar", PasswordBatchVerification(ok=False, status="unsupported_method"))
    seven_zip_fast = FormatVerifier("7z", PasswordBatchVerification(
        ok=False,
        status="no_match",
        attempts=2,
        error_text="wrong password",
    ))
    chain = PasswordVerifierChain([zip_fast, rar_fast, seven_zip_fast])

    outcome = chain.verify_batch("sample.7z", ["bad1", "bad2"])

    assert outcome.status == "no_match"
    assert seven_zip_fast.batches == [["bad1", "bad2"]]
    assert zip_fast.batches == []
    assert rar_fast.batches == []


def test_verifier_chain_prioritizes_fast_verifier_from_archive_input():
    zip_fast = FormatVerifier("zip", PasswordBatchVerification(ok=False, status="unsupported_method"))
    rar_fast = FormatVerifier("rar", PasswordBatchVerification(
        ok=False,
        status="no_match",
        attempts=1,
        error_text="wrong password",
    ))
    chain = PasswordVerifierChain([zip_fast, rar_fast])

    outcome = chain.verify_batch(
        "carrier.jpg",
        ["bad"],
        archive_input={"format_hint": "rar"},
    )

    assert outcome.status == "no_match"
    assert rar_fast.batches == [["bad"]]
    assert zip_fast.batches == []
