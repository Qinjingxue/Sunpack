from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Literal

from sunpack.passwords.cache import PasswordAttemptCache
from sunpack.passwords.candidates import PasswordCandidate
from sunpack.passwords.fingerprint import build_archive_fingerprint
from sunpack.passwords.job import PasswordJob
from sunpack.passwords.verifier import PasswordBatchVerification, PasswordVerifier, PasswordVerifierRegistry
from sunpack.passwords.verifier.rar_fast import RarFastVerifier
from sunpack.passwords.verifier.seven_zip_fast import SevenZipFastVerifier
from sunpack.passwords.verifier.zip_fast import ZipFastVerifier


class PasswordSearchStatus(str, Enum):
    FOUND = "found"
    UNENCRYPTED = "unencrypted"
    EXHAUSTED = "exhausted"
    INCONCLUSIVE = "inconclusive"
    DAMAGED = "damaged"
    UNSUPPORTED = "unsupported"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    NEEDS_VOLUME_OR_TAIL_DAMAGED = "needs_volume_or_tail_damaged"
    STOPPED = "stopped"


@dataclass(frozen=True)
class PasswordSearchResult:
    password: str | None
    status: PasswordSearchStatus
    test_result: object = None
    error_text: str = ""
    attempts: int = 0
    exhausted: bool = False
    stopped_reason: str = ""
    extraction_candidates: tuple[str, ...] = ()
    extraction_candidate_evidence: str = ""


@dataclass(frozen=True)
class PasswordProgressEvent:
    stage: Literal["started", "batch_started", "batch_finished", "skipped_cached_negative", "finished"]
    attempts: int = 0
    candidates_seen: int = 0
    skipped: int = 0
    batch_size: int = 0
    elapsed_seconds: float = 0.0
    password_found: bool = False
    stopped_reason: str = ""
    error_text: str = ""


class PasswordScheduler:
    def __init__(
        self,
        verifier: PasswordVerifier,
        *,
        cache: PasswordAttemptCache | None = None,
        default_batch_size: int = 256,
    ):
        self.verifier = verifier
        self.cache = cache or PasswordAttemptCache()
        self.default_batch_size = max(1, int(default_batch_size))

    @classmethod
    def with_fast_verifiers(cls) -> "PasswordScheduler":
        registry = PasswordVerifierRegistry(
            fast_verifiers=[ZipFastVerifier(), RarFastVerifier(), SevenZipFastVerifier()],
        )
        return cls(registry.build())

    def run(self, job: PasswordJob) -> PasswordSearchResult:
        started_at = time.monotonic()
        self._emit_progress(job, PasswordProgressEvent(stage="started"))
        fingerprint = job.fingerprint or build_archive_fingerprint(
            job.archive_path,
            job.part_paths,
            archive_input=job.archive_input,
        )
        cached_success = self.cache.get_success(fingerprint.key)
        if cached_success is not None:
            result = PasswordSearchResult(
                password=cached_success,
                status=(
                    PasswordSearchStatus.UNENCRYPTED
                    if cached_success == ""
                    else PasswordSearchStatus.FOUND
                ),
                attempts=0,
                stopped_reason="cache_hit",
            )
            self._emit_finished(job, result, started_at, candidates_seen=0, skipped=0)
            return result

        attempts = 0
        candidates_seen = 0
        skipped = 0
        last_result = None
        last_error = ""
        batch_size = max(1, int(job.batch_size or self.default_batch_size))
        batch: list[str] = []

        for candidate in job.candidate_pipeline():
            stop_reason = self._stop_reason(job, attempts, started_at)
            if stop_reason:
                result = PasswordSearchResult(
                    password=None,
                    status=PasswordSearchStatus.STOPPED,
                    test_result=last_result,
                    error_text=last_error or "password search stopped",
                    attempts=attempts,
                    stopped_reason=stop_reason,
                )
                self._emit_finished(job, result, started_at, candidates_seen, skipped)
                return result
            password = _candidate_value(candidate)
            candidates_seen += 1
            if self.cache.has_negative(fingerprint.key, password):
                skipped += 1
                self._emit_progress(job, PasswordProgressEvent(
                    stage="skipped_cached_negative",
                    attempts=attempts,
                    candidates_seen=candidates_seen,
                    skipped=skipped,
                    elapsed_seconds=time.monotonic() - started_at,
                ))
                continue
            batch.append(password)
            if len(batch) >= self._allowed_batch_size(job, attempts, batch_size):
                outcome = self._verify_batch(job, fingerprint.key, batch, attempts, started_at, candidates_seen, skipped)
                attempts = outcome.attempts
                last_result = outcome.test_result
                last_error = outcome.error_text
                if outcome.password is not None or outcome.stopped_reason:
                    self._emit_finished(job, outcome, started_at, candidates_seen, skipped)
                    return outcome
                batch = []

        if batch:
            outcome = self._verify_batch(job, fingerprint.key, batch, attempts, started_at, candidates_seen, skipped)
            attempts = outcome.attempts
            last_result = outcome.test_result
            last_error = outcome.error_text
            if outcome.password is not None or outcome.stopped_reason:
                self._emit_finished(job, outcome, started_at, candidates_seen, skipped)
                return outcome

        result = PasswordSearchResult(
            password=None,
            status=PasswordSearchStatus.EXHAUSTED,
            test_result=last_result,
            error_text=last_error,
            attempts=attempts,
            exhausted=True,
        )
        self._emit_finished(job, result, started_at, candidates_seen, skipped)
        return result

    def plan_for_extraction(self, job: PasswordJob) -> PasswordSearchResult:
        """Resolve cheap proofs and return inconclusive candidates for real extraction.

        This path never invokes the full-payload final verifier.  Candidates that
        cannot be proven from bounded archive metadata are handed to the generic
        SevenZip extraction worker as one batch; the worker performs its bounded
        backend probe and then the actual extraction transaction.
        """
        started_at = time.monotonic()
        self._emit_progress(job, PasswordProgressEvent(stage="started"))
        fingerprint = job.fingerprint or build_archive_fingerprint(
            job.archive_path,
            job.part_paths,
            archive_input=job.archive_input,
        )
        cached_success = self.cache.get_success(fingerprint.key)
        if cached_success is not None:
            result = PasswordSearchResult(
                password=cached_success,
                status=(
                    PasswordSearchStatus.UNENCRYPTED
                    if cached_success == ""
                    else PasswordSearchStatus.FOUND
                ),
                attempts=0,
                stopped_reason="cache_hit",
            )
            self._emit_finished(job, result, started_at, candidates_seen=0, skipped=0)
            return result

        candidates: list[str] = []
        seen: set[str] = set()
        skipped = 0
        for candidate in job.candidate_pipeline():
            password = _candidate_value(candidate)
            if password in seen:
                continue
            seen.add(password)
            if self.cache.has_negative(fingerprint.key, password):
                skipped += 1
                continue
            candidates.append(password)

        if not candidates:
            result = PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.EXHAUSTED,
                attempts=0,
                exhausted=True,
            )
            self._emit_finished(job, result, started_at, candidates_seen=0, skipped=skipped)
            return result

        batch_size = max(1, int(job.batch_size or self.default_batch_size))
        inconclusive: list[str] = []
        inconclusive_evidence = ""
        attempts = 0
        for offset in range(0, len(candidates), batch_size):
            batch = candidates[offset:offset + batch_size]
            verification = _call_fast_verifier(
                self.verifier,
                job.archive_path,
                batch,
                part_paths=job.part_paths,
                archive_input=job.archive_input,
            )
            attempts += max(0, min(int(verification.attempts or 0), len(batch)))
            if verification.status == "not_required":
                self.cache.remember_success(fingerprint.key, "")
                result = PasswordSearchResult(
                    password="",
                    status=PasswordSearchStatus.UNENCRYPTED,
                    test_result=verification.test_result,
                    attempts=attempts,
                    stopped_reason="fast_not_required",
                )
                self._emit_finished(job, result, started_at, len(candidates), skipped)
                return result
            matched_indices = _valid_matched_indices(verification, len(batch))
            if verification.status == "match" and matched_indices:
                matched = batch[matched_indices[0]]
                if not verification.final_confirmation_required:
                    self.cache.remember_success(fingerprint.key, matched)
                    result = PasswordSearchResult(
                        password=matched,
                        status=PasswordSearchStatus.FOUND,
                        test_result=verification.test_result,
                        attempts=attempts,
                        stopped_reason="fast_proof",
                    )
                    self._emit_finished(job, result, started_at, len(candidates), skipped)
                    return result
                inconclusive.extend(batch[index] for index in matched_indices)
                rejected = [password for index, password in enumerate(batch) if index not in matched_indices]
                self.cache.remember_negative_batch(fingerprint.key, rejected)
                if not inconclusive_evidence:
                    inconclusive_evidence = verification.match_evidence
                elif verification.match_evidence != inconclusive_evidence:
                    inconclusive_evidence = ""
                continue
            if verification.status == "no_match":
                self.cache.remember_negative_batch(fingerprint.key, batch)
                continue
            if verification.status == "damaged":
                result = PasswordSearchResult(
                    password=None,
                    status=PasswordSearchStatus.DAMAGED,
                    test_result=verification.test_result,
                    error_text=verification.error_text,
                    attempts=attempts,
                    stopped_reason="terminal",
                )
                self._emit_finished(job, result, started_at, len(candidates), skipped)
                return result
            if verification.status == "needs_volume_or_tail_damaged":
                result = PasswordSearchResult(
                    password=None,
                    status=PasswordSearchStatus.NEEDS_VOLUME_OR_TAIL_DAMAGED,
                    test_result=verification.test_result,
                    error_text=verification.error_text,
                    attempts=attempts,
                    stopped_reason="terminal",
                )
                self._emit_finished(job, result, started_at, len(candidates), skipped)
                return result
            if verification.status == "backend_unavailable":
                # Extraction may still have a usable worker/backend. Preserve the
                # candidates instead of misclassifying an infrastructure failure.
                inconclusive.extend(batch)
                continue
            inconclusive.extend(batch)

        if inconclusive:
            result = PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.INCONCLUSIVE,
                attempts=attempts,
                stopped_reason="extraction_confirmation_required",
                extraction_candidates=tuple(dict.fromkeys(inconclusive)),
                extraction_candidate_evidence=inconclusive_evidence,
            )
        else:
            result = PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.EXHAUSTED,
                attempts=attempts,
                exhausted=True,
            )
        self._emit_finished(job, result, started_at, len(candidates), skipped)
        return result

    def remember_extraction_success(self, fingerprint_key: str, password: str) -> None:
        if fingerprint_key:
            self.cache.remember_success(fingerprint_key, password)

    def remember_extraction_rejection(self, fingerprint_key: str, password: str) -> None:
        if fingerprint_key:
            self.cache.remember_negative(fingerprint_key, password)

    def _verify_batch(
        self,
        job: PasswordJob,
        fingerprint_key: str,
        batch: list[str],
        previous_attempts: int,
        started_at: float,
        candidates_seen: int,
        skipped: int,
    ) -> PasswordSearchResult:
        batch = batch[: self._allowed_batch_size(job, previous_attempts, len(batch))]
        if not batch:
            return PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.STOPPED,
                attempts=previous_attempts,
                error_text="password attempt limit reached",
                stopped_reason="max_attempts",
            )
        self._emit_progress(job, PasswordProgressEvent(
            stage="batch_started",
            attempts=previous_attempts,
            candidates_seen=candidates_seen,
            skipped=skipped,
            batch_size=len(batch),
            elapsed_seconds=time.monotonic() - started_at,
        ))
        verification = self.verifier.verify_batch(
            job.archive_path,
            batch,
            part_paths=job.part_paths,
            archive_input=job.archive_input,
        )
        attempted_in_batch = max(0, min(max(verification.attempts, 0), len(batch)))
        if (
            not verification.ok
            and attempted_in_batch == 0
            and verification.status != "needs_volume_or_tail_damaged"
        ):
            attempted_in_batch = len(batch)
        total_attempts = previous_attempts + attempted_in_batch
        self._emit_progress(job, PasswordProgressEvent(
            stage="batch_finished",
            attempts=total_attempts,
            candidates_seen=candidates_seen,
            skipped=skipped,
            batch_size=len(batch),
            elapsed_seconds=time.monotonic() - started_at,
            password_found=verification.ok and not verification.final_confirmation_required,
            error_text=verification.error_text,
        ))
        if verification.status == "not_required":
            self.cache.remember_success(fingerprint_key, "")
            return PasswordSearchResult(
                password="",
                status=PasswordSearchStatus.UNENCRYPTED,
                test_result=verification.test_result,
                attempts=total_attempts,
                stopped_reason="fast_not_required",
            )
        if verification.ok and verification.final_confirmation_required:
            matched_indices = _valid_matched_indices(verification, len(batch))
            return PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.INCONCLUSIVE,
                test_result=verification.test_result,
                error_text=verification.error_text,
                attempts=total_attempts,
                stopped_reason="final_confirmation_required",
                extraction_candidates=tuple(batch[index] for index in matched_indices),
                extraction_candidate_evidence=verification.match_evidence,
            )
        if verification.ok:
            password = batch[verification.matched_index]
            self.cache.remember_success(fingerprint_key, password)
            return PasswordSearchResult(
                password=password,
                status=PasswordSearchStatus.FOUND,
                test_result=verification.test_result,
                error_text="",
                attempts=total_attempts,
                stopped_reason="found",
            )
        status_by_verification = {
            "no_match": PasswordSearchStatus.EXHAUSTED,
            "damaged": PasswordSearchStatus.DAMAGED,
            "unsupported_method": PasswordSearchStatus.UNSUPPORTED,
            "backend_unavailable": PasswordSearchStatus.BACKEND_UNAVAILABLE,
            "needs_volume_or_tail_damaged": PasswordSearchStatus.NEEDS_VOLUME_OR_TAIL_DAMAGED,
        }
        search_status = status_by_verification.get(verification.status, PasswordSearchStatus.INCONCLUSIVE)
        if search_status == PasswordSearchStatus.EXHAUSTED:
            self.cache.remember_negative_batch(fingerprint_key, batch[:attempted_in_batch])
        return PasswordSearchResult(
            password=None,
            status=search_status,
            test_result=verification.test_result,
            error_text=verification.error_text,
            attempts=total_attempts,
            stopped_reason="terminal" if verification.terminal else "",
        )

    @staticmethod
    def _stop_reason(job: PasswordJob, attempts: int, started_at: float) -> str:
        if job.max_attempts is not None and attempts >= job.max_attempts:
            return "max_attempts"
        if job.timeout_seconds is not None and time.monotonic() - started_at >= job.timeout_seconds:
            return "timeout"
        return ""

    @staticmethod
    def _allowed_batch_size(job: PasswordJob, attempts: int, requested_batch_size: int) -> int:
        requested_batch_size = max(1, int(requested_batch_size))
        if job.max_attempts is None:
            return requested_batch_size
        return max(0, min(requested_batch_size, job.max_attempts - attempts))

    @staticmethod
    def _emit_progress(job: PasswordJob, event: PasswordProgressEvent) -> None:
        if job.progress_callback is None:
            return
        job.progress_callback(event)

    def _emit_finished(
        self,
        job: PasswordJob,
        result: PasswordSearchResult,
        started_at: float,
        candidates_seen: int,
        skipped: int,
    ) -> None:
        self._emit_progress(job, PasswordProgressEvent(
            stage="finished",
            attempts=result.attempts,
            candidates_seen=candidates_seen,
            skipped=skipped,
            elapsed_seconds=time.monotonic() - started_at,
            password_found=result.password is not None,
            stopped_reason=result.stopped_reason,
            error_text=result.error_text,
        ))


def _candidate_value(candidate: PasswordCandidate | str) -> str:
    if isinstance(candidate, PasswordCandidate):
        return candidate.value
    return str(candidate)


def _valid_matched_indices(verification: PasswordBatchVerification, batch_size: int) -> tuple[int, ...]:
    raw = verification.matched_indices or (
        (verification.matched_index,) if verification.matched_index >= 0 else ()
    )
    return tuple(dict.fromkeys(
        int(index)
        for index in raw
        if 0 <= int(index) < batch_size
    ))




def _call_fast_verifier(
    verifier: PasswordVerifier,
    archive_path: str,
    passwords: list[str],
    *,
    part_paths: list[str] | None = None,
    archive_input: dict | None = None,
):
    fast = getattr(verifier, "verify_fast_batch", None)
    if not callable(fast):
        return PasswordBatchVerification(
            ok=False,
            status="unknown_needs_final_verifier",
            attempts=0,
            error_text="bounded password verifier is unavailable",
        )
    try:
        return fast(
            archive_path,
            passwords,
            part_paths=part_paths,
            archive_input=archive_input,
        )
    except TypeError as error:
        if "archive_input" not in str(error):
            raise
        return fast(archive_path, passwords, part_paths=part_paths)
