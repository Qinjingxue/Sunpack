from __future__ import annotations

from sunpack.core.passwords.candidates import PasswordCandidatePipeline, PasswordCandidate

import asyncio
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from functools import wraps
from itertools import chain, islice
from typing import Literal

from sunpack.core.passwords.cache import PasswordAttemptCache
from sunpack.core.passwords.fingerprint import build_archive_fingerprint
from sunpack.core.passwords.job import PasswordJob
from sunpack.core.passwords.verifier import PasswordBatchVerification, PasswordVerifier, PasswordVerifierRegistry
from sunpack.core.passwords.verifier.rar_fast import RarFastVerifier
from sunpack.core.passwords.verifier.seven_zip_fast import SevenZipFastVerifier
from sunpack.core.passwords.verifier.zip_fast import ZipFastVerifier
from sunpack.core.passwords.verifier.enc_fast import EncFastVerifier
from sunpack.core.passwords.verifier.input import PasswordProbeInput
from sunpack.core.support.archive_sessions import archive_session_scope
from sunpack.core.support.work_context import CURRENT_CANCELLATION


def _raise_if_cancelled() -> None:
    cancellation = CURRENT_CANCELLATION.get()
    if cancellation is not None:
        cancellation.raise_if_cancelled()


def _cancellable_password_job(operation):
    @wraps(operation)
    def run(*args, **kwargs):
        cancellation = CURRENT_CANCELLATION.get()
        if cancellation is None:
            return operation(*args, **kwargs)
        from sunpack_native import PasswordCancellation, PasswordProbeCancelled

        cancellation.raise_if_cancelled()
        native = PasswordCancellation()
        unsubscribe = cancellation.subscribe(native.cancel)
        try:
            with native:
                try:
                    result = operation(*args, **kwargs)
                    cancellation.raise_if_cancelled()
                    return result
                except PasswordProbeCancelled:
                    raise asyncio.CancelledError from None
        finally:
            unsubscribe()
    return run


class PasswordSearchStatus(str, Enum):
    FOUND = "found"
    UNENCRYPTED = "unencrypted"
    EXHAUSTED = "exhausted"
    INCONCLUSIVE = "inconclusive"
    DAMAGED = "damaged"
    UNSUPPORTED = "unsupported"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    NEEDS_VOLUME_OR_TAIL_DAMAGED = "needs_volume_or_tail_damaged"
    MISSING_VOLUME = "missing_volume"


# Verdicts about the archive/backend rather than the tried passwords. Trying
# more candidates cannot change them, and they must not end as EXHAUSTED.
_ARCHIVE_LEVEL_STATUSES = frozenset({
    PasswordSearchStatus.DAMAGED,
    PasswordSearchStatus.UNSUPPORTED,
    PasswordSearchStatus.BACKEND_UNAVAILABLE,
    PasswordSearchStatus.NEEDS_VOLUME_OR_TAIL_DAMAGED,
    PasswordSearchStatus.MISSING_VOLUME,
})


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
            fast_verifiers=[ZipFastVerifier(), RarFastVerifier(), SevenZipFastVerifier(), EncFastVerifier()],
        )
        return cls(registry.build())

    @archive_session_scope()
    @_cancellable_password_job
    def run(self, job: PasswordJob) -> PasswordSearchResult:
        started_at = time.monotonic()
        self._emit_progress(job, PasswordProgressEvent(stage="started"))
        fingerprint = job.fingerprint or build_archive_fingerprint(
            job.archive_path,
            job.part_paths,
            archive_input=job.archive_input,
        )
        cached_success = self.cache.get_success(fingerprint.key)
        if cached_success is not None and _allows_cached_password(job, cached_success):
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

        with _prepare_job(self.verifier, job) as job:
            attempts = 0
            candidates_seen = 0
            skipped = 0
            last_result = None
            last_error = ""
            batch_size = max(1, int(job.batch_size or self.default_batch_size))
            batch: list[str] = []

            for candidate in job.candidate_pipeline():
                _raise_if_cancelled()
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
                if len(batch) >= batch_size:
                    outcome = self._verify_batch(job, fingerprint.key, batch, attempts, started_at, candidates_seen, skipped)
                    attempts = outcome.attempts
                    last_result = outcome.test_result
                    last_error = outcome.error_text
                    if (
                        outcome.password is not None
                        or outcome.stopped_reason
                        or outcome.status in _ARCHIVE_LEVEL_STATUSES
                    ):
                        self._emit_finished(job, outcome, started_at, candidates_seen, skipped)
                        return outcome
                    batch = []

            if batch:
                outcome = self._verify_batch(job, fingerprint.key, batch, attempts, started_at, candidates_seen, skipped)
                attempts = outcome.attempts
                last_result = outcome.test_result
                last_error = outcome.error_text
                if (
                    outcome.password is not None
                    or outcome.stopped_reason
                    or outcome.status in _ARCHIVE_LEVEL_STATUSES
                ):
                    self._emit_finished(job, outcome, started_at, candidates_seen, skipped)
                    return outcome

            result = PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.EXHAUSTED,
                test_result=last_result,
                error_text=last_error,
                attempts=attempts,
                exhausted=True,
                stopped_reason="candidates_rejected" if candidates_seen else "no_candidates",
            )
            self._emit_finished(job, result, started_at, candidates_seen, skipped)
            return result

    @archive_session_scope()
    @_cancellable_password_job
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
        if cached_success is not None and _allows_cached_password(job, cached_success):
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

        with _prepare_job(self.verifier, job) as job:
            pipeline = job.candidate_pipeline()
            seen: set[str] | None = None if isinstance(pipeline, PasswordCandidatePipeline) else set()
            skipped = 0
            candidates_seen = 0

            def available_candidates():
                nonlocal skipped, candidates_seen
                for candidate in pipeline:
                    _raise_if_cancelled()
                    password = _candidate_value(candidate)
                    if seen is not None:
                        if password in seen:
                            continue
                        seen.add(password)
                    if self.cache.has_negative(fingerprint.key, password):
                        skipped += 1
                        continue
                    candidates_seen += 1
                    yield password

            candidates = iter(available_candidates())

            # The authoritative Rust descriptor identifies ENC independently of its
            # physical name. One remaining candidate needs only the worker's Open;
            # the ordinary extraction-confirmation path commits success/rejection.
            if str((job.archive_input or {}).get("format_hint") or "").strip().lower() == "enc":
                first = list(islice(candidates, 2))
                if len(first) == 1:
                    result = PasswordSearchResult(
                        password=None,
                        status=PasswordSearchStatus.INCONCLUSIVE,
                        attempts=0,
                        stopped_reason="extraction_confirmation_required",
                        extraction_candidates=tuple(first),
                    )
                    self._emit_finished(job, result, started_at, candidates_seen, skipped)
                    return result
                candidates = chain(first, candidates)

            batch_size = max(1, int(job.batch_size or self.default_batch_size))
            inconclusive: list[str] = []
            inconclusive_evidence = ""
            attempts = 0
            while batch := list(islice(candidates, batch_size)):
                _raise_if_cancelled()
                verification = _call_fast_verifier(
                    self.verifier,
                    job.archive_path,
                    batch,
                    part_paths=job.part_paths,
                    archive_input=job.probe_input or job.archive_input,
                )
                _raise_if_cancelled()
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
                    self._emit_finished(job, result, started_at, candidates_seen, skipped)
                    return result
                matched_indices = _valid_matched_indices(verification, len(batch))
                tested_count = max(0, min(int(verification.attempts or 0), len(batch)))
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
                        self._emit_finished(job, result, started_at, candidates_seen, skipped)
                        return result
                    matched_set = set(matched_indices)
                    inconclusive.extend(batch[index] for index in matched_indices)
                    self.cache.remember_negative_batch(
                        fingerprint.key,
                        [
                            batch[index]
                            for index in range(tested_count)
                            if index not in matched_set
                        ],
                    )
                    inconclusive.extend(
                        batch[index]
                        for index in range(tested_count, len(batch))
                        if index not in matched_set
                    )
                    if not inconclusive_evidence:
                        inconclusive_evidence = verification.match_evidence
                    elif verification.match_evidence != inconclusive_evidence:
                        inconclusive_evidence = ""
                    continue
                if verification.status == "no_match":
                    self.cache.remember_negative_batch(fingerprint.key, batch[:tested_count])
                    if tested_count < len(batch):
                        inconclusive.extend(batch[tested_count:])
                    continue
                if verification.status in {"damaged", "needs_volume_or_tail_damaged", "missing_volume"}:
                    result = PasswordSearchResult(
                        password=None,
                        status=_archive_failure_status(verification.status, job),
                        test_result=verification.test_result,
                        error_text=verification.error_text,
                        attempts=attempts,
                        stopped_reason="terminal",
                    )
                    self._emit_finished(job, result, started_at, candidates_seen, skipped)
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
                    extraction_candidates=tuple(inconclusive),
                    extraction_candidate_evidence=inconclusive_evidence,
                )
            else:
                result = PasswordSearchResult(
                    password=None,
                    status=PasswordSearchStatus.EXHAUSTED,
                    attempts=attempts,
                    exhausted=True,
                    stopped_reason="candidates_rejected" if candidates_seen or skipped else "no_candidates",
                )
            self._emit_finished(job, result, started_at, candidates_seen, skipped)
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
            archive_input=job.probe_input or job.archive_input,
        )
        _raise_if_cancelled()
        attempted_in_batch = max(0, min(max(verification.attempts, 0), len(batch)))
        if (
            not verification.ok
            and attempted_in_batch == 0
            and verification.status not in {"needs_volume_or_tail_damaged", "missing_volume"}
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
            "unsupported_method": PasswordSearchStatus.UNSUPPORTED,
            "backend_unavailable": PasswordSearchStatus.BACKEND_UNAVAILABLE,
        }
        search_status = (
            _archive_failure_status(verification.status, job)
            if verification.status in {"damaged", "needs_volume_or_tail_damaged", "missing_volume"}
            else status_by_verification.get(verification.status, PasswordSearchStatus.INCONCLUSIVE)
        )
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


def _archive_failure_status(status: str, job: PasswordJob) -> PasswordSearchStatus:
    if status == "needs_volume_or_tail_damaged":
        # Reuse the Rust analysis already attached to this exact logical input.
        # A tail read fault alone is not proof that another volume exists.
        execution = (job.archive_input or {}).get("analysis", {}).get("execution", {})
        if execution.get("missing_volume_evidence"):
            return PasswordSearchStatus.MISSING_VOLUME
    return PasswordSearchStatus(status)


def _candidate_value(candidate: PasswordCandidate | str) -> str:
    if isinstance(candidate, PasswordCandidate):
        return candidate.value
    return str(candidate)


@contextmanager
def _prepare_job(verifier, job: PasswordJob):
    prepare = getattr(verifier, "prepare_input", None)
    if prepare is None:
        yield job
        return
    prepared = prepare(job.archive_path, part_paths=job.part_paths, archive_input=job.archive_input)
    with prepared.scope() as bound:
        yield replace(job, probe_input=bound)


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
    archive_input: dict | PasswordProbeInput | None = None,
):
    fast = getattr(verifier, "verify_fast_batch", None)
    if not callable(fast):
        return PasswordBatchVerification(
            ok=False,
            status="unknown_needs_final_verifier",
            attempts=0,
            error_text="bounded password verifier is unavailable",
        )
    return fast(
        archive_path,
        passwords,
        part_paths=part_paths,
        archive_input=archive_input,
    )


def _allows_cached_password(job: PasswordJob, password: str) -> bool:
    if password == "":
        return True
    candidates = job.candidate_pipeline()
    if isinstance(candidates, PasswordCandidatePipeline):
        return candidates.allows(password)
    # Bare iterables are caller-owned; only a repeatable collection can validate
    # a cache hit without consuming the upcoming verifier stream.
    if iter(candidates) is candidates:
        return False
    return any((candidate.value if isinstance(candidate, PasswordCandidate) else candidate) == password for candidate in candidates)
