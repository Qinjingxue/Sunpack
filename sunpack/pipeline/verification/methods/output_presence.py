from sunpack.pipeline.verification.evidence import VerificationEvidence
from sunpack.pipeline.verification.methods._output_stats import output_stats_for_evidence, should_emit_file_observations
from sunpack.pipeline.verification.registry import register_verification_method
from sunpack.core.contracts.verification import FileVerificationObservation, VerificationIssue, VerificationStep


@register_verification_method("output_presence")
class OutputPresenceMethod:
    name = "output_presence"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStep:
        stats = output_stats_for_evidence(evidence)
        issues: list[VerificationIssue] = []
        if not stats.exists:
            return self._fail(
                code="fail.output_missing",
                message="Extraction output directory does not exist",
                path=evidence.output_dir,
            )
        if not stats.is_dir:
            return self._fail(
                code="fail.output_not_directory",
                message="Extraction output path is not a directory",
                path=evidence.output_dir,
            )
        if stats.file_count <= 0:
            return self._fail(
                code="fail.output_empty",
                message="Extraction output contains no files",
                path=evidence.output_dir,
            )

        if stats.unreadable_count:
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.output_unreadable_files",
                message="Some output files could not be inspected",
                path=evidence.output_dir,
                expected=0,
                actual=stats.unreadable_count,
            ))

        if stats.transient_file_count and stats.transient_file_count == stats.file_count:
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.output_only_transient_files",
                message="Extraction output only contains transient-looking files",
                path=evidence.output_dir,
                expected=0,
                actual=stats.transient_file_count,
            ))
        elif stats.transient_file_count:
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.output_transient_files",
                message="Extraction output contains transient-looking files",
                path=evidence.output_dir,
                expected=0,
                actual=stats.transient_file_count,
            ))

        observations = _manifest_observations(evidence) if should_emit_file_observations(evidence, self.name) else []
        manifest_completeness = _manifest_completeness(evidence)
        if evidence.progress_manifest:
            coverage = _manifest_coverage(evidence)
            issues.append(VerificationIssue(
                method=self.name,
                code="info.output_progress_coverage",
                message="Worker extraction progress was converted into output completeness",
                path=evidence.output_dir,
                expected=(evidence.progress_manifest.get("summary") or {}).get("total"),
                actual={
                    **coverage,
                    "completeness": manifest_completeness,
                    "summary": dict(evidence.progress_manifest.get("summary") or {}),
                    "files_written": evidence.progress_manifest.get("files_written"),
                    "bytes_written": evidence.progress_manifest.get("bytes_written"),
                },
            ))
        return VerificationStep(
            method=self.name,
            status="warning" if issues else "passed",
            issues=issues,
            completeness_hint=manifest_completeness,
            file_observations=observations,
        )

    def _fail(self, code: str, message: str, path: str) -> VerificationStep:
        return VerificationStep(
            method=self.name,
            status="failed",
            completeness_hint=0.0,
            issues=[
                VerificationIssue(
                    method=self.name,
                    code=code,
                    message=message,
                    path=path,
                )
            ],
        )


def _manifest_observations(evidence: VerificationEvidence) -> list[FileVerificationObservation]:
    manifest = evidence.progress_manifest or {}
    observations: list[FileVerificationObservation] = []
    for item in manifest.get("files") or []:
        if not isinstance(item, dict):
            continue
        state = str(item.get("status") or "unverified")
        observations.append(FileVerificationObservation(
            path=str(item.get("path") or item.get("archive_path") or ""),
            archive_path=str(item.get("archive_path") or ""),
            state=state if state in {"complete", "partial", "failed", "missing", "unverified"} else "unverified",
            method="output_presence",
            bytes_written=_as_int(item.get("bytes_written")),
            expected_size=_optional_int(item.get("expected_size")),
            progress=_progress(item),
        ))
    return observations


def _manifest_completeness(evidence: VerificationEvidence) -> float:
    manifest = evidence.progress_manifest or {}
    files = [item for item in manifest.get("files") or [] if isinstance(item, dict)]
    if not files:
        return 1.0
    total = 0.0
    for item in files:
        progress = _progress(item)
        if progress is not None:
            total += progress
            continue
        status = str(item.get("status") or "")
        if status == "complete":
            total += 1.0
        elif status == "partial":
            total += 0.5
    return min(1.0, max(0.0, total / max(1, len(files))))


def _manifest_coverage(evidence: VerificationEvidence) -> dict:
    manifest = evidence.progress_manifest or {}
    files = [item for item in manifest.get("files") or [] if isinstance(item, dict)]
    expected_files = len(files)
    matched_files = sum(1 for item in files if str(item.get("status") or "") != "failed" or _as_int(item.get("bytes_written")) > 0)
    complete_files = sum(1 for item in files if str(item.get("status") or "") == "complete")
    partial_files = sum(1 for item in files if str(item.get("status") or "") == "partial")
    failed_files = sum(1 for item in files if str(item.get("status") or "") == "failed")
    unverified_files = sum(1 for item in files if str(item.get("status") or "") == "unverified")
    expected_bytes = sum(_optional_int(item.get("expected_size")) or 0 for item in files)
    matched_bytes = 0
    complete_bytes = 0
    for item in files:
        expected = _optional_int(item.get("expected_size")) or 0
        written = _as_int(item.get("bytes_written"))
        matched_bytes += min(written, expected) if expected else written
        if str(item.get("status") or "") == "complete":
            complete_bytes += expected or written
    file_coverage = matched_files / max(1, expected_files)
    byte_coverage = matched_bytes / expected_bytes if expected_bytes > 0 else file_coverage
    return {
        "file_coverage": round(file_coverage, 6),
        "byte_coverage": round(byte_coverage, 6),
        "expected_files": expected_files,
        "matched_files": matched_files,
        "complete_files": complete_files,
        "partial_files": partial_files,
        "failed_files": failed_files,
        "missing_files": 0,
        "unverified_files": unverified_files,
        "expected_bytes": expected_bytes,
        "matched_bytes": matched_bytes,
        "complete_bytes": complete_bytes,
    }


def _progress(item: dict) -> float | None:
    expected = _optional_int(item.get("expected_size"))
    bytes_written = _as_int(item.get("bytes_written"))
    if expected and expected > 0:
        return min(1.0, max(0.0, bytes_written / expected))
    status = str(item.get("status") or "")
    if status == "complete":
        return 1.0
    if status == "failed":
        return 0.0
    if status == "partial":
        return 0.5
    return None


def _as_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _optional_int(value) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
