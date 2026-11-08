from sunpack.pipeline.verification.evidence import VerificationEvidence
from sunpack.pipeline.verification.methods._output_stats import (
    output_stats_for_evidence, progress_observations, should_emit_file_observations,
)
from sunpack.pipeline.verification.registry import register_verification_method
from sunpack.core.contracts.verification import VerificationIssue, VerificationStep


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

        observations = progress_observations(evidence, self.name) if should_emit_file_observations(evidence, self.name) else []
        manifest = evidence.progress_manifest
        manifest_completeness = manifest.completeness() if manifest is not None else 1.0
        if manifest is not None:
            summary = manifest.summary
            issues.append(VerificationIssue(
                method=self.name,
                code="info.output_progress_coverage",
                message="Worker extraction progress was converted into output completeness",
                path=evidence.output_dir,
                expected=summary.get("total"),
                actual={
                    **manifest.coverage(),
                    "completeness": manifest_completeness,
                    "summary": summary,
                    "files_written": manifest.files_written,
                    "bytes_written": manifest.bytes_written,
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
