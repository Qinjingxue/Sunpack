from sunpack.pipeline.verification.archive_input_manifest import ArchiveInputManifest, archive_input_manifest_for_evidence
from sunpack.pipeline.verification.evidence import VerificationEvidence
from sunpack.pipeline.verification.methods._archive_output_match import match_archive_output
from sunpack.pipeline.verification.methods._output_stats import (
    output_inventory_for_evidence,
    output_stats_for_evidence,
    should_emit_file_observations,
)
from sunpack.pipeline.verification.registry import register_verification_method
from sunpack.core.contracts.verification import (
    DECISION_RETRY_EXTRACT,
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTENT_INTEGRITY_VERIFIED_COMPLETE,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    VERIFICATION_STRENGTH_MANIFEST,
    VerificationIssue,
    VerificationStep,
)


@register_verification_method("manifest_size_match")
class ManifestSizeMatchMethod:
    name = "manifest_size_match"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStep:
        input_manifest = archive_input_manifest_for_evidence(
            evidence,
        )
        if not input_manifest.ok:
            return VerificationStep(method=self.name, status="skipped")
        expected_files = input_manifest.file_count
        expected_size = input_manifest.total_unpacked_size
        named_count = input_manifest.retained_file_count

        stats = output_stats_for_evidence(evidence)
        if not stats.exists or not stats.is_dir:
            return VerificationStep(method=self.name, status="skipped")

        issues: list[VerificationIssue] = []
        content_integrity = _content_integrity_hint(input_manifest)
        name_completeness = 1.0
        observations = []
        if named_count:
            emit_observations = should_emit_file_observations(evidence, self.name)
            if emit_observations or not _has_identity_worker_inventory(evidence):
                match, observations = match_archive_output(
                    input_manifest,
                    output_inventory_for_evidence(evidence),
                    method=self.name,
                    names_only=True,
                    include_observations=emit_observations,
                )
                coverage = match["coverage"]
                name_completeness = coverage["completeness"]
                if coverage["missing_files"]:
                    issues.append(VerificationIssue(
                        method=self.name,
                        code="fail.manifest_named_files_missing",
                        message="Some manifest-named files were not found in extraction output",
                        path=evidence.output_dir,
                        expected=named_count,
                        actual={
                            **coverage,
                            "source_manifest": True,
                            "archive_type": input_manifest.archive_type,
                            "manifest_source": input_manifest.source,
                        },
                    ))

        if stats.file_count < expected_files:
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.manifest_file_count_under",
                message="Output file count is lower than archive manifest file count",
                path=evidence.output_dir,
                expected=expected_files,
                actual=stats.file_count,
            ))
        elif stats.file_count > expected_files:
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.manifest_file_count_over",
                message="Output file count is higher than archive manifest file count",
                path=evidence.output_dir,
                expected=expected_files,
                actual=stats.file_count,
            ))

        if stats.total_size < expected_size:
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.manifest_size_under",
                message="Output total size is lower than archive manifest unpacked size",
                path=evidence.output_dir,
                expected=expected_size,
                actual=stats.total_size,
            ))
        elif stats.total_size > expected_size:
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.manifest_size_over",
                message="Output total size is higher than archive manifest unpacked size",
                path=evidence.output_dir,
                expected=expected_size,
                actual=stats.total_size,
            ))

        if not issues:
            return VerificationStep(
                method=self.name,
                status="passed",
                completeness_hint=name_completeness,
                content_integrity_hint=content_integrity,
                verification_strength=VERIFICATION_STRENGTH_MANIFEST,
                total_item_count=int(getattr(input_manifest, "item_count", 0) or 0),
                verified_item_count=int(getattr(input_manifest, "verified_item_count", 0) or 0),
                archive_walk_complete=bool(getattr(input_manifest, "archive_walk_complete", False)),
                file_observations=observations,
            )
        completeness = min(
            name_completeness,
            _manifest_completeness(stats.file_count, stats.total_size, expected_files, expected_size),
        )
        return VerificationStep(
            method=self.name,
            status="warning",
            issues=issues,
            completeness_hint=completeness,
            content_integrity_hint=(
                CONTENT_INTEGRITY_VERIFIED_PARTIAL
                if content_integrity == CONTENT_INTEGRITY_VERIFIED_COMPLETE and completeness < 0.999
                else content_integrity
            ),
            verification_strength=VERIFICATION_STRENGTH_MANIFEST,
            total_item_count=int(getattr(input_manifest, "item_count", 0) or 0),
            verified_item_count=int(getattr(input_manifest, "verified_item_count", 0) or 0),
            archive_walk_complete=bool(getattr(input_manifest, "archive_walk_complete", False)),
            recoverable_upper_bound_hint=completeness,
            decision_hint=DECISION_RETRY_EXTRACT,
            file_observations=observations,
        )


def _has_identity_worker_inventory(evidence: VerificationEvidence) -> bool:
    worker = evidence.worker_result
    manifest = worker.get("verified_manifest", {})
    inventory = manifest.get("inventory", {})
    return bool(
        worker.get("status") == "ok"
        and manifest.get("validated")
        and inventory.get("complete")
        and inventory.get("identity_paths")
    )


def _manifest_completeness(actual_files: int, actual_size: int, expected_files: int, expected_size: int) -> float:
    ratios = []
    if expected_files > 0:
        ratios.append(min(1.0, max(0.0, actual_files / expected_files)))
    if expected_size > 0:
        ratios.append(min(1.0, max(0.0, actual_size / expected_size)))
    return min(ratios) if ratios else 1.0


def _content_integrity_hint(input_manifest: ArchiveInputManifest) -> str:
    if input_manifest.checksum_error:
        return CONTENT_INTEGRITY_PAYLOAD_DAMAGED
    if (
        input_manifest.archive_walk_complete
        and input_manifest.verified_item_count >= input_manifest.item_count
    ):
        return CONTENT_INTEGRITY_VERIFIED_COMPLETE
    return CONTENT_INTEGRITY_UNKNOWN

