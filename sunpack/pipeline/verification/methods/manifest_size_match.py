from sunpack.core.config.advanced_defaults import advanced_named_config
from sunpack.pipeline.verification.archive_input_manifest import ArchiveInputManifest, archive_input_manifest_for_evidence
from sunpack.pipeline.verification.evidence import VerificationEvidence
from sunpack.pipeline.verification.methods._archive_output_match import (
    ArchiveOutputCoverage,
    archive_files_from_names,
    coverage_details,
    coverage_from_native_inventory,
)
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
        config = {**advanced_named_config(("verification", "methods"), self.name), **config}
        input_manifest = archive_input_manifest_for_evidence(
            evidence,
            max_items=max(1, int(config.get("max_expected_names", 2000) or 2000)),
        )
        expected_files = _expected_file_count(input_manifest)
        expected_size = _expected_total_size(input_manifest)
        expected_names = _expected_names(input_manifest)
        if expected_files <= 0 and expected_size <= 0:
            return VerificationStep(method=self.name, status="skipped")

        stats = output_stats_for_evidence(evidence)
        if not stats.exists or not stats.is_dir:
            return VerificationStep(method=self.name, status="skipped")

        issues: list[VerificationIssue] = []
        content_integrity = _content_integrity_hint(input_manifest)
        name_coverage = None
        if expected_names:
            emit_observations = should_emit_file_observations(evidence, self.name)
            if _identity_worker_inventory(evidence) is not None and not emit_observations:
                count = len(expected_names)
                name_coverage = ArchiveOutputCoverage(
                    completeness=1.0, file_coverage=1.0, byte_coverage=1.0,
                    expected_files=count, matched_files=count, complete_files=count,
                    partial_files=0, failed_files=0, missing_files=0,
                    expected_bytes=0, matched_bytes=0, complete_bytes=0,
                )
            else:
                detail_limit = (
                    min(len(expected_names), 128)
                    if emit_observations
                    else 0
                )
                name_coverage, _ = coverage_from_native_inventory(
                    archive_files_from_names(expected_names),
                    output_inventory_for_evidence(evidence),
                    method=self.name,
                    basename_mode="unique",
                    include_observations=emit_observations,
                    detail_limit=detail_limit,
                    max_issue_items=0,
                )
            if name_coverage.missing_files:
                issues.append(VerificationIssue(
                    method=self.name,
                    code="fail.manifest_named_files_missing",
                    message="Some manifest-named files were not found in extraction output",
                    path=evidence.output_dir,
                    expected=len(expected_names),
                    actual=_coverage_actual(name_coverage, input_manifest),
                ))

        if expected_files > 0:
            file_tolerance = max(
                int(config["file_count_abs_tolerance"] or 0),
                int(expected_files * float(config["file_count_ratio_tolerance"] or 0.0)),
            )
            lower_bound = max(0, expected_files - file_tolerance)
            upper_bound = expected_files + file_tolerance
            if stats.file_count < lower_bound:
                issues.append(VerificationIssue(
                    method=self.name,
                    code="fail.manifest_file_count_under",
                    message="Output file count is lower than archive manifest file count",
                    path=evidence.output_dir,
                    expected=expected_files,
                    actual=stats.file_count,
                ))
            elif stats.file_count > upper_bound:
                issues.append(VerificationIssue(
                    method=self.name,
                    code="warning.manifest_file_count_over",
                    message="Output file count is higher than archive manifest file count",
                    path=evidence.output_dir,
                    expected=expected_files,
                    actual=stats.file_count,
                ))

        if expected_size > 0:
            size_tolerance = max(
                int(config["size_abs_tolerance_bytes"] or 0),
                int(expected_size * float(config["size_ratio_tolerance"] or 0.0)),
            )
            lower_bound = max(0, expected_size - size_tolerance)
            upper_bound = expected_size + size_tolerance
            if stats.total_size < lower_bound:
                issues.append(VerificationIssue(
                    method=self.name,
                    code="fail.manifest_size_under",
                    message="Output total size is lower than archive manifest unpacked size",
                    path=evidence.output_dir,
                    expected=expected_size,
                    actual=stats.total_size,
                ))
            elif stats.total_size > upper_bound:
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
                completeness_hint=name_coverage.completeness if name_coverage is not None else 1.0,
                content_integrity_hint=content_integrity,
                verification_strength=VERIFICATION_STRENGTH_MANIFEST,
                total_item_count=int(getattr(input_manifest, "item_count", 0) or 0),
                verified_item_count=int(getattr(input_manifest, "verified_item_count", 0) or 0),
                archive_walk_complete=bool(getattr(input_manifest, "archive_walk_complete", False)),
                file_observations=name_coverage.observations if name_coverage is not None else [],
            )
        completeness = _manifest_completeness(stats.file_count, stats.total_size, expected_files, expected_size)
        if name_coverage is not None:
            completeness = min(completeness, name_coverage.completeness)
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
            file_observations=name_coverage.observations if name_coverage is not None else [],
        )


def _identity_worker_inventory(evidence) -> dict | None:
    worker = evidence.worker_result if isinstance(evidence.worker_result, dict) else {}
    manifest = worker.get("verified_manifest") if isinstance(worker.get("verified_manifest"), dict) else {}
    inventory = manifest.get("inventory") if isinstance(manifest.get("inventory"), dict) else {}
    if (
        worker.get("status") == "ok"
        and manifest.get("validated")
        and inventory.get("complete")
        and inventory.get("identity_paths")
    ):
        return inventory
    return None


def _manifest_completeness(actual_files: int, actual_size: int, expected_files: int, expected_size: int) -> float:
    ratios = []
    if expected_files > 0:
        ratios.append(min(1.0, max(0.0, actual_files / expected_files)))
    if expected_size > 0:
        ratios.append(min(1.0, max(0.0, actual_size / expected_size)))
    return min(ratios) if ratios else 1.0


def _content_integrity_hint(input_manifest: ArchiveInputManifest | None = None) -> str:
    if input_manifest is None:
        return CONTENT_INTEGRITY_UNKNOWN
    if input_manifest.checksum_error:
        return CONTENT_INTEGRITY_PAYLOAD_DAMAGED
    if (
        input_manifest.archive_walk_complete
        and input_manifest.verified_item_count >= input_manifest.item_count
    ):
        return CONTENT_INTEGRITY_VERIFIED_COMPLETE
    return CONTENT_INTEGRITY_UNKNOWN


def _expected_names(input_manifest: ArchiveInputManifest | None = None) -> list[str]:
    if input_manifest is None or not input_manifest.ok:
        return []
    return list(input_manifest.expected_names)[:2000]


def _expected_file_count(input_manifest: ArchiveInputManifest) -> int:
    return int(input_manifest.file_count or 0) if input_manifest.ok else 0


def _expected_total_size(input_manifest: ArchiveInputManifest) -> int:
    return int(input_manifest.total_unpacked_size or 0) if input_manifest.ok else 0


def _coverage_actual(coverage, input_manifest: ArchiveInputManifest) -> dict:
    actual = coverage_details(coverage)
    actual.update({
        "source_manifest": True,
        "archive_type": input_manifest.archive_type,
        "manifest_source": input_manifest.source,
    })
    return actual

