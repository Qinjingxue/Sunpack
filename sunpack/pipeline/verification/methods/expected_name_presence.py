from typing import Any

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
    should_emit_file_observations,
)
from sunpack.pipeline.verification.registry import register_verification_method
from sunpack.core.contracts.verification import (
    DECISION_NONE,
    DECISION_RETRY_EXTRACT,
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTENT_INTEGRITY_VERIFIED_COMPLETE,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    VERIFICATION_STRENGTH_MANIFEST,
    VerificationIssue,
    VerificationStep,
)
from sunpack.core.support.path_names import clean_relative_archive_path, normalize_match_path




@register_verification_method("expected_name_presence")
class ExpectedNamePresenceMethod:
    name = "expected_name_presence"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStep:
        config = {**advanced_named_config(("verification", "methods"), self.name), **config}
        input_manifest = archive_input_manifest_for_evidence(
            evidence,
            max_items=max(1, int(config.get("max_expected_names", 50) or 50)),
        )
        expected_names = self._expected_names(config, input_manifest)
        if not expected_names:
            return VerificationStep(method=self.name, status="skipped")

        inventory = output_inventory_for_evidence(evidence)
        stats = inventory.stats
        if not stats.exists or not stats.is_dir or stats.file_count <= 0:
            return VerificationStep(method=self.name, status="skipped")

        emit_observations = should_emit_file_observations(evidence, self.name)
        if inventory.worker_inventory_complete and inventory.identity_paths and not emit_observations:
            count = len(expected_names)
            coverage = ArchiveOutputCoverage(
                completeness=1.0, file_coverage=1.0, byte_coverage=1.0,
                expected_files=count, matched_files=count, complete_files=count,
                partial_files=0, failed_files=0, missing_files=0,
                expected_bytes=0, matched_bytes=0, complete_bytes=0,
            )
            missing = []
        else:
            detail_limit = (
                min(len(expected_names), max(1, int(config.get("detail_page_size", 128) or 128)))
                if emit_observations
                else 0
            )
            coverage, native_match = coverage_from_native_inventory(
                archive_files_from_names(expected_names),
                inventory,
                method=self.name,
                basename_mode="any",
                include_observations=emit_observations,
                detail_limit=detail_limit,
                max_issue_items=len(expected_names),
            )
            missing = [str(item) for item in native_match.get("missing") or []]

        if not missing:
            return VerificationStep(
                method=self.name,
                status="passed",
                completeness_hint=coverage.completeness,
                content_integrity_hint=_content_integrity_hint(input_manifest),
                verification_strength=VERIFICATION_STRENGTH_MANIFEST,
                total_item_count=int(getattr(input_manifest, "item_count", 0) or 0),
                verified_item_count=int(getattr(input_manifest, "verified_item_count", 0) or 0),
                archive_walk_complete=bool(getattr(input_manifest, "archive_walk_complete", False)),
                file_observations=coverage.observations,
                issues=[VerificationIssue(
                    method=self.name,
                    code="info.expected_name_coverage",
                    message="Expected archive names were matched against extraction output",
                    path=evidence.output_dir,
                    expected=len(expected_names),
                    actual=_coverage_actual(coverage, input_manifest),
                )],
            )

        total = len(expected_names)
        matched = total - len(missing)
        missing_ratio = len(missing) / max(1, total)
        required_match_ratio = float(config["required_match_ratio"] or 0.0)
        actual_match_ratio = matched / max(1, total)
        if actual_match_ratio >= required_match_ratio:
            penalty = int(config["minor_missing_penalty"])
            code = "warning.expected_names_partially_missing"
        elif matched == 0:
            penalty = int(config["all_missing_penalty"])
            code = "fail.expected_names_all_missing"
        else:
            penalty = int(config["missing_penalty"])
            code = "fail.expected_names_missing"

        issue = VerificationIssue(
            method=self.name,
            code=code,
            message="Expected archive item names were not found in extraction output",
            path=evidence.output_dir,
            expected=expected_names,
            actual={
                "matched": matched,
                "missing": missing,
                "missing_ratio": round(missing_ratio, 3),
                "coverage": _coverage_actual(coverage, input_manifest),
            },
        )
        content_integrity = _content_integrity_hint(input_manifest)
        return VerificationStep(
            method=self.name,
            status="warning",
            issues=[issue],
            completeness_hint=coverage.completeness,
            recoverable_upper_bound_hint=coverage.completeness,
            content_integrity_hint=(
                CONTENT_INTEGRITY_VERIFIED_PARTIAL
                if _expected_names_are_strong(config, content_integrity, input_manifest)
                else content_integrity
            ),
            verification_strength=VERIFICATION_STRENGTH_MANIFEST,
            total_item_count=int(getattr(input_manifest, "item_count", 0) or 0),
            verified_item_count=int(getattr(input_manifest, "verified_item_count", 0) or 0),
            archive_walk_complete=bool(getattr(input_manifest, "archive_walk_complete", False)),
            decision_hint=DECISION_RETRY_EXTRACT if _expected_names_are_strong(config, content_integrity, input_manifest) else DECISION_NONE,
            file_observations=coverage.observations,
        )

    def _expected_names(
        self,
        config: dict,
        input_manifest: ArchiveInputManifest | None = None,
    ) -> list[str]:
        configured = config.get("expected_names")
        candidates = list(_iter_name_values(configured))
        if not candidates and input_manifest is not None and input_manifest.ok:
            candidates.extend(input_manifest.expected_names)

        max_names = max(1, int(config.get("max_expected_names", 50) or 50))
        names = []
        seen = set()
        for candidate in candidates:
            cleaned = clean_relative_archive_path(candidate)
            if not cleaned:
                continue
            key = normalize_match_path(cleaned)
            if key in seen:
                continue
            seen.add(key)
            names.append(cleaned)
            if len(names) >= max_names:
                break
        return names

def _iter_name_values(value: Any):
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, bytes):
        try:
            yield value.decode("utf-8", errors="replace")
        except Exception:
            return
        return
    if isinstance(value, dict):
        for key in ("name", "path", "file", "filename"):
            if key in value:
                yield from _iter_name_values(value.get(key))
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_name_values(item)


def _content_integrity_hint(input_manifest: ArchiveInputManifest | None = None) -> str:
    if input_manifest is None:
        return CONTENT_INTEGRITY_UNKNOWN
    if input_manifest.checksum_error:
        return CONTENT_INTEGRITY_PAYLOAD_DAMAGED
    if input_manifest.archive_walk_complete and input_manifest.verified_item_count >= input_manifest.item_count:
        return CONTENT_INTEGRITY_VERIFIED_COMPLETE
    return CONTENT_INTEGRITY_UNKNOWN


def _expected_names_are_strong(
    config: dict,
    content_integrity: str,
    input_manifest: ArchiveInputManifest | None = None,
) -> bool:
    if config.get("expected_names"):
        return True
    if input_manifest is not None and input_manifest.ok and input_manifest.expected_names:
        return True
    return content_integrity == CONTENT_INTEGRITY_VERIFIED_COMPLETE


def _coverage_actual(coverage, input_manifest: ArchiveInputManifest | None) -> dict[str, Any]:
    actual = coverage_details(coverage)
    actual.update({
        "source_manifest": True,
        "archive_type": input_manifest.archive_type if input_manifest is not None else "",
        "manifest_source": input_manifest.source if input_manifest is not None and input_manifest.ok else "configured",
    })
    return actual
