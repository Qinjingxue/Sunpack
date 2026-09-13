import os
from typing import Any

from sunpack.config.advanced_defaults import advanced_named_config
from sunpack.support.sevenzip_bridge import STATUS_DAMAGED, STATUS_OK
from sunpack.verification.archive_state_manifest import ArchiveStateManifest, archive_state_manifest_for_evidence
from sunpack.verification.evidence import VerificationEvidence
from sunpack.verification.methods._archive_output_match import (
    ArchiveOutputCoverage,
    archive_files_from_names,
    coverage_details,
    coverage_from_archive_and_output,
)
from sunpack.verification.methods._output_stats import (
    output_file_index_for_evidence,
    output_inventory_for_evidence,
    should_emit_file_observations,
)
from sunpack.verification.registry import register_verification_method
from sunpack.contracts.verification import (
    DECISION_NONE,
    DECISION_RETRY_EXTRACT,
    CONTENT_INTEGRITY_PAYLOAD_DAMAGED,
    CONTENT_INTEGRITY_UNKNOWN,
    CONTENT_INTEGRITY_VERIFIED_COMPLETE,
    CONTENT_INTEGRITY_VERIFIED_PARTIAL,
    VERIFICATION_STRENGTH_MANIFEST,
    VerificationIssue,
    VerificationStepResult,
)
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.path_names import clean_relative_archive_path, normalize_match_name, normalize_match_path


NAME_FIELDS = (
    "expected_names",
    "manifest_names",
    "item_names",
    "file_names",
    "path_samples",
    "paths",
)


@register_verification_method("expected_name_presence")
class ExpectedNamePresenceMethod:
    name = "expected_name_presence"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        config = {**advanced_named_config(("verification", "methods"), self.name), **config}
        state_manifest = archive_state_manifest_for_evidence(
            evidence,
            max_items=max(1, int(config.get("max_expected_names", 50) or 50)),
        )
        expected_names = self._expected_names(evidence, config, state_manifest)
        if not expected_names:
            return VerificationStepResult(method=self.name, status="skipped")

        inventory = output_inventory_for_evidence(evidence)
        stats = inventory.stats
        if not stats.exists or not stats.is_dir or stats.file_count <= 0:
            return VerificationStepResult(method=self.name, status="skipped")

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
            output_index = output_file_index_for_evidence(evidence)
            output_paths = output_index.normalized_paths
            output_basenames = output_index.normalized_basenames
            coverage = coverage_from_archive_and_output(
                archive_files_from_names(expected_names),
                output_index.files,
                method=self.name,
                include_observations=emit_observations,
                output_index=output_index,
            )
            missing = []
            for expected in expected_names:
                normalized_path = normalize_match_path(expected)
                basename = normalize_match_name(os.path.basename(normalized_path))
                if normalized_path in output_paths or basename in output_basenames:
                    continue
                missing.append(expected)

        if not missing:
            return VerificationStepResult(
                method=self.name,
                status="passed",
                completeness_hint=coverage.completeness,
                content_integrity_hint=_content_integrity_hint(state_manifest),
                verification_strength=VERIFICATION_STRENGTH_MANIFEST,
                total_item_count=int(getattr(state_manifest, "item_count", 0) or 0),
                verified_item_count=int(getattr(state_manifest, "verified_item_count", 0) or 0),
                archive_walk_complete=bool(getattr(state_manifest, "archive_walk_complete", False)),
                file_observations=coverage.observations,
                issues=[VerificationIssue(
                    method=self.name,
                    code="info.expected_name_coverage",
                    message="Expected archive names were matched against extraction output",
                    path=evidence.output_dir,
                    expected=len(expected_names),
                    actual=_coverage_actual(coverage, state_manifest, evidence),
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
                "coverage": _coverage_actual(coverage, state_manifest, evidence),
            },
        )
        content_integrity = _content_integrity_hint(state_manifest)
        return VerificationStepResult(
            method=self.name,
            status="warning",
            issues=[issue],
            completeness_hint=coverage.completeness,
            recoverable_upper_bound_hint=coverage.completeness,
            content_integrity_hint=(
                CONTENT_INTEGRITY_VERIFIED_PARTIAL
                if _expected_names_are_strong(evidence, config, content_integrity, state_manifest)
                else content_integrity
            ),
            verification_strength=VERIFICATION_STRENGTH_MANIFEST,
            total_item_count=int(getattr(state_manifest, "item_count", 0) or 0),
            verified_item_count=int(getattr(state_manifest, "verified_item_count", 0) or 0),
            archive_walk_complete=bool(getattr(state_manifest, "archive_walk_complete", False)),
            decision_hint=DECISION_RETRY_EXTRACT if _expected_names_are_strong(evidence, config, content_integrity, state_manifest) else DECISION_NONE,
            file_observations=coverage.observations,
        )

    def _expected_names(
        self,
        evidence: VerificationEvidence,
        config: dict,
        state_manifest: ArchiveStateManifest | None = None,
    ) -> list[str]:
        configured = config.get("expected_names")
        candidates = list(_iter_name_values(configured))
        if not candidates and state_manifest is not None and state_manifest.ok:
            candidates.extend(state_manifest.expected_names)
        if not candidates:
            analysis = _merged_analysis(evidence)
            for field in NAME_FIELDS:
                candidates.extend(_iter_name_values(analysis.get(field)))
        if not candidates:
            candidates.extend(_iter_name_values(knowledge_view.get(evidence.task, "verification.expected_names", [])))

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


def _content_integrity_hint(state_manifest: ArchiveStateManifest | None = None) -> str:
    if state_manifest is None:
        return CONTENT_INTEGRITY_UNKNOWN
    if state_manifest.checksum_error:
        return CONTENT_INTEGRITY_PAYLOAD_DAMAGED
    if state_manifest.archive_walk_complete and state_manifest.verified_item_count >= state_manifest.item_count:
        return CONTENT_INTEGRITY_VERIFIED_COMPLETE
    return CONTENT_INTEGRITY_UNKNOWN


def _expected_names_are_strong(
    evidence: VerificationEvidence,
    config: dict,
    content_integrity: str,
    state_manifest: ArchiveStateManifest | None = None,
) -> bool:
    if config.get("expected_names"):
        return True
    if state_manifest is not None and state_manifest.ok and state_manifest.expected_names:
        return True
    source = str(config.get("expected_names_source") or _merged_analysis(evidence).get("expected_names_source") or "")
    if source in {"user", "central_directory", "manifest"}:
        return True
    return content_integrity == CONTENT_INTEGRITY_VERIFIED_COMPLETE


def _merged_analysis(evidence: VerificationEvidence) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for payload in (evidence.archive_state_analysis, evidence.analysis_facts, evidence.analysis):
        if isinstance(payload, dict):
            merged.update(payload)
    return merged


def _coverage_actual(coverage, state_manifest: ArchiveStateManifest | None, evidence: VerificationEvidence) -> dict[str, Any]:
    actual = coverage_details(coverage)
    actual.update({
        "source_manifest": True,
        "archive_type": state_manifest.archive_type if state_manifest is not None else "",
        "manifest_source": state_manifest.source if state_manifest is not None and state_manifest.ok else "analysis_or_config",
    })
    return actual
