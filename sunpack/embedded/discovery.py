"""Embedded discovery admission and residual candidate selection."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any

from sunpack.embedded.scanner import scan_embedded_archives
from sunpack.embedded.options import EmbeddedOptions
from sunpack.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
    ArchiveInputSegment,
)
from sunpack.contracts.discovery import (
    DiscoveryCandidate,
    ResolvedArchiveInput,
    StageResult,
    candidate_paths,
)
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.scheduler import DetectionResult
from sunpack_native import inspect_pe_overlay_structure, executable_runtime_bundle_profile


DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO = 0.3


@dataclass(frozen=True)
class EmbeddedScanPlan:
    recursive: bool
    allowed_candidate_ids: frozenset[int]
    reason: str

    def allows(self, candidate: DiscoveryCandidate) -> bool:
        return id(candidate) in self.allowed_candidate_ids


class EmbeddedScanGate:
    def __init__(self, config: dict[str, Any], options: EmbeddedOptions | None = None):
        self.config = config
        self.options = options or EmbeddedOptions()

    def plan(
        self,
        residual_candidates: list[DiscoveryCandidate],
        *,
        is_recursive_scan: bool,
    ) -> EmbeddedScanPlan:
        embedded_config = self.config.get("embedded_scan")
        if isinstance(embedded_config, dict) and not embedded_config.get("enabled", True):
            return EmbeddedScanPlan(is_recursive_scan, frozenset(), "shared_embedded_scan_disabled")
        if self.options.force_scan or not is_recursive_scan:
            return EmbeddedScanPlan(
                False,
                frozenset(map(id, residual_candidates)),
                "initial_scan_all_residuals",
            )
        selected = select_single_candidate_ratio(
            residual_candidates,
            self._recursive_candidate_ratio(),
        )
        return EmbeddedScanPlan(
            True,
            frozenset(map(id, selected)),
            "recursive_candidate_ratio" if selected else "recursive_candidate_ratio_selected_none",
        )

    def _recursive_candidate_ratio(self) -> float:
        embedded = self.config.get("embedded_scan") or {}
        try:
            return min(1.0, max(0.0, float(embedded.get(
                "recursive_candidate_ratio",
                DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO,
            ))))
        except (TypeError, ValueError):
            return 0.0


class EmbeddedDiscovery:
    """Confirm archive payloads only in unclaimed physical files."""

    def __init__(self, config: dict[str, Any], options: EmbeddedOptions | None = None):
        self.gate = EmbeddedScanGate(config, options)

    def discover(
        self,
        candidates: list[DiscoveryCandidate],
        *,
        is_recursive_scan: bool = False,
    ) -> tuple[StageResult, list[DetectionResult]]:
        result = StageResult()
        decisions: list[DetectionResult] = []
        plan = self.gate.plan(candidates, is_recursive_scan=is_recursive_scan)
        for candidate in candidates:
            if not plan.allows(candidate):
                result.residual_paths.update(candidate_paths(candidate))
                continue
            decision, resolved = self.discover_candidate(candidate)
            decisions.append(DetectionResult(
                candidate,
                decision,
                resolved.format if resolved is not None else "",
            ))
            if resolved is not None:
                result.add_resolved(resolved)
            else:
                result.residual_paths.update(candidate_paths(candidate))
        result.validate()
        return result, decisions

    def discover_candidate(
        self,
        candidate: DiscoveryCandidate,
    ) -> tuple[RuleDecision, ResolvedArchiveInput | None]:
        path = candidate.entry_path
        size = candidate.size
        if not path or not isinstance(size, int) or size <= 0:
            return RuleDecision(False, [], decision="not_archive"), None
        try:
            overlay = dict(inspect_pe_overlay_structure(path, size, b""))
            if overlay.get("is_pe"):
                profile = executable_runtime_bundle_profile(
                    path,
                    8 * 1024 * 1024,
                    int(overlay.get("overlay_offset") or 0),
                )
                if profile:
                    return (
                        RuleDecision(
                            False,
                            [],
                            stop_reason=f"Runtime bundle: {profile}",
                            decision="not_archive",
                        ),
                        None,
                    )
            scan = scan_embedded_archives(path, expected_size=size)
        except OSError:
            return RuleDecision(False, [], decision="not_archive"), None

        archive_candidates = [
            item
            for item in scan.candidates
            if item.candidate_kind == "logical_archive" and item.extractable
        ]
        if not scan.complete or not archive_candidates:
            return RuleDecision(False, [], decision="not_archive"), None

        archive_candidates.sort(key=lambda item: (item.offset, -item.confidence, item.format))
        primary = archive_candidates[0]
        base_name = candidate.logical_name or os.path.basename(path)
        segments: list[dict] = []
        for index, item in enumerate(archive_candidates, start=1):
            segment_end = item.range_end_offset or item.end_offset
            logical_name = f"{base_name}_{index:02d}_{item.format}"
            descriptor = _descriptor_for_candidate(
                path,
                size,
                item.format,
                item.offset,
                segment_end,
                logical_name,
            )
            segments.append({
                "segment_id": f"embedded_{index:02d}_{item.format.replace('/', '_')}",
                "index": index,
                "format": item.format,
                "start_offset": item.offset,
                "end_offset": segment_end,
                "confidence": item.confidence,
                "damage_flags": [],
                "logical_name": logical_name,
                "segment": item.to_dict(),
                "archive_input": descriptor.to_dict(),
            })

        primary_descriptor = ArchiveInputDescriptor.from_dict(
            segments[0]["archive_input"],
            archive_path=path,
        )
        reason = f"Validated embedded {primary.format} at offset {primary.offset}"
        resolved = ResolvedArchiveInput.from_candidate(
            candidate,
            "embedded",
            {
                "reason": reason,
                "scan": scan.to_dict(),
                "primary": primary.to_dict(),
            },
            archive_input=primary_descriptor,
            confidence=float(primary.confidence),
            reasons=(reason,),
            extractable_segments=segments,
        )
        return (
            RuleDecision(
                True,
                ["embedded_discovery"],
                stop_reason=reason,
                decision="archive",
                decision_stage="embedded",
                deciding_rule="embedded_discovery",
            ),
            resolved,
        )


def select_single_candidate_ratio(
    candidates: list[DiscoveryCandidate],
    ratio: float,
) -> list[DiscoveryCandidate]:
    sized = [
        (size, candidate.entry_path, candidate)
        for candidate in candidates
        if (size := logical_candidate_size(candidate)) > 0
    ]
    if not sized or ratio <= 0.0:
        return []
    sized.sort(key=lambda item: (-item[0], os.path.normcase(os.path.normpath(item[1]))))
    threshold = sum(size for size, _path, _candidate in sized) * min(1.0, ratio)
    return [candidate for size, _path, candidate in sized if size >= threshold]


def logical_candidate_size(candidate: DiscoveryCandidate) -> int:
    if len(candidate.member_paths) > 1:
        total = 0
        seen: set[str] = set()
        for raw_path in candidate.member_paths:
            if not raw_path:
                continue
            normalized = os.path.normcase(os.path.normpath(raw_path))
            if normalized in seen:
                continue
            seen.add(normalized)
            try:
                total += os.path.getsize(raw_path)
            except OSError:
                continue
        if total > 0:
            return total
    return int(candidate.size) if isinstance(candidate.size, int) and candidate.size > 0 else 0


def _descriptor_for_candidate(
    path: str,
    size: int,
    archive_format: str,
    start: int,
    end: int | None,
    logical_name: str,
) -> ArchiveInputDescriptor:
    if start == 0 and (end is None or end >= size):
        return ArchiveInputDescriptor.from_parts(
            archive_path=path,
            part_paths=[path],
            format_hint=archive_format,
            logical_name=logical_name,
        )
    archive_range = ArchiveInputRange(path=path, start=start, end=end)
    return ArchiveInputDescriptor(
        entry_path=path,
        open_mode="file_range",
        format_hint=archive_format,
        logical_name=logical_name,
        parts=[ArchiveInputPart(path=path, role="main", range=archive_range)],
        segment=ArchiveInputSegment(start=start, end=end, source="embedded"),
    )
