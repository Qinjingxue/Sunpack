"""Embedded discovery admission and residual candidate selection."""

from dataclasses import dataclass
import os
from typing import Any

from sunpack.embedded.scanner import scan_embedded_archives
from sunpack.embedded.options import EmbeddedOptions
from sunpack.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, ArchiveInputRange, ArchiveInputSegment
from sunpack.contracts.discovery import ResolvedArchiveInput, StageResult, candidate_paths
from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.scheduler import DetectionResult
from sunpack_native import inspect_pe_overlay_structure, executable_runtime_bundle_profile


EMBEDDED_SCAN_ALLOWED_FACT = "candidate.embedded_scan_allowed"
DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO = 0.3


@dataclass(frozen=True)
class EmbeddedScanPlan:
    recursive: bool
    allowed_bag_ids: frozenset[int]
    reason: str

    def apply(self, fact_bags: list[FactBag]) -> None:
        for bag in fact_bags:
            bag.set(EMBEDDED_SCAN_ALLOWED_FACT, id(bag) in self.allowed_bag_ids)


class EmbeddedScanGate:
    def __init__(self, config: dict[str, Any], options: EmbeddedOptions | None = None):
        self.config = config
        self.options = options or EmbeddedOptions()

    def plan(self, residual_bags: list[FactBag], *, is_recursive_scan: bool) -> EmbeddedScanPlan:
        embedded_config = self.config.get("embedded_scan")
        if isinstance(embedded_config, dict) and not embedded_config.get("enabled", True):
            return EmbeddedScanPlan(is_recursive_scan, frozenset(), "shared_embedded_scan_disabled")
        if self.options.force_scan or not is_recursive_scan:
            return EmbeddedScanPlan(False, frozenset(map(id, residual_bags)), "initial_scan_all_residuals")
        selected = select_single_candidate_ratio(residual_bags, self._recursive_candidate_ratio())
        return EmbeddedScanPlan(
            True,
            frozenset(map(id, selected)),
            "recursive_candidate_ratio" if selected else "recursive_candidate_ratio_selected_none",
        )

    def _recursive_candidate_ratio(self) -> float:
        embedded = self.config.get("embedded_scan") or {}
        try:
            return min(1.0, max(0.0, float(embedded.get(
                "recursive_candidate_ratio", DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO,
            ))))
        except (TypeError, ValueError):
            return 0.0


class EmbeddedDiscovery:
    """Confirm archive payloads only in unclaimed physical files."""

    def __init__(self, config: dict[str, Any], options: EmbeddedOptions | None = None):
        self.gate = EmbeddedScanGate(config, options)

    def discover(
        self, bags: list[FactBag], *, is_recursive_scan: bool = False,
    ) -> tuple[StageResult, list[DetectionResult]]:
        result = StageResult()
        decisions = []
        self.gate.plan(bags, is_recursive_scan=is_recursive_scan).apply(bags)
        for bag in bags:
            if not bag.get(EMBEDDED_SCAN_ALLOWED_FACT):
                result.residual_paths.update(candidate_paths(bag))
                continue
            decision = self.discover_bag(bag)
            decisions.append(DetectionResult(bag, decision))
            if decision.should_extract:
                result.add_resolved(ResolvedArchiveInput.from_bag(bag, "embedded", {
                    "reason": decision.stop_reason,
                }))
            else:
                result.residual_paths.update(candidate_paths(bag))
        result.validate()
        return result, decisions

    def discover_bag(self, bag: FactBag) -> RuleDecision:
        path = str(bag.get("candidate.entry_path") or "")
        size = bag.get("file.size")
        if not path or not isinstance(size, int) or size <= 0:
            return RuleDecision(False, [], decision="not_archive")
        try:
            overlay = dict(inspect_pe_overlay_structure(path, size, b""))
            if overlay.get("is_pe"):
                bag.set("file.container_type", "pe")
                profile = executable_runtime_bundle_profile(
                    path, 8 * 1024 * 1024, int(overlay.get("overlay_offset") or 0),
                )
                if profile:
                    return RuleDecision(False, [], stop_reason=f"Runtime bundle: {profile}", decision="not_archive")
            scan = scan_embedded_archives(path, expected_size=size)
        except OSError:
            return RuleDecision(False, [], decision="not_archive")
        candidates = [
            item for item in scan.candidates
            if item.candidate_kind == "logical_archive" and item.extractable
        ]
        if not scan.complete or not candidates:
            return RuleDecision(False, [], decision="not_archive")
        candidates.sort(key=lambda item: (item.offset, -item.confidence, item.format))
        primary = candidates[0]
        end = primary.range_end_offset or primary.end_offset
        bag.set("file.detected_ext", primary.detected_ext)
        bag.set("file.probe_detected_archive", True)
        bag.set("file.probe_offset", primary.offset)
        bag.set("file.embedded_archive_found", True)
        bag.set("analysis.signature_prepass", scan.to_prepass())
        bag.set("embedded_archive.analysis", scan.to_dict())
        base_name = str(bag.get("candidate.logical_name") or os.path.basename(path))
        segments = []
        for index, candidate in enumerate(candidates, start=1):
            segment_end = candidate.range_end_offset or candidate.end_offset
            logical_name = f"{base_name}_{index:02d}_{candidate.format}"
            descriptor = _descriptor_for_candidate(
                path, size, candidate.format, candidate.offset, segment_end, logical_name,
            )
            segments.append({
                "segment_id": f"embedded_{index:02d}_{candidate.format.replace('/', '_')}",
                "index": index,
                "format": candidate.format,
                "start_offset": candidate.offset,
                "end_offset": segment_end,
                "confidence": candidate.confidence,
                "damage_flags": [],
                "logical_name": logical_name,
                "segment": candidate.to_dict(),
                "archive_input": descriptor.to_dict(),
            })
        bag.set("archive.input", segments[0]["archive_input"])
        bag.set("source.extractable_segments", segments)
        return RuleDecision(
            True, ["embedded_discovery"],
            stop_reason=f"Validated embedded {primary.format} at offset {primary.offset}",
            decision="archive", decision_stage="embedded", deciding_rule="embedded_discovery",
        )


def select_single_candidate_ratio(fact_bags: list[FactBag], ratio: float) -> list[FactBag]:
    sized = [
        (size, str(bag.get("file.path") or ""), bag)
        for bag in fact_bags
        if (size := logical_candidate_size(bag)) > 0
    ]
    if not sized or ratio <= 0.0:
        return []
    sized.sort(key=lambda item: (-item[0], os.path.normcase(os.path.normpath(item[1]))))
    threshold = sum(size for size, _path, _bag in sized) * min(1.0, ratio)
    return [bag for size, _path, bag in sized if size >= threshold]


def logical_candidate_size(bag: FactBag) -> int:
    paths = bag.get("candidate.member_paths")
    if isinstance(paths, list) and len(paths) > 1:
        total = 0
        seen: set[str] = set()
        for raw_path in paths:
            if not isinstance(raw_path, str) or not raw_path:
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
    size = bag.get("file.size")
    return int(size) if isinstance(size, int) and size > 0 else 0


def _descriptor_for_candidate(
    path: str, size: int, archive_format: str, start: int, end: int | None, logical_name: str,
) -> ArchiveInputDescriptor:
    if start == 0 and (end is None or end >= size):
        return ArchiveInputDescriptor.from_parts(
            archive_path=path, part_paths=[path], format_hint=archive_format,
            logical_name=logical_name,
        )
    archive_range = ArchiveInputRange(path=path, start=start, end=end)
    return ArchiveInputDescriptor(
        entry_path=path, open_mode="file_range", format_hint=archive_format,
        logical_name=logical_name,
        parts=[ArchiveInputPart(path=path, role="main", range=archive_range)],
        segment=ArchiveInputSegment(start=start, end=end, source="embedded"),
    )
