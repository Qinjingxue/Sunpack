"""Embedded archive discovery for physical files left unresolved by earlier stages."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any

from sunpack.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
    ArchiveInputSegment,
)
from sunpack.contracts.discovery import (
    DiscoveryCandidate,
    ResolvedArchiveInput,
    ResolvedArchiveSegment,
    StageResult,
)
from sunpack.analysis.embedded import inspect_runtime_bundle, scan_embedded_archives
from sunpack.embedded.options import EmbeddedOptions


DEFAULT_DEEP_SCAN_SINGLE_CANDIDATE_RATIO = 0.3


@dataclass(frozen=True)
class EmbeddedScanPlan:
    recursive: bool
    allowed_ids: frozenset[int]
    reason: str


class EmbeddedScanGate:
    def __init__(self, config: dict[str, Any], options: EmbeddedOptions | None = None):
        self.config = config
        self.options = options or EmbeddedOptions()

    def plan(
        self,
        candidates: list[DiscoveryCandidate],
        *,
        is_recursive_scan: bool,
    ) -> EmbeddedScanPlan:
        embedded_config = self.config.get("embedded_scan")
        if isinstance(embedded_config, dict) and not embedded_config.get("enabled", True):
            return EmbeddedScanPlan(is_recursive_scan, frozenset(), "shared_embedded_scan_disabled")
        if self.options.force_scan or not is_recursive_scan:
            return EmbeddedScanPlan(False, frozenset(map(id, candidates)), "initial_scan_all_residuals")
        selected = select_single_candidate_ratio(candidates, self._recursive_candidate_ratio())
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
    ) -> StageResult:
        result = StageResult()
        plan = self.gate.plan(candidates, is_recursive_scan=is_recursive_scan)
        for candidate in candidates:
            if id(candidate) not in plan.allowed_ids:
                result.add_residual(
                    candidate,
                    source="embedded",
                    reason=plan.reason,
                )
                continue

            resolved, reason = self._discover_candidate(candidate)
            if resolved is None:
                result.add_residual(candidate, source="embedded", reason=reason)
                continue
            result.add_resolved(resolved, reason=reason)

        result.validate()
        return result

    def _discover_candidate(
        self,
        candidate: DiscoveryCandidate,
    ) -> tuple[ResolvedArchiveInput | None, str]:
        path = candidate.entry_path
        size = candidate.size
        if not path or not isinstance(size, int) or size <= 0:
            return None, "missing_or_empty_file"

        try:
            profile = inspect_runtime_bundle(path, size)
            if profile:
                return None, f"Runtime bundle: {profile}"
            scan = scan_embedded_archives(path, expected_size=size)
        except OSError:
            return None, "embedded_scan_io_error"

        physical = [
            item
            for item in scan.candidates
            if item.candidate_kind == "logical_archive" and item.extractable
        ]
        if not scan.complete or not physical:
            return None, "no_complete_embedded_archive"

        physical.sort(key=lambda item: (item.offset, -item.confidence, item.format))
        segments: list[ResolvedArchiveSegment] = []
        base_name = candidate.logical_name or os.path.basename(path)
        for index, item in enumerate(physical, start=1):
            end = item.range_end_offset or item.end_offset
            logical_name = f"{base_name}_{index:02d}_{item.format}"
            descriptor = _descriptor_for_candidate(
                path,
                size,
                item.format,
                item.offset,
                end,
                logical_name,
            )
            segments.append(ResolvedArchiveSegment(
                archive_input=descriptor,
                format=item.format,
                confidence=float(item.confidence),
                start_offset=int(item.offset),
                end_offset=end,
                evidence=item.to_dict(),
            ))

        primary = segments[0]
        return (
            ResolvedArchiveInput(
                archive_input=primary.archive_input,
                source="embedded",
                carrier_path=candidate.carrier_path,
                cleanup_paths=candidate.cleanup_paths,
                evidence={
                    "scan": scan.to_prepass(),
                    "primary": dict(primary.evidence),
                },
                segments=tuple(segments),
            ),
            f"Validated embedded {primary.format} at offset {primary.start_offset}",
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
