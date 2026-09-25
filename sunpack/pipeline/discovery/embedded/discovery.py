"""Embedded archive discovery for physical files left unresolved by earlier stages."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from typing import Any

from sunpack.core.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    InputExtent,
)
from sunpack.core.contracts.discovery import (
    DiscoveryCandidate,
    StageResult,
)
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.analysis.embedded import (
    inspect_runtime_bundle,
    resolve_encrypted_rar_boundaries,
    scan_embedded_archives,
)
from sunpack.core.passwords.internal.lists import dedupe_passwords
from sunpack.core.passwords.internal.local_files import discover_directory_passwords_for_archive
from sunpack.core.support.global_cache_manager import file_identity
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions


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
        self.config = config
        self.options = options or EmbeddedOptions()
        self.gate = EmbeddedScanGate(config, self.options)

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
                if reason in {
                    "embedded_password_required",
                    "embedded_wrong_password",
                    "embedded_truncated",
                }:
                    result.add_blocked(candidate, source="embedded", reason=reason)
                else:
                    result.add_residual(candidate, source="embedded", reason=reason)
                continue
            result.add_resolved(resolved, reason=reason)

        result.validate()
        return result

    def _discover_candidate(
        self,
        candidate: DiscoveryCandidate,
    ) -> tuple[ArchiveTask | None, str]:
        path = candidate.entry_path
        if not path:
            return None, "missing_or_empty_file"

        try:
            identity = file_identity(path)
            size = int(identity[1])
            if size <= 0:
                return None, "missing_or_empty_file"
            if not self.options.force_scan:
                profile = inspect_runtime_bundle(path, size)
                if profile:
                    return None, f"Runtime bundle: {profile}"
            scan = scan_embedded_archives(
                path,
                expected_size=size,
                identity=identity,
            )
        except OSError:
            return None, "embedded_scan_io_error"

        password_by_offset: dict[int, str] = {}
        encrypted_offsets = [
            item.offset
            for item in scan.candidates
            if item.candidate_kind == "logical_archive"
            and item.password_required
            and item.end_offset is None
        ]
        if encrypted_offsets:
            passwords = self._password_candidates(path)
            try:
                boundary = resolve_encrypted_rar_boundaries(
                    path,
                    encrypted_offsets,
                    passwords,
                )
            except (OSError, RuntimeError, ValueError):
                return None, "embedded_scan_io_error"
            status = str(boundary.get("status") or "")
            if status == "password_required":
                return None, "embedded_password_required"
            if status == "wrong_password":
                return None, "embedded_wrong_password"
            if status == "truncated":
                return None, "embedded_truncated"
            if status != "ok":
                return None, "embedded_scan_io_error"

            resolved_rows = {
                int(row["offset"]): (int(row["end_offset"]), str(row["password"]))
                for row in boundary.get("resolved") or []
                if isinstance(row, dict)
                and row.get("end_offset") is not None
                and row.get("password") is not None
            }
            rewritten = []
            for item in scan.candidates:
                resolved = resolved_rows.get(item.offset)
                if resolved is None:
                    rewritten.append(item)
                    continue
                end_offset, password = resolved
                password_by_offset[item.offset] = password
                rewritten.append(replace(
                    item,
                    end_offset=end_offset,
                    validation=f"{item.validation}_decrypted_end",
                    boundary_kind="exact",
                    extractable=True,
                ))
            scan = replace(
                scan,
                candidates=tuple(rewritten),
                logical_resolution_complete=all(
                    item.candidate_kind != "logical_archive"
                    or item.boundary_kind == "exact"
                    for item in rewritten
                ),
            )

        if not candidate.is_split and any(
            item.candidate_kind == "logical_archive"
            and item.boundary_kind != "exact"
            and item.validation == "start_header_crc_truncated_declared_range"
            for item in scan.candidates
        ):
            return None, "embedded_truncated"

        physical = [
            item
            for item in scan.candidates
            if item.candidate_kind == "logical_archive"
            and item.boundary_kind == "exact"
            and item.extractable
            and item.end_offset is not None
        ]
        if not scan.complete or not physical:
            return None, "no_complete_embedded_archive"

        physical.sort(key=lambda item: (item.offset, -item.confidence, item.format))
        segments: list[tuple[ArchiveInputDescriptor, dict[str, Any]]] = []
        base_name = candidate.logical_name or os.path.basename(path)
        for index, item in enumerate(physical, start=1):
            logical_name = f"{base_name}_{index:02d}_{item.format}"
            descriptor = _descriptor_for_candidate(
                path,
                size,
                item.format,
                item.offset,
                item.end_offset,
                logical_name,
                confidence=float(item.confidence),
                password_required=item.password_required,
            )
            segments.append((descriptor, item.to_dict()))

        primary = segments[0][0]
        task = ArchiveTask.from_archive_input(
            primary,
            discovery_source="embedded",
            carrier_path=candidate.carrier_path,
            cleanup_paths=candidate.cleanup_paths,
            discovery_evidence={
                "scan": scan.to_prepass(),
            },
            discovery_segments=tuple(segments),
        )
        if password_by_offset:
            task.runtime["embedded_segment_passwords"] = {
                str(offset): password
                for offset, password in password_by_offset.items()
            }
        return (
            task,
            f"Validated embedded {primary.format_hint} at offset {primary.primary_extent.start if primary.primary_extent else 0}",
        )

    def _password_candidates(self, path: str) -> list[str]:
        return dedupe_passwords([
            *discover_directory_passwords_for_archive(path, self.config),
            *list(self.config.get("user_passwords") or []),
            *list(self.config.get("builtin_passwords") or []),
        ])


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
    part_paths = candidate.archive_input.part_paths()
    if len(part_paths) > 1:
        total = 0
        seen: set[str] = set()
        for raw_path in part_paths:
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
    *,
    confidence: float,
    password_required: bool = False,
) -> ArchiveInputDescriptor:
    analysis = {
        "segment_confidence": confidence,
        "segment_source": "embedded",
    }
    if password_required:
        analysis["password_required"] = True
    if start == 0 and (end is None or end >= size):
        return ArchiveInputDescriptor(
            entry_path=path,
            format_hint=archive_format,
            logical_name=logical_name,
            parts=[ArchiveInputPart(extent=InputExtent(path=path), role="main", volume_number=1)],
            analysis=analysis,
        )
    extent = InputExtent(path=path, start=start, end=end)
    return ArchiveInputDescriptor(
        entry_path=path,
        open_mode="file_range",
        format_hint=archive_format,
        logical_name=logical_name,
        parts=[ArchiveInputPart(extent=extent, role="main")],
        analysis=analysis,
    )
