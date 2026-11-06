"""Embedded archive discovery for physical files left unresolved by earlier stages."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from typing import Any

from sunpack.core.support.path_keys import case_key, path_key
from sunpack_native import inspect_pe_image, relations_logical_name

from sunpack.core.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    InputExtent,
)
from sunpack.core.contracts.discovery import (
    DiscoveryCandidate,
    DiscoveryFinding,
    DiscoveryTrace,
    StageResult,
    discovery_failure,
)
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.input_plan import LogicalArchiveInput
from sunpack.core.analysis.embedded import (
    resolve_encrypted_rar_boundaries,
    scan_embedded_archives,
)
from sunpack.core.analysis.embedded.result import (
    embedded_candidate_requires_password,
    embedded_scan_prepass,
)
from sunpack.core.passwords.directory_context import password_scope_for_path
from sunpack.core.passwords.internal.store import PasswordStore
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
        self.password_store = PasswordStore.from_config(config)

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

            self._discover_into(result, candidate)

        result.validate()
        return result

    def discover_native(
        self,
        table,
        routes,
        session,
        *,
        is_recursive_scan: bool = False,
        include_details: bool = True,
    ) -> StageResult:
        embedded_config = self.config.get("embedded_scan") or {}
        ratio = self.gate._recursive_candidate_ratio()
        batch = table.scan_embedded(
            routes,
            recursive=is_recursive_scan,
            force_scan=self.options.force_scan,
            enabled=embedded_config.get("enabled", True),
            recursive_ratio=ratio,
            include_residual_details=include_details,
        )
        result = StageResult()
        for offset in range(0, len(batch), 256):
            for index, status, reason, raw_scan in batch.scan_page(table, offset, 256):
                if status == 3:
                    # Rust retains the verified anchor until all peer residuals
                    # have their normal Embedded ownership decisions.
                    continue
                if status == 2:
                    entry_path, format_hint = table.summary(index)
                    result.blocked_paths.update(table.path_keys(index))
                    result.traces.append(DiscoveryTrace(
                        entry_path=entry_path, source="embedded", status="blocked",
                        format=format_hint, reason=reason, error=raw_scan["error"],
                    ))
                    continue
                if status == 0:
                    entry_path, format_hint = table.summary(index)
                    result.residual_paths.update(table.path_keys(index))
                    result.traces.append(DiscoveryTrace(
                        entry_path=entry_path,
                        source="embedded",
                        status="residual",
                        format=format_hint,
                        reason=reason,
                    ))
                    continue

                candidate = session.project_native_candidate(table, index)
                self._discover_into(result, candidate, raw_scan, include_details=include_details)

        passwords = [
            (path, self._password_candidates(path))
            for path, _offset in batch.encrypted_volume_inputs(table)
        ]
        shared_inputs = False
        for index, status, raw_scan, password in batch.resolve_volumes(table, passwords):
            candidate = session.project_native_candidate(table, index)
            if status == 0:
                shared_inputs = True
                self._discover_into(result, candidate, raw_scan, include_details=include_details)
                continue
            # A directed relation replaces only earlier decisions for its own
            # physical inputs (a continuation may already have been blocked).
            keys = candidate.path_keys
            shared_inputs = (shared_inputs or not keys.isdisjoint(result.claimed_paths)
                             or not keys.isdisjoint(result.blocked_paths))
            result.residual_paths.difference_update(keys)
            result.blocked_paths.difference_update(keys)
            reason = candidate.relation_anchor.get("relation_failure_reason")
            if reason:
                result.add_blocked(candidate, source="relations", reason=str(reason))
            else:
                task = ArchiveTask.from_archive_input(
                    candidate.archive_input, discovery_source="relations",
                    carrier_path=candidate.carrier_path, cleanup_paths=candidate.cleanup_paths,
                    discovery_evidence=candidate.relation_anchor,
                )
                if password is not None:
                    task.set_inputs((replace(task.inputs[0], password=password),))
                result.add_resolved(task, reason="Relations confirmed embedded volume anchor")
        if shared_inputs and len(result.tasks) > 1:
            self._combine_shared_inputs(result)
        result.validate()
        return result

    @staticmethod
    def _combine_shared_inputs(result: StageResult) -> None:
        """One physical owner, independent logical inputs in the existing executor."""
        owners: dict[str, int] = {}
        parents: list[int] = []

        def root(index):
            while parents[index] != index:
                parents[index] = parents[parents[index]]
                index = parents[index]
            return index

        for index, task in enumerate(result.tasks):
            parents.append(index)
            for path in task.cleanup_parts:
                key = path_key(path)
                if key in owners:
                    parents[root(index)] = root(owners[key])
                owners[key] = index
        by_root: dict[int, list[ArchiveTask]] = {}
        for index, task in enumerate(result.tasks):
            by_root.setdefault(root(index), []).append(task)
        combined = []
        for group in by_root.values():
            if len(group) == 1:
                combined.extend(group)
                continue
            primary = next((task for task in group if task.discovery_source == "relations"), group[0])
            segments = []
            cleanup = list(dict.fromkeys(path for task in group for path in task.cleanup_parts))
            for task in group:
                segments.extend(task.inputs)
            segments = list({node.input_id: node for node in segments}.values())
            segments.sort(key=lambda node: (case_key(node.descriptor.entry_path),
                                           node.descriptor.primary_extent.start if node.descriptor.primary_extent else 0))
            task = ArchiveTask.from_archive_input(
                primary.archive_input(), discovery_source="embedded",
                carrier_path=primary.carrier_path, cleanup_paths=cleanup,
                logical_inputs=tuple(replace(node, position=index) for index, node in enumerate(segments, 1)),
            )
            combined.append(task)
            keys = {path_key(path) for path in cleanup}
            result.blocked_paths.difference_update(keys)
            result.residual_paths.difference_update(keys)
            result.claimed_paths.update(keys)
        result.tasks = combined

    def _discover_into(
        self, result: StageResult, candidate: DiscoveryCandidate, precomputed_scan=None,
        *, include_details: bool = True,
    ) -> None:
        try:
            resolved, reason, findings = self._discover_candidate(
                candidate, precomputed_scan=precomputed_scan, include_details=include_details,
            )
        except OSError as exc:
            result.add_blocked(candidate, source="embedded", reason="embedded_scan_io_error", error=str(exc))
            return
        if resolved is not None:
            result.add_resolved(resolved, reason=reason)
        elif reason in {"embedded_password_required", "embedded_wrong_password", "embedded_truncated"}:
            if include_details:
                result.findings.extend(findings)
            result.add_blocked(candidate, source="embedded", reason=reason)
        elif include_details:
            result.add_residual(candidate, source="embedded", reason=reason)

    def _discover_candidate(
        self,
        candidate: DiscoveryCandidate,
        *,
        precomputed_scan=None,
        include_details: bool = True,
    ) -> tuple[ArchiveTask | None, str, tuple[DiscoveryFinding, ...]]:
        path = candidate.entry_path
        if not path:
            return None, "missing_or_empty_file", ()
        if precomputed_scan is None:
            if not self.options.force_scan and inspect_pe_image(path):
                return None, "embedded_executable_skipped", ()
            scan = scan_embedded_archives(path).to_dict()
            size = int(scan["file_size"])
            if size <= 0:
                return None, "missing_or_empty_file", ()
        else:
            scan = precomputed_scan
            size = int(scan["file_size"])

        password_by_offset: dict[int, str] = dict(scan.get("resolved_passwords") or ())
        pending_failures = {item["offset"]: item["discovery_failure_reason"]
                            for item in scan["candidates"] if item.get("discovery_failure_reason")}
        resolved_rows = {}
        encrypted_offsets = [
            item["offset"]
            for item in scan["candidates"]
            if item["candidate_kind"] == "logical_archive"
            and not item.get("volume_candidate")
            and embedded_candidate_requires_password(item["format"], item["validation"])
            and item["end_offset"] is None
            and item["offset"] not in pending_failures
        ]
        if encrypted_offsets:
            passwords = self._password_candidates(path)
            try:
                boundary = resolve_encrypted_rar_boundaries(
                    path,
                    encrypted_offsets,
                    passwords,
                )
            except (RuntimeError, ValueError) as exc:
                raise OSError(str(exc)) from exc
            status = str(boundary.get("status") or "")
            resolved_rows = {
                int(row["offset"]): (int(row["end_offset"]), str(row["password"]))
                for row in boundary.get("resolved") or []
                if isinstance(row, dict)
                and row.get("end_offset") is not None
                and row.get("password") is not None
            }
            blocked_reason = {
                "password_required": "embedded_password_required",
                "wrong_password": "embedded_wrong_password",
                "truncated": "embedded_truncated",
            }.get(status)
            if blocked_reason is not None:
                pending_failures.update((offset, blocked_reason) for offset in encrypted_offsets
                                        if offset not in resolved_rows)
            elif status != "ok":
                raise OSError(str(boundary.get("error") or "Unable to resolve encrypted archive boundary"))
            rewritten = []
            for item in scan["candidates"]:
                resolved = resolved_rows.get(item["offset"])
                if resolved is None:
                    rewritten.append(item)
                    continue
                end_offset, password = resolved
                password_by_offset[item["offset"]] = password
                rewritten.append({
                    **item,
                    "end_offset": end_offset,
                    "validation": f"{item['validation']}_decrypted_end",
                    "boundary_kind": "exact",
                    "extractable": True,
                })
            scan = {
                **scan,
                "candidates": rewritten,
                "logical_resolution_complete": all(
                    item["candidate_kind"] != "logical_archive"
                    or item["boundary_kind"] == "exact"
                    for item in rewritten
                ),
            }

        truncated = next((
            item
            for item in scan["candidates"]
            if item["candidate_kind"] == "logical_archive"
            and not item.get("volume_candidate")
            and item["boundary_kind"] != "exact"
            and item["validation"] == "start_header_crc_truncated_declared_range"
        ), None)
        if not candidate.is_split and truncated is not None:
            return (
                None,
                "embedded_truncated",
                _blocked_findings(
                    path,
                    scan,
                    "embedded_truncated",
                    failed_offset=truncated["offset"],
                ) if include_details else (),
            )

        physical = [
            item
            for item in scan["candidates"]
            if item["candidate_kind"] == "logical_archive"
            and not item.get("volume_candidate")
            and item["boundary_kind"] == "exact"
            and item["extractable"]
            and item["end_offset"] is not None
        ]
        if not scan["complete"] or not physical:
            if pending_failures:
                reason = next(iter(pending_failures.values()))
                return None, reason, _blocked_findings(
                    path, scan, reason, failed_offset=next(iter(pending_failures)),
                    resolved_rows=resolved_rows,
                ) if include_details else ()
            return None, "no_complete_embedded_archive", ()

        physical.sort(key=lambda item: (item["offset"], -item["confidence"], item["format"]))
        segments: list[LogicalArchiveInput] = []
        base_name = candidate.logical_name or relations_logical_name(os.path.basename(path), True)
        logical = physical
        if pending_failures:
            logical = sorted([*physical, *(item for item in scan["candidates"]
                              if item["offset"] in pending_failures)], key=lambda item: item["offset"])
        for item in logical:
            descriptor = _descriptor_for_candidate(
                path,
                size,
                item["format"],
                item["offset"],
                item["end_offset"],
                base_name,
                confidence=float(item["confidence"]),
                password_required=embedded_candidate_requires_password(item["format"], item["validation"]),
                execution_analysis={"stream_plan": item["stream_plan"]} if item.get("stream_plan") else None,
            )
            segments.append(LogicalArchiveInput(
                descriptor, position=len(segments) + 1,
                failure=(discovery_failure("embedded", pending_failures[item["offset"]], path)
                         if item["offset"] in pending_failures else None),
                password=password_by_offset.get(item["offset"]),
            ))

        primary = segments[0].descriptor
        task = ArchiveTask.from_archive_input(
            primary,
            discovery_source="embedded",
            carrier_path=candidate.carrier_path,
            cleanup_paths=candidate.cleanup_paths,
            discovery_evidence={
                "scan": embedded_scan_prepass(scan),
            },
            logical_inputs=tuple(segments),
        )
        return (
            task,
            f"Validated embedded {primary.format_hint} at offset {primary.primary_extent.start if primary.primary_extent else 0}",
            (),
        )

    def _password_candidates(self, path: str) -> list[str]:
        return self.password_store.candidates(password_scope_for_path(self.config, path))


def _blocked_findings(
    path: str,
    scan,
    reason: str,
    *,
    failed_offset: int | None = None,
    resolved_rows: dict[int, tuple[int, str]] | None = None,
) -> tuple[DiscoveryFinding, ...]:
    """Project already-scanned archive identities without creating execution tasks."""

    resolved_rows = resolved_rows or {}
    base_name = relations_logical_name(os.path.basename(path), True)
    findings: list[DiscoveryFinding] = []
    logical = [
        item
        for item in scan["candidates"]
        if item["candidate_kind"] == "logical_archive"
    ]
    for item in logical:
        resolved = resolved_rows.get(item["offset"])
        end_offset = resolved[0] if resolved is not None else item["end_offset"]
        boundary_kind = "exact" if resolved is not None else item["boundary_kind"]
        finding_reason = (
            reason
            if failed_offset is None or int(item["offset"]) == int(failed_offset)
            else "embedded_carrier_blocked"
        )
        findings.append(DiscoveryFinding(
            entry_path=path,
            source="embedded",
            format=item["format"],
            status="blocked",
            reason=finding_reason,
            logical_name=base_name,
            part_paths=(path,),
            offset=int(item["offset"]),
            end_offset=int(end_offset) if end_offset is not None else None,
            boundary_kind=boundary_kind,
            extractable=False,
        ))
    return tuple(findings)


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
    sized.sort(key=lambda item: (-item[0], case_key(os.path.normpath(item[1]))))
    threshold = sum(size for size, _path, _candidate in sized) * min(1.0, ratio)
    return [candidate for size, _path, candidate in sized if size >= threshold]


def logical_candidate_size(candidate: DiscoveryCandidate) -> int:
    size = candidate.logical_size if candidate.is_split else candidate.size
    return int(size) if isinstance(size, int) and size > 0 else 0


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
    execution_analysis: dict[str, Any] | None = None,
) -> ArchiveInputDescriptor:
    analysis = {
        "segment_confidence": confidence,
        "segment_source": "embedded",
        "volume_completeness": "complete" if end is not None else "unknown",
    }
    if execution_analysis:
        analysis.update(execution_analysis)
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
