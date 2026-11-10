"""Embedded archive discovery for physical files left unresolved by earlier stages."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import replace
import os
from typing import Any

from sunpack.core.support.path_keys import case_key, path_key
from sunpack_native import NativeEmbeddedBatch, relations_logical_name, resolve_embedded_rar_boundaries

from sunpack.core.config.fields.embedded import DEFAULT_EMBEDDED_SCAN
from sunpack.core.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    InputExtent,
)
from sunpack.core.contracts.discovery import (
    DiscoveryCandidate,
    StageResult,
    discovery_failure,
)
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.input_plan import LogicalArchiveInput
from sunpack.core.contracts.failures import aggregate_input_failures
from sunpack.core.i18n import I18nContext
from sunpack.core.analysis.embedded.result import (
    embedded_candidate_requires_password,
    embedded_scan_prepass,
)
from sunpack.core.passwords.directory_context import password_scope_for_path
from sunpack.core.passwords.internal.store import PasswordStore
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions


class EmbeddedDiscovery:
    """Confirm archive payloads only in unclaimed physical files."""

    def __init__(self, config: dict[str, Any], options: EmbeddedOptions | None = None):
        self.config = config
        self.options = options or EmbeddedOptions()
        self.password_store = PasswordStore.from_config(config)

    def prepare_native(self, table, routes, *, is_recursive_scan=False):
        embedded_config = self.config.get("embedded_scan") or DEFAULT_EMBEDDED_SCAN
        return table.prepare_embedded(
            routes, recursive=is_recursive_scan, force_scan=self.options.force_scan,
            enabled=embedded_config.get("enabled", DEFAULT_EMBEDDED_SCAN["enabled"]),
            recursive_ratio=embedded_config.get("recursive_candidate_ratio", DEFAULT_EMBEDDED_SCAN["recursive_candidate_ratio"]),
        )

    def discover_many_native(self, scans, session) -> list[StageResult]:
        results = [StageResult() for _ in scans]
        groups, ends = [], []
        total = 0
        for index, (_, batch) in enumerate(scans):
            if count := len(batch):
                total += count
                groups.append(index)
                ends.append(total)
        page_size = 256
        for offset in range(0, total, page_size):
            first = bisect_right(ends, offset)
            last = bisect_left(ends, min(offset + page_size, total), lo=first)
            page_groups = groups[first:last + 1]
            page = [scans[index] for index in page_groups]
            local_offset = offset - (ends[first - 1] if first else 0)
            for group, rows in NativeEmbeddedBatch.scan_pages(page, local_offset, page_size):
                index = page_groups[group]
                self._project_scan_rows(results[index], scans[index][0], rows, session)
        for (table, batch), result in zip(scans, results):
            self._resolve_native_volumes(result, table, batch, session)
        return results

    def _project_scan_rows(self, result, table, rows, session) -> None:
        for index, status, reason, raw_scan in rows:
            if status == 3:
                # Rust retains the verified anchor until all peer residuals
                # have their normal Embedded ownership decisions.
                continue
            if status == 2:
                entry_path, format_hint = table.summary(index)
                if format_hint:
                    candidate = session.project_native_candidate(table, index)
                    result.add_blocked(candidate, source="embedded", reason=reason, error=raw_scan["error"])
                    continue
                result.blocked_paths.update(table.path_keys(index))
                failure = discovery_failure("embedded", reason, entry_path, raw_scan["error"] or "Unable to read archive input")
                if failure is not None:
                    result.scan_failures.append(failure)
                continue

            candidate = session.project_native_candidate(table, index)
            self._discover_into(result, candidate, raw_scan)

    def _resolve_native_volumes(self, result, table, batch, session) -> None:
        passwords = [
            (path, self._password_candidates(path))
            for path in batch.encrypted_volume_paths(table)
        ]
        shared_inputs = False
        for index, status, raw_scan, password in batch.resolve_volumes(table, passwords):
            candidate = session.project_native_candidate(table, index)
            if status == 0:
                shared_inputs = True
                self._discover_into(result, candidate, raw_scan)
                continue
            # A directed relation replaces only earlier decisions for its own
            # physical inputs (a continuation may already have been blocked).
            keys = candidate.path_keys
            shared_inputs = (shared_inputs or not keys.isdisjoint(result.claimed_paths)
                             or not keys.isdisjoint(result.blocked_paths))
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
                result.add_resolved(task)
        if shared_inputs and len(result.tasks) > 1:
            self._combine_shared_inputs(result)
        result.validate()

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
            result.claimed_paths.update(keys)
        result.tasks = combined

    def _discover_into(
        self, result: StageResult, candidate: DiscoveryCandidate, scan,
    ) -> None:
        try:
            resolved = self._discover_candidate(candidate, scan)
        except OSError as exc:
            result.add_blocked(candidate, source="embedded", reason="embedded_scan_io_error", error=str(exc))
            return
        if resolved is not None:
            if resolved.discovery_failure is not None:
                result.tasks.append(resolved)
                result.blocked_paths.update(candidate.path_keys)
            else:
                result.add_resolved(resolved)

    def _discover_candidate(
        self,
        candidate: DiscoveryCandidate,
        scan,
    ) -> ArchiveTask | None:
        path = candidate.entry_path
        if not path:
            return None
        size = int(scan["file_size"])

        password_by_offset: dict[int, str] = dict(scan.get("resolved_passwords") or ())
        pending_failures = {item["offset"]: item["discovery_failure_reason"]
                            for item in scan["candidates"] if item.get("discovery_failure_reason")}
        boundary_errors = {}
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
                boundary = resolve_embedded_rar_boundaries(
                    path,
                    encrypted_offsets,
                    passwords,
                )
            except (OSError, RuntimeError, ValueError) as exc:
                error = str(exc)
                boundary = ({"offset": offset, "status": "error", "error": error}
                            for offset in encrypted_offsets)
            resolved_rows = {}
            for row in boundary:
                offset = row["offset"]
                status = row["status"]
                if row.get("password") is not None:
                    password_by_offset[offset] = row["password"]
                if status == "ok" and row.get("end_offset") is not None:
                    resolved_rows[offset] = row["end_offset"]
                    continue
                reason = {
                    "password_required": "embedded_password_required",
                    "wrong_password": "embedded_wrong_password",
                    "truncated": "embedded_truncated",
                }.get(status, "embedded_scan_io_error")
                pending_failures[offset] = reason
                if reason == "embedded_scan_io_error":
                    boundary_errors[offset] = row.get("error") or "Unable to resolve encrypted archive boundary"
            rewritten = []
            for item in scan["candidates"]:
                resolved = resolved_rows.get(item["offset"])
                if resolved is None:
                    rewritten.append(item)
                    continue
                end_offset = resolved
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

        if not candidate.is_split:
            pending_failures.update((item["offset"], "embedded_truncated")
                for item in scan["candidates"]
                if item["candidate_kind"] == "logical_archive"
                and not item.get("volume_candidate")
                and item["boundary_kind"] != "exact"
                and item["validation"] == "start_header_crc_truncated_declared_range")

        physical = [
            item
            for item in scan["candidates"]
            if item["candidate_kind"] == "logical_archive"
            and not item.get("volume_candidate")
            and item["boundary_kind"] == "exact"
            and item["extractable"]
            and item["offset"] not in pending_failures
            and item["end_offset"] is not None
        ]
        if not physical and not pending_failures:
            return None

        physical.sort(key=lambda item: (item["offset"], item["format"]))
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
                password_required=embedded_candidate_requires_password(item["format"], item["validation"]),
                execution_analysis={"stream_plan": item["stream_plan"]} if item.get("stream_plan") else None,
            )
            segments.append(LogicalArchiveInput(
                descriptor, position=len(segments) + 1,
                failure=(discovery_failure("embedded", pending_failures[item["offset"]], path,
                                          boundary_errors.get(item["offset"], ""))
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
        if pending_failures:
            failures = [node.failure for node in segments if node.failure is not None]
            if len(failures) == len(segments):
                task.discovery_failure = failures[0] if len(failures) == 1 else aggregate_input_failures(
                    failures, segment_count=len(segments), i18n=I18nContext(self.config.get("cli", {}).get("language")),
                )
        return task

    def _password_candidates(self, path: str) -> list[str]:
        return self.password_store.candidates(password_scope_for_path(self.config, path))


def _descriptor_for_candidate(
    path: str,
    size: int,
    archive_format: str,
    start: int,
    end: int | None,
    logical_name: str,
    *,
    password_required: bool = False,
    execution_analysis: dict[str, Any] | None = None,
) -> ArchiveInputDescriptor:
    analysis = {
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
