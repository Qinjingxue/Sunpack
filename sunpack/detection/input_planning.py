import json
import os
import threading
from contextlib import nullcontext
from dataclasses import asdict, replace
from typing import Any, Callable

from sunpack.analysis import ArchiveAnalysisReport, ArchiveAnalyzer
from sunpack.analysis.request import AnalysisRequest
from sunpack.coordinator.nested_extraction_policy import EMBEDDED_SCAN_ALLOWED_FACT
from sunpack.analysis.source import analysis_source_for_descriptor
from sunpack.support.archive_input_projection import (
    write_source_extractable_segments,
    write_source_password_probe_input,
    write_source_selected_segment,
)
from sunpack.support.archive_knowledge_writer import (
    commit_task_knowledge,
    ensure_knowledge,
    write_payload,
)
from sunpack.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
    ArchiveInputSegment,
)
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.tasks import ArchiveTask
from sunpack.support import archive_knowledge_projection as knowledge_view


class ArchiveInputPlanningStage:
    """Turn neutral Analysis reports into main-flow archive inputs."""
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        module_executor_pool=None,
    ):
        self.config = config or {}
        planning_config = self.config.get("input_planning") if isinstance(self.config.get("input_planning"), dict) else {}
        self.enabled = bool(planning_config.get("enabled", True))
        self._report_cache: dict[tuple, ArchiveAnalysisReport] = {}
        self._report_cache_lock = threading.Lock()
        self.analyzer = (
            ArchiveAnalyzer(self.config, executor_pool=module_executor_pool)
            if self.enabled
            else None
        )

    def plan_tasks(self, tasks: list[ArchiveTask]) -> list[ArchiveTask]:
        if not self.enabled or self.analyzer is None:
            return tasks
        groups = self._planning_task_groups(tasks)
        expanded_tasks: list[ArchiveTask] = []
        for group in groups:
            for _index, task_results in self._plan_task_group(group):
                expanded_tasks.extend(task_results)
        return expanded_tasks

    def _remember_report(self, cache_key: tuple, report: ArchiveAnalysisReport) -> None:
        planning_config = self.config.get("input_planning") if isinstance(self.config.get("input_planning"), dict) else {}
        limit = max(0, int(planning_config.get("cache_size", 512) or 512))
        if limit <= 0:
            return
        with self._report_cache_lock:
            if len(self._report_cache) >= limit:
                self._report_cache.pop(next(iter(self._report_cache)))
            self._report_cache[cache_key] = report

    def remember_report(self, task: ArchiveTask, report: ArchiveAnalysisReport) -> None:
        """Seed the shared cache with a coordinator-produced analysis report."""
        self._remember_report(self._report_cache_key(task), report)

    def clear_report_cache(self) -> None:
        """Release archive-specific reports after a completed request group."""
        with self._report_cache_lock:
            self._report_cache.clear()

    def _report_cache_key(self, task: ArchiveTask) -> tuple:
        return (
            "source",
            json.dumps(knowledge_view.source_fingerprint(task), ensure_ascii=False, sort_keys=True, default=str),
            "embedded_scan_allowed",
            bool(task.fact_bag.get(EMBEDDED_SCAN_ALLOWED_FACT)),
        )

    @staticmethod
    def _path_cache_fingerprint(path: str) -> tuple:
        normalized = os.path.abspath(os.path.normpath(path))
        try:
            stat = os.stat(normalized)
            return (normalized, int(stat.st_size), int(stat.st_mtime_ns))
        except OSError:
            return (normalized, -1, -1)

    def _planning_task_groups(self, tasks: list[ArchiveTask]) -> list[list[tuple[int, ArchiveTask]]]:
        grouped: dict[tuple, list[tuple[int, ArchiveTask]]] = {}
        order: list[tuple] = []
        for index, task in enumerate(tasks):
            try:
                task.ensure_archive_state()
                cache_key = self._report_cache_key(task)
            except Exception:
                cache_key = ("task", id(task))
            if cache_key not in grouped:
                grouped[cache_key] = []
                order.append(cache_key)
            grouped[cache_key].append((index, task))
        return [grouped[key] for key in order]

    def _plan_task_group(self, group: list[tuple[int, ArchiveTask]]) -> list[tuple[int, list[ArchiveTask]]]:
        if not group:
            return []
        if len(group) == 1:
            index, task = group[0]
            _, task_results = self._plan_task_to_tasks(task)
            return [(index, task_results)]
        first_index, first_task = group[0]
        report, first_results = self._plan_task_to_tasks(first_task)
        results = [(first_index, first_results)]
        if report is None:
            for index, task in group[1:]:
                task.fact_bag.set("input_planning.status", "error")
                results.append((index, [task]))
            return results
        for index, task in group[1:]:
            task_report = replace(report, cache_hits=report.cache_hits + 1)
            results.append((index, self._tasks_from_report(task, task_report)))
        return results

    def plan_task(self, task: ArchiveTask) -> ArchiveAnalysisReport | None:
        report, _ = self._plan_task_to_tasks(task)
        return report

    def plan_task_to_tasks(self, task: ArchiveTask) -> list[ArchiveTask]:
        _, tasks = self._plan_task_to_tasks(task)
        return tasks

    def _plan_task_to_tasks(self, task: ArchiveTask) -> tuple[ArchiveAnalysisReport | None, list[ArchiveTask]]:
        if self.analyzer is None:
            return None, [task]
        task.ensure_archive_state()
        try:
            report = self._get_or_create_report(task)
        except Exception as exc:
            task.fact_bag.set("input_planning.status", "error")
            task.fact_bag.set("input_planning.error", str(exc))
            _write_plan_error(task, str(exc))
            return None, [task]

        return report, self._tasks_from_report(task, report)

    def _get_or_create_report(self, task: ArchiveTask, *, phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "input_planning") -> ArchiveAnalysisReport:
        with _phase(phase_timer, f"{phase_prefix}_cache_key"):
            cache_key = self._report_cache_key(task)
        with _phase(phase_timer, f"{phase_prefix}_cache_lookup"):
            with self._report_cache_lock:
                report = self._report_cache.get(cache_key)
        if report is None:
            with _phase(phase_timer, f"{phase_prefix}_analyze_source"):
                report = self._analyze_task(task)
            with _phase(phase_timer, f"{phase_prefix}_remember_report"):
                self._remember_report(cache_key, report)
            return report
        return replace(report, cache_hits=report.cache_hits + 1)

    def _analyze_task(self, task: ArchiveTask) -> ArchiveAnalysisReport:
        state = task.archive_state()
        source = analysis_source_for_descriptor(
            state.to_archive_input_descriptor(),
            report_path=task.main_path,
        )
        prepass = task.fact_bag.get("analysis.signature_prepass")
        initial_prepass = (
            dict(prepass)
            if isinstance(prepass, dict) and prepass.get("full_scan_complete")
            else None
        )
        return self.analyzer.analyze(
            source,
            AnalysisRequest(
                initial_prepass=initial_prepass,
                embedded_scan_allowed=bool(task.fact_bag.get(EMBEDDED_SCAN_ALLOWED_FACT)),
            ),
        )

    def _tasks_from_report(self, task: ArchiveTask, report: ArchiveAnalysisReport, *, phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "input_planning") -> list[ArchiveTask]:
        with _phase(phase_timer, f"{phase_prefix}_record_report"):
            self._record_report(task, report, phase_timer=phase_timer, phase_prefix=phase_prefix, record_state=False, write_knowledge=False)
        with _phase(phase_timer, f"{phase_prefix}_set_report_path"):
            task.fact_bag.set("input_planning.report_path", report.path)
        with _phase(phase_timer, f"{phase_prefix}_extractable_segments"):
            candidates = self._extractable_segments(report)
        with _phase(phase_timer, f"{phase_prefix}_write_segments_build_payload"):
            segment_payloads = self._extractable_segment_payloads(task, candidates)
        selected_segment = None
        if not candidates:
            password_candidate = self._password_required_embedded_segment(report)
            if password_candidate is not None:
                evidence, segment, index = password_candidate
                selected_segment = (evidence, segment, index)
                with _phase(phase_timer, f"{phase_prefix}_write_segments_build_payload"):
                    segment_payloads = self._extractable_segment_payloads(task, [(evidence, segment, index)])
                with _phase(phase_timer, f"{phase_prefix}_apply_selected_segment"):
                    self._apply_selected_segment(task, evidence, segment, index=index, write_knowledge=False)
            with _phase(phase_timer, f"{phase_prefix}_batched_write"):
                password_probe_input = (
                    self._password_probe_input_for_segment(task, *selected_segment)
                    if selected_segment is not None
                    else self._structured_volume_source(task)
                )
                _write_plan_knowledge(
                    task,
                    report,
                    segment_payloads,
                    selected_segment,
                    password_probe_input,
                )
            with _phase(phase_timer, f"{phase_prefix}_state_update"):
                self._record_planning_state(task, report, phase_timer=phase_timer, phase_prefix=phase_prefix)
            return [task]
        evidence, segment, index = candidates[0]
        selected_segment = (evidence, segment, index)
        with _phase(phase_timer, f"{phase_prefix}_apply_selected_segment"):
            self._apply_selected_segment(task, evidence, segment, index=index, write_knowledge=False)
        with _phase(phase_timer, f"{phase_prefix}_batched_write"):
            password_probe_input = self._password_probe_input_for_segment(
                task,
                evidence,
                segment,
                index,
            )
            _write_plan_knowledge(
                task,
                report,
                segment_payloads,
                selected_segment,
                password_probe_input,
            )
        with _phase(phase_timer, f"{phase_prefix}_state_update"):
            self._record_planning_state(task, report, phase_timer=phase_timer, phase_prefix=phase_prefix)
        return [task]

    @staticmethod
    def _structured_volume_source(task: ArchiveTask) -> ArchiveInputDescriptor | None:
        split_info = getattr(task, "split_info", None)
        source_input = getattr(split_info, "archive_input", None)
        if isinstance(source_input, ArchiveInputDescriptor) and len(source_input.parts) > 1:
            return source_input
        return None

    def _apply_selected_segment(
        self,
        task: ArchiveTask,
        evidence: ArchiveFormatEvidence,
        segment: ArchiveSegment,
        *,
        index: int,
        write_knowledge: bool = True,
    ) -> None:
        segment_payload = self._segment_payload(task, evidence, segment)
        task.fact_bag.set("input_planning.status", evidence.status)
        task.fact_bag.set("archive.format_hint", evidence.format)
        task.fact_bag.set("source.segment_index", index)
        task.fact_bag.set("source.segment", segment_payload)
        if write_knowledge:
            write_source_selected_segment(task, evidence, segment, index=index)

    def _record_report(
        self,
        task: ArchiveTask,
        report: ArchiveAnalysisReport,
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "input_planning",
        record_state: bool = True,
        write_knowledge: bool = True,
    ) -> None:
        selected = _best_selected(report)
        with _phase(phase_timer, f"{phase_prefix}_record_report_fact_bag_basic"):
            task.fact_bag.set("input_planning.status", "extractable" if report.has_extractable else "not_extractable")
            task.fact_bag.set("input_planning.read_bytes", report.read_bytes)
            task.fact_bag.set("input_planning.cache_hits", report.cache_hits)
            if selected is not None:
                task.fact_bag.set("archive.format_hint", selected.format)
                task.fact_bag.set("input_planning.confidence", float(selected.confidence or 0.0))
        with _phase(phase_timer, f"{phase_prefix}_record_report_evidence_payload"):
            evidences = [
                {
                    "format": evidence.format,
                    "confidence": evidence.confidence,
                    "status": evidence.status,
                    "warnings": list(evidence.warnings),
                    "details": dict(evidence.details),
                    "segments": [asdict(segment) for segment in evidence.segments],
                }
                for evidence in report.evidences
            ]
        with _phase(phase_timer, f"{phase_prefix}_record_report_fact_bag_evidences"):
            task.fact_bag.set("input_planning.evidences", evidences)
        if write_knowledge:
            with _phase(phase_timer, f"{phase_prefix}_record_report_write_knowledge"):
                _write_plan_knowledge(task, report, [], None)
        if record_state:
            with _phase(phase_timer, f"{phase_prefix}_record_report_state_analysis"):
                self._record_planning_state(task, report, phase_timer=phase_timer, phase_prefix=phase_prefix)

    def _record_planning_state(self, task: ArchiveTask, report: ArchiveAnalysisReport, *, phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "input_planning") -> None:
        with _phase(phase_timer, f"{phase_prefix}_record_state_get_archive_state"):
            state = task.archive_state()
        with _phase(phase_timer, f"{phase_prefix}_record_state_build_payload"):
            selected = _best_selected(report)
            analysis = {
                "status": "extractable" if report.has_extractable else "not_extractable",
                "report_path": report.path,
                "read_bytes": report.read_bytes,
                "cache_hits": report.cache_hits,
            }
            if selected is not None:
                analysis.update({
                    "selected_format": selected.format,
                    "confidence": float(selected.confidence),
                })
            selected_format = str(getattr(selected, "format", "") or "")
            source = replace(state.source, format_hint=selected_format) if selected_format else state.source
            new_state = ArchiveState(
                source=source,
                logical_name=state.logical_name,
                format_hint=selected_format or state.format_hint,
                analysis=analysis,
                verification=dict(state.verification),
            )
        with _phase(phase_timer, f"{phase_prefix}_record_state_set_archive_state"):
            if dict(state.analysis) != analysis:
                task.set_archive_state(
                    new_state,
                    phase_timer=phase_timer,
                    phase_prefix=f"{phase_prefix}_record_state_set_archive_state",
                )

    def _extractable_segments(self, report: ArchiveAnalysisReport) -> list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]]:
        if _is_damaged_native_archive_fallback(report):
            # The embedded scanner also acts as a last-resort ZIP local-header
            # scanner. For a native archive, those ranges are malformed
            # fragments, not independent embedded archives.
            return []
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]] = []
        index = 1
        for evidence in sorted(report.selected, key=lambda item: item.confidence, reverse=True):
            for segment in evidence.segments:
                if segment.end_offset is None:
                    continue
                if int(segment.start_offset) <= 0 and str(getattr(segment, "role", "") or "primary") == "primary":
                    continue
                candidates.append((evidence, segment, index))
                index += 1
        candidates.sort(key=lambda item: (int(item[1].start_offset), item[0].format, item[2]))
        candidates = self._prefer_specific_segments(candidates)
        candidates = self._suppress_segments_covered_by_whole_composite(report, candidates)
        return [
            (evidence, segment, position)
            for position, (evidence, segment, _) in enumerate(candidates, start=1)
        ]

    def _suppress_segments_covered_by_whole_composite(
        self,
        report: ArchiveAnalysisReport,
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]],
    ) -> list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]]:
        whole_composites = _whole_file_composite_segments(report)
        if not whole_composites:
            return candidates
        filtered = []
        for evidence, segment, index in candidates:
            if any(_segment_is_shadowed_by_composite(evidence, segment, composite) for composite in whole_composites):
                continue
            filtered.append((evidence, segment, index))
        return filtered

    def _write_extractable_segments(
        self,
        task: ArchiveTask,
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]],
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "input_planning",
    ) -> None:
        with _phase(phase_timer, f"{phase_prefix}_write_segments_build_payload"):
            payloads = self._extractable_segment_payloads(task, candidates)
        with _phase(phase_timer, f"{phase_prefix}_write_segments_commit"):
            write_source_extractable_segments(task, payloads)

    def _extractable_segment_payloads(
        self,
        task: ArchiveTask,
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]],
    ) -> list[dict[str, Any]]:
        payloads: list[dict[str, Any]] = []
        for evidence, segment, index in candidates:
            archive_input = self._archive_input_for_segment(task, evidence, segment, index=index)
            if archive_input is None:
                continue
            segment_payload = self._segment_payload(task, evidence, segment)
            payloads.append({
                "segment_id": f"embedded_{index:02d}_{str(evidence.format or 'archive').replace('/', '_')}",
                "index": int(index),
                "format": str(evidence.format or ""),
                "start_offset": int(segment.start_offset),
                "end_offset": int(segment.end_offset) if segment.end_offset is not None else None,
                "confidence": float(segment.confidence or evidence.confidence or 0.0),
                "damage_flags": list(segment.damage_flags),
                "evidence": {
                    "format": evidence.format,
                    "confidence": float(evidence.confidence or 0.0),
                    "status": evidence.status,
                    "warnings": list(evidence.warnings),
                    "details": dict(evidence.details or {}),
                },
                "logical_name": self._segment_logical_name(task, evidence, index),
                "segment": segment_payload,
                "archive_input": archive_input.to_dict(),
            })
        return payloads

    def _prefer_specific_segments(
        self,
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]],
    ) -> list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]]:
        stream_to_container = {
            "gzip": "tar.gz",
            "bzip2": "tar.bz2",
            "xz": "tar.xz",
            "zstd": "tar.zst",
        }
        by_range = {
            (int(segment.start_offset), int(segment.end_offset), evidence.format)
            for evidence, segment, _ in candidates
            if segment.end_offset is not None
        }
        filtered = []
        for evidence, segment, index in candidates:
            if segment.end_offset is not None:
                container_format = stream_to_container.get(evidence.format)
                if container_format and (
                    int(segment.start_offset),
                    int(segment.end_offset),
                    container_format,
                ) in by_range:
                    continue
            filtered.append((evidence, segment, index))
        return filtered

    def _password_required_embedded_segment(
        self,
        report: ArchiveAnalysisReport,
    ) -> tuple[ArchiveFormatEvidence, ArchiveSegment, int] | None:
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]] = []
        for evidence in report.evidences:
            if not evidence.details.get("password_required"):
                continue
            for index, segment in enumerate(evidence.segments, start=1):
                if int(segment.start_offset) <= 0:
                    continue
                candidates.append((evidence, segment, 0))
        if not candidates:
            return None
        return sorted(candidates, key=lambda item: (-item[0].confidence, int(item[1].start_offset)))[0]

    def _segment_payload(self, task: ArchiveTask, evidence: ArchiveFormatEvidence, segment: ArchiveSegment) -> dict:
        payload = asdict(segment)
        payload.update({
            "format": evidence.format,
            "format_hint": evidence.format,
            "path": task.main_path,
        })
        return payload

    def _archive_input_for_segment(
        self,
        task: ArchiveTask,
        evidence: ArchiveFormatEvidence,
        segment: ArchiveSegment,
        *,
        index: int = 1,
    ) -> ArchiveInputDescriptor | None:
        parts = self._ordered_parts(task)
        if not parts:
            return None
        if len(parts) == 1:
            if int(segment.start_offset) <= 0:
                return None
            archive_range = ArchiveInputRange(
                path=parts[0],
                start=int(segment.start_offset),
                end=int(segment.end_offset) if segment.end_offset is not None else None,
            )
            return ArchiveInputDescriptor(
                entry_path=parts[0],
                open_mode="file_range",
                format_hint=evidence.format,
                logical_name=self._segment_logical_name(task, evidence, index),
                parts=[ArchiveInputPart(path=parts[0], range=archive_range)],
                segment=ArchiveInputSegment(
                    start=int(segment.start_offset),
                    end=int(segment.end_offset) if segment.end_offset is not None else None,
                    confidence=float(segment.confidence),
                ),
                analysis={
                    "status": evidence.status,
                    "confidence": float(evidence.confidence),
                    "damage_flags": list(segment.damage_flags),
                },
            )
        if int(segment.start_offset) <= 0:
            return None
        if evidence.format == "rar":
            return None
        ranges = self._logical_range_to_file_ranges(
            parts,
            int(segment.start_offset),
            int(segment.end_offset) if segment.end_offset is not None else None,
        )
        if not ranges:
            return None
        return ArchiveInputDescriptor(
            entry_path=task.main_path,
            open_mode="concat_ranges",
            format_hint=evidence.format,
            logical_name=self._segment_logical_name(task, evidence, index),
            ranges=[ArchiveInputRange(path=item["path"], start=item["start"], end=item.get("end")) for item in ranges],
            segment=ArchiveInputSegment(
                start=int(segment.start_offset),
                end=int(segment.end_offset) if segment.end_offset is not None else None,
                confidence=float(segment.confidence),
            ),
            analysis={
                "status": evidence.status,
                "confidence": float(evidence.confidence),
                "damage_flags": list(segment.damage_flags),
            },
        )

    def _password_probe_input_for_segment(
        self,
        task: ArchiveTask,
        evidence: ArchiveFormatEvidence,
        segment: ArchiveSegment,
        index: int,
    ) -> ArchiveInputDescriptor | None:
        archive_input = self._archive_input_for_segment(
            task,
            evidence,
            segment,
            index=index,
        )
        if archive_input is not None:
            return archive_input

        # A segment beginning at logical offset zero does not need a carved
        # range, but password verification must still receive the structured
        # multi-volume descriptor. Falling back to the single physical file
        # loses the part table and makes encrypted split inputs unverifiable.
        parts = self._ordered_parts(task)
        if len(parts) > 1 and int(segment.start_offset) <= 0:
            split_info = getattr(task, "split_info", None)
            source_input = getattr(split_info, "archive_input", None)
            if isinstance(source_input, ArchiveInputDescriptor) and len(source_input.parts) > 1:
                return source_input

        # RAR volumes are independent containers and cannot become one concat
        # stream.  Header-password probes only need the real archive prefix in
        # the first SFX volume, while extraction retains sfx_with_volumes.
        start = int(segment.start_offset)
        if str(evidence.format or "").lower() != "rar" or len(parts) < 2 or start <= 0:
            return None
        first_part = parts[0]
        try:
            first_size = os.path.getsize(first_part)
        except OSError:
            return None
        if start >= first_size:
            return None
        archive_range = ArchiveInputRange(path=first_part, start=start, end=first_size)
        return ArchiveInputDescriptor(
            entry_path=first_part,
            open_mode="file_range",
            format_hint="rar",
            logical_name=self._segment_logical_name(task, evidence, index),
            parts=[ArchiveInputPart(path=first_part, role="main", range=archive_range)],
            segment=ArchiveInputSegment(
                start=start,
                end=first_size,
                confidence=float(segment.confidence),
            ),
            analysis={
                "status": evidence.status,
                "confidence": float(evidence.confidence),
                "damage_flags": list(segment.damage_flags),
                "purpose": "password_probe",
            },
        )

    def _ordered_parts(self, task: ArchiveTask) -> list[str]:
        volumes = list(getattr(task.split_info, "volumes", None) or [])
        if volumes:
            numbered = [
                (int(volume.get("number") or 0), str(volume.get("path") or ""))
                for volume in volumes
                if isinstance(volume, dict) and volume.get("path")
            ]
            numbered.sort(key=lambda item: item[0])
            paths = [path for _, path in numbered]
            if paths:
                return paths
        return list(task.all_parts or [task.main_path])

    def _logical_range_to_file_ranges(self, parts: list[str], start: int, end: int | None) -> list[dict]:
        ranges = []
        cursor = 0
        for path in parts:
            try:
                size = os.path.getsize(path)
            except OSError:
                return []
            part_start = cursor
            part_end = cursor + size
            cursor = part_end
            if end is not None and start >= end:
                break
            if start >= part_end:
                continue
            if end is not None and end <= part_start:
                break
            local_start = max(start, part_start) - part_start
            local_end = size if end is None else min(end, part_end) - part_start
            if local_end <= local_start:
                continue
            ranges.append({
                "path": path,
                "start": int(local_start),
                "end": int(local_end),
            })
        return ranges

    def _segment_logical_name(self, task: ArchiveTask, evidence: ArchiveFormatEvidence, index: int) -> str:
        base = str(task.logical_name or os.path.splitext(os.path.basename(task.main_path))[0] or "archive")
        if knowledge_view.get(task, "source.selected_segment.index", 0):
            return base
        if index <= 0:
            return base
        fmt = str(evidence.format or "archive").replace("/", "_")
        return f"{base}_{index:02d}_{fmt}"


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)


def _best_selected(report: ArchiveAnalysisReport) -> ArchiveFormatEvidence | None:
    if not report.selected:
        return None
    return max(report.selected, key=lambda item: float(getattr(item, "confidence", 0.0) or 0.0))


_COMPOSITE_INNER_FORMATS = {
    "tar.gz": {"tar", "gzip"},
    "tar.bz2": {"tar", "bzip2"},
    "tar.xz": {"tar", "xz"},
    "tar.zst": {"tar", "zstd"},
}


_NATIVE_ARCHIVE_EXTENSIONS = {
    "zip": {".zip", ".zipx"},
    "rar": {".rar"},
    "7z": {".7z"},
}


def _is_damaged_native_archive_fallback(report: ArchiveAnalysisReport) -> bool:
    prepass = report.prepass if isinstance(report.prepass, dict) else {}
    if str(prepass.get("source") or "") != "embedded_scan":
        return False
    suffix = os.path.splitext(str(report.path or ""))[1].lower()
    if not suffix:
        return False
    return any(
        suffix in _NATIVE_ARCHIVE_EXTENSIONS.get(str(evidence.format or "").lower(), set())
        and str((evidence.details or {}).get("source") or "") == "embedded_scan"
        for evidence in report.selected
    )


def _whole_file_composite_segments(report: ArchiveAnalysisReport) -> list[tuple[ArchiveFormatEvidence, ArchiveSegment]]:
    result = []
    for evidence in report.selected:
        if evidence.format not in _COMPOSITE_INNER_FORMATS:
            continue
        for segment in evidence.segments:
            if segment.end_offset is None:
                continue
            if int(segment.start_offset) != 0:
                continue
            if int(segment.end_offset) < int(report.size):
                continue
            result.append((evidence, segment))
    return result


def _segment_is_shadowed_by_composite(
    evidence: ArchiveFormatEvidence,
    segment: ArchiveSegment,
    composite: tuple[ArchiveFormatEvidence, ArchiveSegment],
) -> bool:
    composite_evidence, composite_segment = composite
    inner_formats = _COMPOSITE_INNER_FORMATS.get(composite_evidence.format, set())
    if evidence.format not in inner_formats:
        return False
    if float(evidence.confidence or 0.0) >= float(composite_evidence.confidence or 0.0):
        return False
    if int(segment.start_offset) < int(composite_segment.start_offset):
        return False
    if segment.end_offset is None or composite_segment.end_offset is None:
        return False
    if int(segment.end_offset) > int(composite_segment.end_offset):
        return False
    return True


def _write_plan_knowledge(
    task: ArchiveTask,
    report: ArchiveAnalysisReport,
    segments: list[dict[str, Any]],
    selected_segment: tuple[ArchiveFormatEvidence, ArchiveSegment, int] | None,
    password_probe_input: ArchiveInputDescriptor | None,
) -> None:
    selected = _best_selected(report)
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "input_planning",
        {
            "status": "extractable" if report.has_extractable else "not_extractable",
            "report_path": report.path,
            "read_bytes": report.read_bytes,
            "cache_hits": report.cache_hits,
            "selected_format": getattr(selected, "format", "") if selected is not None else "",
            "confidence": float(getattr(selected, "confidence", 0.0) or 0.0) if selected is not None else 0.0,
        },
        source_layer="detection",
        source_module="archive_input_planner",
    )
    commit_task_knowledge(task, knowledge)
    write_source_extractable_segments(task, segments)
    write_source_password_probe_input(
        task,
        password_probe_input.to_dict() if password_probe_input is not None else None,
    )
    if selected_segment is not None:
        evidence, segment, index = selected_segment
        write_source_selected_segment(task, evidence, segment, index=index)


def _write_plan_error(task: ArchiveTask, error: str) -> None:
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "input_planning",
        {"status": "error", "error": str(error or "")},
        source_layer="detection",
        source_module="archive_input_planner",
    )
    commit_task_knowledge(task, knowledge)
