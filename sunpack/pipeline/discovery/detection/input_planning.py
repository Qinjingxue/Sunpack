import json
import os
import threading
from contextlib import nullcontext
from dataclasses import asdict, replace
from typing import Any, Callable

from sunpack.core.analysis import ArchiveAnalysisReport, ArchiveAnalyzer
from sunpack.core.analysis.request import AnalysisCapability, AnalysisRequest, DEFAULT_ANALYSIS_CAPABILITIES
from sunpack.core.analysis.source import analysis_source_for_descriptor
from sunpack.core.support.archive_input_projection import (
    write_source_extractable_segments,
    write_source_password_probe_input,
    write_source_selected_segment,
)
from sunpack.core.support.archive_knowledge_writer import (
    commit_task_knowledge,
    ensure_knowledge,
    write_payload,
)
from sunpack.core.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    InputExtent,
)
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.support import archive_knowledge_projection as knowledge_view


class ArchiveInputPlanningStage:
    """Turn neutral Analysis reports into main-flow archive inputs."""
    def __init__(
        self,
        config: dict[str, Any] | None = None,
    ):
        self.config = config or {}
        planning_config = self.config.get("input_planning") if isinstance(self.config.get("input_planning"), dict) else {}
        self.enabled = bool(planning_config.get("enabled", True))
        self._report_cache: dict[tuple, ArchiveAnalysisReport] = {}
        self._report_cache_lock = threading.Lock()
        self.analyzer = (
            ArchiveAnalyzer(self.config)
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
        limit = max(0, int(planning_config.get("cache_size", 512)))
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
            "discovery_confirmed",
            _discovery_confirmed(task),
        )

    def _planning_task_groups(self, tasks: list[ArchiveTask]) -> list[list[tuple[int, ArchiveTask]]]:
        grouped: dict[tuple, list[tuple[int, ArchiveTask]]] = {}
        order: list[tuple] = []
        for index, task in enumerate(tasks):
            try:
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
        if _discovery_confirmed(group[0][1]):
            return [
                (index, self._plan_task_to_tasks(task)[1])
                for index, task in group
            ]
        if len(group) == 1:
            index, task = group[0]
            _, task_results = self._plan_task_to_tasks(task)
            return [(index, task_results)]
        first_index, first_task = group[0]
        report, first_results = self._plan_task_to_tasks(first_task)
        results = [(first_index, first_results)]
        if report is None:
            for index, task in group[1:]:
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

    def requires_analysis(self, task: ArchiveTask) -> bool:
        if self.analyzer is None:
            return False
        descriptor = task.archive_input()
        # Identity confirmation does not carry stream structure.
        # Embedded tasks already own the canonical plan; reuse it directly.
        if descriptor.format_hint in {"lz4", "tar.lz4"}:
            return not descriptor.analysis.get("stream_plan")
        return not _discovery_confirmed(task)

    def _plan_task_to_tasks(self, task: ArchiveTask) -> tuple[ArchiveAnalysisReport | None, list[ArchiveTask]]:
        if not self.requires_analysis(task):
            return None, [task]
        try:
            report = self._get_or_create_report(task)
        except Exception as exc:
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
        descriptor = task.archive_input()
        source = analysis_source_for_descriptor(
            descriptor,
            report_path=task.main_path,
        )
        prepass = knowledge_view.inspection_prepass(task)
        initial_prepass = (
            dict(prepass)
            if isinstance(prepass, dict) and prepass.get("full_scan_complete")
            else None
        )
        return self.analyzer.analyze(
            source,
            AnalysisRequest(
                initial_prepass=initial_prepass,
                capabilities=(frozenset({AnalysisCapability.FORMAT_STRUCTURE})
                    if _discovery_confirmed(task) and descriptor.format_hint in {"lz4", "tar.lz4"}
                    else DEFAULT_ANALYSIS_CAPABILITIES),
            ),
        )

    def _tasks_from_report(self, task: ArchiveTask, report: ArchiveAnalysisReport, *, phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "input_planning") -> list[ArchiveTask]:
        with _phase(phase_timer, f"{phase_prefix}_record_report"):
            self._record_report(task, report, phase_timer=phase_timer, phase_prefix=phase_prefix, record_state=False, write_knowledge=False)
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
                self._record_planning_input(task, report, phase_timer=phase_timer, phase_prefix=phase_prefix)
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
            self._record_planning_input(task, report, phase_timer=phase_timer, phase_prefix=phase_prefix)
        return [task]

    @staticmethod
    def _structured_volume_source(task: ArchiveTask) -> ArchiveInputDescriptor | None:
        source_input = task.archive_input()
        return source_input if len(source_input.parts) > 1 else None

    def _apply_selected_segment(
        self,
        task: ArchiveTask,
        evidence: ArchiveFormatEvidence,
        segment: ArchiveSegment,
        *,
        index: int,
        write_knowledge: bool = True,
    ) -> None:
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
        if write_knowledge:
            with _phase(phase_timer, f"{phase_prefix}_record_report_write_knowledge"):
                _write_plan_knowledge(task, report, [], None)
        if record_state:
            with _phase(phase_timer, f"{phase_prefix}_record_report_state_analysis"):
                self._record_planning_input(task, report, phase_timer=phase_timer, phase_prefix=phase_prefix)

    @staticmethod
    def _execution_analysis_for_report(
        descriptor: ArchiveInputDescriptor,
        report: ArchiveAnalysisReport,
    ) -> dict[str, Any]:
        """Project only analysis facts that the extraction worker can consume.

        These facts are advisory execution metadata, not a second preflight
        decision. The worker still opens and extracts the current files, so a
        stale analysis result cannot reject a volume that arrived later.
        """
        if descriptor.open_mode not in {"native_volumes", "sfx_with_volumes"}:
            return {}
        if len(descriptor.parts) <= 1 or not report.missing_volume_evidence:
            return {}
        return {"missing_volume_evidence": report.missing_volume_evidence}

    def _record_planning_input(
        self,
        task: ArchiveTask,
        report: ArchiveAnalysisReport,
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "input_planning",
    ) -> None:
        with _phase(phase_timer, f"{phase_prefix}_record_input_get"):
            descriptor = task.archive_input()
        with _phase(phase_timer, f"{phase_prefix}_record_input_build"):
            selected = report.best_selected
            analysis = dict(descriptor.analysis)
            analysis.pop("execution", None)
            execution_analysis = self._execution_analysis_for_report(descriptor, report)
            if execution_analysis:
                analysis["execution"] = execution_analysis
            selected_format = str(getattr(selected, "format", "") or "")
            analysis.update(_stream_execution_analysis(selected, 0))
            updated = replace(
                descriptor,
                format_hint=selected_format or descriptor.format_hint,
                analysis=analysis,
            )
        with _phase(phase_timer, f"{phase_prefix}_record_input_set"):
            if updated != descriptor:
                task.set_archive_input(updated)

    @staticmethod
    def _extractable_segments(report: ArchiveAnalysisReport) -> list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]]:
        return [
            (evidence, segment, position)
            for position, (evidence, segment) in enumerate(report.extractable_segments, start=1)
        ]

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

    @staticmethod
    def _password_required_embedded_segment(
        report: ArchiveAnalysisReport,
    ) -> tuple[ArchiveFormatEvidence, ArchiveSegment, int] | None:
        if report.password_segment is None:
            return None
        evidence, segment = report.password_segment
        return evidence, segment, 0

    def _segment_payload(self, task: ArchiveTask, evidence: ArchiveFormatEvidence, segment: ArchiveSegment) -> dict:
        payload = asdict(segment)
        payload.update({
            "format": evidence.format,
            "format_hint": evidence.format,
            "path": task.main_path,
        })
        payload.update(_stream_execution_analysis(evidence, segment.start_offset))
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
        if not parts or segment.end_offset is None:
            return None
        segment_analysis = {
            "status": evidence.status,
            "confidence": float(evidence.confidence),
            "damage_flags": list(segment.damage_flags),
            "segment_confidence": float(segment.confidence),
            "segment_source": "analysis",
        }
        segment_analysis.update(_stream_execution_analysis(evidence, segment.start_offset))
        if evidence.details.get("password_required"):
            segment_analysis["password_required"] = True
        if len(parts) == 1:
            try:
                size = os.path.getsize(parts[0])
            except OSError:
                return None
            if not _strict_subrange(segment.start_offset, segment.end_offset, size):
                return None
            extent = InputExtent(
                path=parts[0],
                start=int(segment.start_offset),
                end=int(segment.end_offset) if segment.end_offset is not None else None,
            )
            return ArchiveInputDescriptor(
                entry_path=parts[0],
                open_mode="file_range",
                format_hint=evidence.format,
                logical_name=self._segment_logical_name(task, evidence, index),
                parts=[ArchiveInputPart(extent=extent)],
                analysis=dict(segment_analysis),
            )
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
            extents=[InputExtent(path=item["path"], start=item["start"], end=item.get("end")) for item in ranges],
            analysis=dict(segment_analysis),
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
        if len(parts) == 1 and segment.start_offset > 0 and segment.end_offset is None:
            try:
                size = os.path.getsize(parts[0])
            except OSError:
                return None
            # The archive boundary is unresolved until headers are decrypted.
            # Password probing may use the available suffix without declaring
            # that suffix a complete extractable archive.
            return self._archive_input_for_segment(
                task, evidence, replace(segment, end_offset=size), index=index,
            )
        if len(parts) > 1 and int(segment.start_offset) <= 0:
            source_input = task.archive_input()
            if len(source_input.parts) > 1:
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
        extent = InputExtent(path=first_part, start=start, end=first_size)
        return ArchiveInputDescriptor(
            entry_path=first_part,
            open_mode="file_range",
            format_hint="rar",
            logical_name=self._segment_logical_name(task, evidence, index),
            parts=[ArchiveInputPart(extent=extent, role="main")],
            analysis={
                "status": evidence.status,
                "confidence": float(evidence.confidence),
                "damage_flags": list(segment.damage_flags),
                "purpose": "password_probe",
                "segment_confidence": float(segment.confidence),
                "segment_source": "analysis",
            },
        )

    def _ordered_parts(self, task: ArchiveTask) -> list[str]:
        return list(task.all_parts or [task.main_path])

    def _logical_range_to_file_ranges(self, parts: list[str], start: int, end: int | None) -> list[dict]:
        ranges = []
        try:
            sizes = [os.path.getsize(path) for path in parts]
        except OSError:
            return []
        if not _strict_subrange(start, end, sum(sizes)):
            return []
        cursor = 0
        for path, size in zip(parts, sizes):
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


def _write_plan_knowledge(
    task: ArchiveTask,
    report: ArchiveAnalysisReport,
    segments: list[dict[str, Any]],
    selected_segment: tuple[ArchiveFormatEvidence, ArchiveSegment, int] | None,
    password_probe_input: ArchiveInputDescriptor | None,
) -> None:
    selected = report.best_selected
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


def _discovery_confirmed(task: ArchiveTask) -> bool:
    return str(getattr(task, "discovery_source", "") or "") in {
        "relations",
        "detection",
        "embedded",
    }


def _strict_subrange(start: int, end: int | None, size: int) -> bool:
    return end is not None and 0 <= start < end <= size and (start > 0 or end < size)


def _stream_execution_analysis(evidence: ArchiveFormatEvidence | None, offset: int) -> dict[str, Any]:
    if evidence is None:
        return {}
    details = evidence.details
    plans = details.get("stream_plans") or {}
    # A sequence of embedded streams must never inherit the plan at offset zero.
    plan = plans.get(str(offset)) if plans else (details.get("stream_plan") if offset == 0 else None)
    return {"stream_plan": plan} if plan else {}
