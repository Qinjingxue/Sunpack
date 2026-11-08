import threading
from collections import OrderedDict
from contextlib import nullcontext
from dataclasses import replace
from typing import Any, Callable
from sunpack_native import archive_input_slices

from sunpack.core.analysis import ArchiveAnalysisReport, ArchiveAnalyzer
from sunpack.core.analysis.request import AnalysisCapability, AnalysisRequest, DEFAULT_ANALYSIS_CAPABILITIES
from sunpack.core.analysis.source import analysis_source_for_descriptor
from sunpack.core.support.archive_input_projection import (
    write_source_inputs,
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
)
from sunpack.core.contracts.tasks import ArchiveTask
from sunpack.core.contracts.input_plan import LogicalArchiveInput
from sunpack.core.support import archive_knowledge_projection as knowledge_view


_REPORT_CACHE_LIMIT = 512


class ArchiveInputPlanningStage:
    """Turn neutral Analysis reports into main-flow archive inputs."""
    def __init__(
        self,
        config: dict[str, Any] | None = None,
    ):
        self._report_cache: OrderedDict[tuple, ArchiveAnalysisReport] = OrderedDict()
        self._report_cache_lock = threading.Lock()
        self.analyzer = ArchiveAnalyzer(config or {})

    def _remember_report(self, cache_key: tuple, report: ArchiveAnalysisReport) -> None:
        with self._report_cache_lock:
            self._report_cache[cache_key] = report
            if len(self._report_cache) > _REPORT_CACHE_LIMIT:
                self._report_cache.popitem(last=False)

    def clear_report_cache(self) -> None:
        """Release archive-specific reports after a completed request group."""
        with self._report_cache_lock:
            self._report_cache.clear()

    def _report_cache_key(self, task: ArchiveTask) -> tuple:
        return knowledge_view.source_fingerprint(task), _discovery_confirmed(task)

    def plan_task(self, task: ArchiveTask) -> ArchiveAnalysisReport | None:
        report, _ = self._plan_task_to_tasks(task)
        return report

    def plan_task_to_tasks(self, task: ArchiveTask) -> list[ArchiveTask]:
        _, tasks = self._plan_task_to_tasks(task)
        return tasks

    def requires_analysis(self, task: ArchiveTask) -> bool:
        if task.discovery_failure is not None:
            return False
        descriptor = task.archive_input()
        # Identity confirmation does not carry stream structure.
        # Embedded tasks already own the canonical plan; reuse it directly.
        if descriptor.format_hint == "lz4":
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
                    if _discovery_confirmed(task) and descriptor.format_hint == "lz4"
                    else DEFAULT_ANALYSIS_CAPABILITIES),
            ),
        )

    def _tasks_from_report(self, task: ArchiveTask, report: ArchiveAnalysisReport, *, phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "input_planning") -> list[ArchiveTask]:
        with _phase(phase_timer, f"{phase_prefix}_extractable_segments"):
            candidates = self._extractable_segments(report)
        if not candidates:
            password_candidate = self._password_required_embedded_segment(report)
            if password_candidate is not None:
                candidates = [password_candidate]
        selected_segment = candidates[0] if candidates else None
        with _phase(phase_timer, f"{phase_prefix}_write_segments_build_payload"):
            segment_payloads, password_probe_input = self._project_segments(task.archive_input(), candidates)
        with _phase(phase_timer, f"{phase_prefix}_batched_write"):
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
            analysis.update(_zip_password_analysis(selected, 0))
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

    @staticmethod
    def _project_segments(
        source: ArchiveInputDescriptor,
        candidates: list[tuple[ArchiveFormatEvidence, ArchiveSegment, int]],
    ) -> tuple[list[LogicalArchiveInput], ArchiveInputDescriptor | None]:
        if not candidates:
            return [], source if len(source.parts) > 1 else None
        projected, probe = archive_input_slices(source.to_dict(), [
            (evidence.format, segment.start_offset, segment.end_offset)
            for evidence, segment, _ in candidates
        ])
        payloads: list[LogicalArchiveInput] = []
        for (evidence, segment, index), row in zip(candidates, projected, strict=True):
            if row is None:
                continue
            analysis = {
                "status": evidence.status,
                "damage_flags": list(segment.damage_flags),
                "segment_source": "analysis",
            }
            analysis.update(_stream_execution_analysis(evidence, segment.start_offset))
            analysis.update(_zip_password_analysis(evidence, segment.start_offset))
            if evidence.details.get("password_required"):
                analysis["password_required"] = True
            descriptor = replace(ArchiveInputDescriptor.from_dict(row), analysis=analysis)
            payloads.append(LogicalArchiveInput(descriptor, position=index))
        if projected[0] is not None:
            return payloads, payloads[0].descriptor
        probe_input = None
        if probe is not None:
            evidence, segment, _ = candidates[0]
            probe_input = replace(ArchiveInputDescriptor.from_dict(probe), analysis={
                **source.analysis,
                **_zip_password_analysis(evidence, segment.start_offset),
            })
        return payloads, probe_input

    @staticmethod
    def _password_required_embedded_segment(
        report: ArchiveAnalysisReport,
    ) -> tuple[ArchiveFormatEvidence, ArchiveSegment, int] | None:
        if report.password_segment is None:
            return None
        evidence, segment = report.password_segment
        return evidence, segment, 0


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)


def _write_plan_knowledge(
    task: ArchiveTask,
    report: ArchiveAnalysisReport,
    segments: list[LogicalArchiveInput],
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
        },
        source_layer="detection",
        source_module="archive_input_planner",
    )
    commit_task_knowledge(task, knowledge)
    write_source_inputs(task, segments)
    write_source_password_probe_input(
        task,
        password_probe_input,
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


def _zip_password_analysis(evidence: ArchiveFormatEvidence | None, offset: int) -> dict[str, Any]:
    if evidence is None or evidence.format != "zip":
        return {}
    details = evidence.details
    candidates = details.get("candidate_details") or [details]
    for candidate in candidates:
        if not isinstance(candidate, dict) or candidate.get("archive_offset", 0) != offset:
            continue
        eocd = candidate.get("eocd_offset")
        if isinstance(eocd, int) and eocd >= offset:
            return {"zip_eocd_offset": eocd - offset}
    return {}


def _stream_execution_analysis(evidence: ArchiveFormatEvidence | None, offset: int) -> dict[str, Any]:
    if evidence is None:
        return {}
    details = evidence.details
    plans = details.get("stream_plans") or {}
    # A sequence of embedded streams must never inherit the plan at offset zero.
    plan = plans.get(str(offset)) if plans else (details.get("stream_plan") if offset == 0 else None)
    return {"stream_plan": plan} if plan else {}
