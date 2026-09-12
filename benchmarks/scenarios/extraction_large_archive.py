from __future__ import annotations

import argparse
import asyncio
import contextlib
import inspect
import json
import os
import shutil
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sunpack.coordinator.engine import DirectOutputCommitter, PipelineEngine
import sunpack.coordinator.engine as engine_module
import sunpack.analysis.engine as analysis_engine_module
import sunpack.analysis.fuzzy_pipeline.modules.binary_profile as binary_profile_module
import sunpack.analysis.structure_pipeline.modules.compression_streams as compression_streams_module
import sunpack.analysis.structure_pipeline.modules.rar as rar_analysis_module
import sunpack.coordinator.scan_session as scan_session_module
from sunpack.analysis.config import enabled_fuzzy_module_configs
from sunpack.analysis.fuzzy_pipeline.registry import get_fuzzy_analysis_module_registry
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.analysis.view import SharedBinaryView
from sunpack.support.output_inventory import OutputInventory
from tests.helpers.performance_config import archive_pressure_config
from benchmarks.harness import render_report, report_from_payload


TimingMap = dict[str, list[float]]


def _measure(timings: TimingMap, label: str, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    started = time.perf_counter()
    try:
        return function(*args, **kwargs)
    finally:
        timings[label].append(time.perf_counter() - started)


async def _measure_async(timings: TimingMap, label: str, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    started = time.perf_counter()
    try:
        return await function(*args, **kwargs)
    finally:
        timings[label].append(time.perf_counter() - started)


def _wrap(
    owner: Any,
    name: str,
    timings: TimingMap,
    label: str | None = None,
    *,
    phase_timer: Callable[..., Any] | None = None,
) -> None:
    if owner is None or not hasattr(owner, name):
        return
    original = getattr(owner, name)
    if inspect.iscoroutinefunction(original):

        async def measured_async(*args: Any, **kwargs: Any) -> Any:
            if phase_timer is not None:
                kwargs.setdefault("phase_timer", phase_timer)
            return await _measure_async(timings, label or name, original, *args, **kwargs)

        setattr(owner, name, measured_async)
        return

    def measured(*args: Any, **kwargs: Any) -> Any:
        if phase_timer is not None:
            kwargs.setdefault("phase_timer", phase_timer)
        return _measure(timings, label or name, original, *args, **kwargs)

    setattr(owner, name, measured)


def _child(owner: Any, name: str) -> Any | None:
    return getattr(owner, name, None) if owner is not None else None


class RequestRuntimeProfiler:
    """Attach probes to the per-submission runtime used by current PipelineEngine."""

    def __init__(self) -> None:
        self.enabled = False
        self.request_timings: list[TimingMap] = []
        self._active_timings: TimingMap | None = None
        self._factory_restore: tuple[Any, Callable[..., Any]] | None = None
        self._instance_restores: list[tuple[Any, str, Any]] = []
        self._global_restores: list[tuple[Any, str, Any]] = []
        self._global_installed: set[tuple[int, str]] = set()

    def install(self, runner: PipelineEngine) -> None:
        original_factory = runner._request_runtime_factory
        self._factory_restore = (runner, original_factory)

        def profiled_factory(*args: Any, **kwargs: Any):
            if not self.enabled:
                return original_factory(*args, **kwargs)
            timings = self._active_timings
            if timings is None:
                # The factory can also be invoked directly by focused tests.
                timings = defaultdict(list)
                self.request_timings.append(timings)
                self._active_timings = timings
            runtime = _measure(timings, "pipeline_runtime_create", original_factory, *args, **kwargs)
            self._instrument_runtime(runtime, timings)
            return runtime

        runner._request_runtime_factory = profiled_factory
        self._install_pipeline_run_timer(runner)
        self._install_instance_method(runner, "_normalize_target", "pipeline_normalize_target")
        path_leases = _child(runner, "_path_leases")
        self._install_instance_method(path_leases, "try_acquire", "pipeline_lease_acquire")
        self._install_instance_method(path_leases, "try_replace", "pipeline_lease_replace")
        self._install_instance_method(path_leases, "release", "pipeline_lease_release")
        self._install_global_method(DirectOutputCommitter, "commit", "pipeline_output_commit")
        self._install_global_method(DirectoryScanner, "inventory_file_indices", "output_inventory_filter")
        self._install_global_method(DirectoryScanner, "snapshot_from_entries", "output_snapshot_filter")
        self._install_global_method(
            DirectoryScanner,
            "snapshot_from_output_inventory",
            "output_inventory_snapshot_fused",
        )
        self._install_global_method(DetectionScanSession, "file_head_facts_for_paths", "output_file_head_facts")
        self._install_global_method(DetectionScanSession, "prime_snapshot", "output_prime_snapshot")
        self._install_global_method(OutputInventory, "from_value", "output_inventory_from_value")
        self._install_global_callable(
            scan_session_module,
            "_native_batch_file_head_facts",
            "output_native_batch_file_head_facts",
        )
        self._install_global_callable(
            analysis_engine_module,
            "run_signature_prepass",
            "planning_signature_prepass",
        )
        self._install_global_callable(
            rar_analysis_module,
            "probe_rar_view",
            "planning_rar_native_probe",
        )
        self._install_global_dynamic_callable(
            compression_streams_module,
            "probe_compression_stream_view",
            lambda _view, options: f"planning_stream_probe_{getattr(options, 'format', 'unknown')}",
        )
        self._install_global_dynamic_method(
            SharedBinaryView,
            "probe_compressed_tar",
            lambda _view, **kwargs: f"planning_compressed_tar_probe_{kwargs.get('format', 'unknown')}",
        )
        self._install_global_method(SharedBinaryView, "fuzzy_binary_profile", "planning_fuzzy_native_profile")
        self._install_global_callable(binary_profile_module, "_complete_profile", "planning_fuzzy_complete_profile")

    def restore(self) -> None:
        if self._factory_restore is not None:
            runner, factory = self._factory_restore
            runner._request_runtime_factory = factory
            self._factory_restore = None
        while self._global_restores:
            owner, name, descriptor = self._global_restores.pop()
            setattr(owner, name, descriptor)
        while self._instance_restores:
            owner, name, original = self._instance_restores.pop()
            setattr(owner, name, original)
        self._global_installed.clear()
        self._active_timings = None

    def _install_pipeline_run_timer(self, runner: PipelineEngine) -> None:
        if not hasattr(runner, "run"):
            return
        original = runner.run
        self._instance_restores.append((runner, "run", original))

        async def measured_run(*args: Any, **kwargs: Any) -> Any:
            if not self.enabled:
                return await original(*args, **kwargs)
            timings: TimingMap = defaultdict(list)
            self.request_timings.append(timings)
            previous_timings = self._active_timings
            self._active_timings = timings
            try:
                return await _measure_async(timings, "pipeline_run", original, *args, **kwargs)
            finally:
                self._active_timings = previous_timings

        runner.run = measured_run

    def _install_instance_method(self, owner: Any, name: str, label: str) -> None:
        if owner is None or not hasattr(owner, name):
            return
        original = getattr(owner, name)
        self._instance_restores.append((owner, name, original))
        if inspect.iscoroutinefunction(original):

            async def measured_async(*args: Any, **kwargs: Any) -> Any:
                timings = self._active_timings
                if timings is None:
                    return await original(*args, **kwargs)
                return await _measure_async(timings, label, original, *args, **kwargs)

            setattr(owner, name, measured_async)
            return

        def measured(*args: Any, **kwargs: Any) -> Any:
            return self._measure_active(label, original, *args, **kwargs)

        setattr(owner, name, measured)

    def _install_global_method(self, owner: type, name: str, label: str) -> None:
        descriptor = owner.__dict__[name]
        original = getattr(owner, name)
        self._global_restores.append((owner, name, descriptor))

        if isinstance(descriptor, classmethod):
            def measured_classmethod(_cls, *args: Any, **kwargs: Any):
                return self._measure_active(label, original, *args, **kwargs)

            setattr(owner, name, classmethod(measured_classmethod))
            return
        if isinstance(descriptor, staticmethod):
            def measured_staticmethod(*args: Any, **kwargs: Any):
                return self._measure_active(label, original, *args, **kwargs)

            setattr(owner, name, staticmethod(measured_staticmethod))
            return

        def measured_method(instance, *args: Any, **kwargs: Any):
            return self._measure_active(label, original, instance, *args, **kwargs)

        setattr(owner, name, measured_method)

    def _install_global_callable(self, owner: Any, name: str, label: str) -> None:
        key = (id(owner), name)
        if key in self._global_installed:
            return
        self._global_installed.add(key)
        original = getattr(owner, name)
        self._global_restores.append((owner, name, original))

        def measured(*args: Any, **kwargs: Any):
            return self._measure_active(label, original, *args, **kwargs)

        setattr(owner, name, measured)

    def _install_global_dynamic_callable(self, owner: Any, name: str, label: Callable[..., str]) -> None:
        key = (id(owner), name)
        if key in self._global_installed:
            return
        self._global_installed.add(key)
        original = getattr(owner, name)
        self._global_restores.append((owner, name, original))

        def measured(*args: Any, **kwargs: Any):
            return self._measure_active(label(*args, **kwargs), original, *args, **kwargs)

        setattr(owner, name, measured)

    def _install_cleanup_timer(self, scope) -> None:
        """Time per-task source cleanup and the share spent at its barrier gate."""

        if scope is None:
            return
        self._install_instance_method(scope, "release_task", "batch_cleanup_task")
        original_barrier = engine_module.promotion_barrier

        @contextlib.contextmanager
        def measured_barrier(*args: Any, **kwargs: Any):
            with original_barrier(*args, **kwargs) as report:
                timings = self._active_timings
                if timings is not None:
                    timings["batch_cleanup_barrier"].append(
                        float(getattr(report, "gate_wait_seconds", 0.0) or 0.0)
                    )
                yield report

        self._global_restores.append((engine_module, "promotion_barrier", original_barrier))
        engine_module.promotion_barrier = measured_barrier

    def _install_global_dynamic_method(self, owner: type, name: str, label: Callable[..., str]) -> None:
        descriptor = owner.__dict__[name]
        original = getattr(owner, name)
        self._global_restores.append((owner, name, descriptor))

        def measured(instance: Any, *args: Any, **kwargs: Any):
            return self._measure_active(label(instance, *args, **kwargs), original, instance, *args, **kwargs)

        setattr(owner, name, measured)

    def _measure_active(self, label: str, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        timings = self._active_timings
        if timings is None:
            return function(*args, **kwargs)
        return _measure(timings, label, function, *args, **kwargs)

    def _instrument_runtime(self, runtime: Any, timings: TimingMap) -> None:
        @contextlib.contextmanager
        def phase(name: str, **_details: Any):
            started = time.perf_counter()
            try:
                yield
            finally:
                timings[f"phase_{name}"].append(time.perf_counter() - started)

        scanner = runtime.task_scanner
        planning = runtime.input_planning_stage
        batch = runtime.batch_runner
        extractor = runtime.extractor
        output_scan = runtime.output_scan_policy

        _wrap(runtime, "execute_async", timings, "pipeline_runtime_execute")
        _wrap(runtime, "_plan_task_isolated", timings, "pipeline_plan_task_isolated")
        _wrap(_child(runtime, "nested_extraction_policy"), "authorize_batch", timings, "pipeline_nested_authorize")
        self._install_cleanup_timer(_child(runtime, "cleanup_scope"))

        _wrap(scanner, "direct_file_tasks", timings, "pipeline_direct_scan")
        _wrap(scanner, "scan_targets", timings, "pipeline_nested_scan")

        _wrap(planning, "plan_tasks", timings, "input_planning")
        for name, label in (
            ("_planning_task_groups", "planning_group_tasks"),
            ("_plan_task_group", "planning_plan_group"),
            ("_plan_task_to_tasks", "planning_plan_task"),
            ("_report_cache_key", "planning_cache_key"),
            ("_get_or_create_report", "planning_get_report"),
            ("_analyze_task", "planning_analyze_task"),
            ("_tasks_from_report", "planning_tasks_from_report"),
            ("_record_report", "planning_record_report"),
            ("_record_planning_state", "planning_record_state"),
        ):
            _wrap(planning, name, timings, label)
        _wrap(_child(planning, "analyzer"), "analyze", timings, "planning_analyzer_analyze")
        analyzer = _child(planning, "analyzer")
        _wrap(analyzer, "_view_for_source", timings, "planning_analyzer_build_view")
        analysis_engine = _child(analyzer, "_engine")
        for name, label in (
            ("analyze_path", "planning_engine_analyze_path"),
            ("analyze_view", "planning_engine_analyze_view"),
            ("_build_single_view", "planning_engine_build_view"),
            ("_run_fuzzy_pipeline", "planning_fuzzy_pipeline"),
            ("_selected_structure_modules", "planning_select_structure_modules"),
            ("_run_structure_modules", "planning_structure_modules"),
            ("_selected_evidences", "planning_select_evidences"),
            ("_embedded_scan_enabled", "planning_embedded_scan_check"),
        ):
            _wrap(analysis_engine, name, timings, label)
        if analysis_engine is not None:
            fuzzy_registry = get_fuzzy_analysis_module_registry()
            for module_name in enabled_fuzzy_module_configs(analysis_engine.config):
                module = fuzzy_registry.get(module_name)
                if module is not None:
                    self._install_global_callable(
                        module,
                        "analyze",
                        f"planning_fuzzy_module_{module_name}",
                    )
        if analysis_engine is not None and hasattr(analysis_engine, "_run_module"):
            original_run_module = analysis_engine._run_module

            def timed_run_module(module, *args: Any, **kwargs: Any):
                module_name = str(getattr(getattr(module, "spec", None), "name", "unknown") or "unknown")
                return _measure(
                    timings,
                    f"planning_structure_module_{module_name}",
                    original_run_module,
                    module,
                    *args,
                    **kwargs,
                )

            analysis_engine._run_module = timed_run_module

        _wrap(batch, "execute_async", timings, "batch_execute")
        for name, label in (
            ("prepare_tasks", "batch_prepare"),
            ("_skip_tasks_inside_batch_outputs", "batch_skip_inside_outputs"),
            ("collect_result", "batch_collect_result"),
            ("_inspect_tasks_before_extract", "batch_password_preflight"),
            ("_inspect_resource_profiles", "batch_resource_profiles"),
        ):
            _wrap(batch, name, timings, label)
        _wrap(_child(batch, "relation_stage"), "resolve_tasks", timings, "batch_relation_resolve")
        _wrap(runtime.rename_scheduler, "build_output_dir_resolver", timings, "batch_output_dir_resolver")
        password_contexts = _child(batch, "directory_password_contexts")
        _wrap(password_contexts, "annotate", timings, "batch_directory_password_annotate")
        _wrap(password_contexts, "remember", timings, "batch_directory_password_remember")
        resource_inspector = _child(batch, "resource_inspector")
        _wrap(resource_inspector, "inspect", timings, "batch_resource_inspect")
        _wrap(resource_inspector, "record_estimated_single_task_profile", timings, "batch_resource_record")
        reporter = runtime.reporter
        _wrap(reporter, "begin_round", timings, "batch_report_begin_round")
        _wrap(reporter, "task_finished", timings, "batch_report_task_finished")
        _wrap(reporter, "log_final_summary", timings, "pipeline_final_report")

        _wrap(output_scan, "scan_roots_from_outputs", timings, "output_scan")
        _wrap(output_scan, "_snapshot_from_inventory", timings, "output_snapshot_from_inventory")
        _wrap(output_scan, "_inventory_files", timings, "output_inventory_files")
        _wrap(output_scan, "_is_within_root", timings, "output_inventory_path_check")
        _wrap(output_scan, "take_scan_session", timings, "output_take_scan_session")

        _wrap(extractor, "inspect", timings, "password_preflight")
        _wrap(extractor, "extract", timings, "extract_total_legacy", phase_timer=phase)
        _wrap(extractor, "extract_asyncio", timings, "extract_total", phase_timer=phase)
        _wrap(extractor, "close", timings, "extractor_close")
        _wrap(_child(extractor, "password_resolver"), "resolve", timings, "password_resolver")
        password_tester = _child(extractor, "password_tester")
        _wrap(password_tester, "test_without_password", timings, "password_without")
        _wrap(_child(password_tester, "native_password_tester"), "try_passwords", timings, "password_candidates")
        metadata_scanner = _child(extractor, "metadata_scanner")
        _wrap(metadata_scanner, "scan", timings, "filename_metadata")
        _wrap(metadata_scanner, "scan_for_task", timings, "filename_metadata_for_task")
        sevenzip = _child(extractor, "sevenzip_runner")
        _wrap(sevenzip, "extract_attempt", timings, "sevenzip_worker_legacy", phase_timer=phase)
        _wrap(sevenzip, "submit_attempt_asyncio", timings, "sevenzip_worker", phase_timer=phase)
        _wrap(sevenzip, "_json_line", timings, "worker_protocol_json_decode")
        _wrap(sevenzip, "_drain_stderr", timings, "worker_protocol_drain_stderr")
        _wrap(sevenzip, "_emit_progress", timings, "worker_protocol_emit_progress")
        _wrap(batch.verifier, "verify", timings, "verify_total", phase_timer=phase)


def _generated_output_path(output_base: Path, kind: str, index: int) -> Path:
    if kind not in {"warmup", "run"}:
        raise ValueError(f"unsupported output kind: {kind}")
    return output_base.parent / f"{output_base.name}-{kind}-{index}"


def _cleanup_generated_output(path: Path, output_base: Path) -> None:
    resolved = path.resolve()
    parent = output_base.resolve().parent
    expected_prefix = f"{output_base.name}-"
    if resolved.parent != parent or not resolved.name.startswith(expected_prefix):
        raise ValueError(f"refusing to clean non-generated output: {resolved}")
    shutil.rmtree(resolved, ignore_errors=True)


def _output_summary(root: Path) -> dict[str, int]:
    files = [path for path in root.rglob("*") if path.is_file()]
    return {"file_count": len(files), "total_bytes": sum(path.stat().st_size for path in files)}


def _timing_medians(request_timings: list[TimingMap]) -> dict[str, float]:
    labels = sorted({label for timings in request_timings for label in timings})
    return {
        label: round(statistics.median(sum(timings.get(label, [])) for timings in request_timings), 6)
        for label in labels
    }


def _timing_totals(timings: TimingMap) -> dict[str, float]:
    return {label: round(sum(values), 6) for label, values in sorted(timings.items())}


def _derived_timing(timings: TimingMap) -> dict[str, float]:
    total = lambda label: sum(timings.get(label, []))
    batch_direct_children = sum(total(label) for label in (
        "batch_report_begin_round",
        "batch_prepare",
        "batch_directory_password_annotate",
        "batch_output_dir_resolver",
        "batch_skip_inside_outputs",
        "batch_collect_result",
        "batch_directory_password_remember",
        "batch_password_preflight",
        "batch_resource_profiles",
        "batch_report_task_finished",
        "batch_cleanup_task",
        "output_scan",
    ))
    output_snapshot_children = sum(total(label) for label in (
        "output_inventory_files",
        "output_inventory_path_check",
        "output_inventory_filter",
        "output_inventory_snapshot_fused",
        "output_file_head_facts",
        "output_snapshot_filter",
    ))
    planning_children = sum(total(label) for label in (
        "planning_group_tasks",
        "planning_plan_group",
    ))
    worker_protocol_children = sum(total(label) for label in (
        "worker_protocol_json_decode",
        "worker_protocol_drain_stdout",
        "worker_protocol_drain_stderr",
        "worker_protocol_progress_sample",
        "worker_protocol_emit_progress",
    ))
    planning_probe_children = sum(
        sum(values)
        for label, values in timings.items()
        if label.startswith("planning_")
    )
    runtime_outside_batch_children = sum(total(label) for label in (
        "pipeline_direct_scan",
        "pipeline_plan_task_isolated",
        "pipeline_nested_authorize",
        "output_take_scan_session",
        "pipeline_final_report",
        "extractor_close",
    ))
    return {
        "batch_overhead_excluding_extract": round(total("batch_execute") - total("extract_total"), 6),
        "batch_parent_python_residual": round(total("batch_execute") - batch_direct_children, 6),
        "batch_cleanup_invocations": len(timings.get("batch_cleanup_task", ())),
        "batch_cleanup_share": round(
            total("batch_cleanup_task") / total("batch_execute"), 6
        ) if total("batch_execute") else 0.0,
        "batch_cleanup_barrier_share": round(
            total("batch_cleanup_barrier") / total("batch_cleanup_task"), 6
        ) if total("batch_cleanup_task") else 0.0,
        "execute_ready_overhead_excluding_extract_verify": round(
            total("batch_execute") - total("extract_total") - total("verify_total"),
            6,
        ),
        "output_snapshot_python_residual": round(
            total("output_snapshot_from_inventory") - output_snapshot_children,
            6,
        ),
        "planning_parent_residual": round(total("input_planning") - planning_children, 6),
        "planning_analysis_residual": round(
            total("planning_analyzer_analyze") - total("planning_engine_analyze_path"),
            6,
        ),
        "pipeline_plan_task_unattributed": round(
            total("pipeline_plan_task_isolated") - planning_probe_children,
            6,
        ),
        "pipeline_runtime_outside_batch": round(
            total("pipeline_runtime_execute") - total("batch_execute"),
            6,
        ),
        "pipeline_runtime_outside_batch_residual": round(
            total("pipeline_runtime_execute") - total("batch_execute") - runtime_outside_batch_children,
            6,
        ),
        "pipeline_run_outside_batch": round(total("pipeline_run") - total("batch_execute"), 6),
        "pipeline_run_outer_residual": round(
            total("pipeline_run")
            - total("pipeline_runtime_create")
            - total("pipeline_runtime_execute")
            - total("pipeline_output_commit"),
            6,
        ),
        "worker_wait_residual": round(total("sevenzip_worker") - worker_protocol_children, 6),
    }


def _derived_timing_medians(request_timings: list[TimingMap]) -> dict[str, float]:
    derived = [_derived_timing(timings) for timings in request_timings]
    labels = sorted({label for row in derived for label in row})
    return {
        label: round(statistics.median(row[label] for row in derived), 6)
        for label in labels
    }


async def _run_profile_once(
    runner: PipelineEngine,
    archive: str,
    output: Path,
    output_base: Path,
    config: dict[str, Any],
    *,
    keep_output: bool,
):
    _cleanup_generated_output(output, output_base)
    config["output"]["root"] = str(output)
    started = time.perf_counter()
    try:
        response = await runner.run([os.path.abspath(archive)], direct=True)
        return time.perf_counter() - started, response.summary, _output_summary(output)
    finally:
        if not keep_output:
            _cleanup_generated_output(output, output_base)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument("output")
    parser.add_argument("--password", action="append", default=[])
    parser.add_argument("--generated-wrong-passwords", type=int, default=0)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--recursive-rounds", type=int, default=2)
    parser.add_argument("--keep-output", action="store_true")
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()

    passwords = [f"sunpack-wrong-{index:04d}" for index in range(max(0, args.generated_wrong_passwords))]
    passwords.extend(args.password)
    config = archive_pressure_config(passwords=passwords)
    config.setdefault("cli", {}).update({"quiet": True, "verbose": False})
    config["recursive_extract"] = {"mode": "fixed", "max_rounds": max(1, args.recursive_rounds)}
    output_base = Path(args.output).resolve()
    config["output"] = {"root": str(output_base)}

    async def run() -> int:
        runner = PipelineEngine(config)
        profiler = RequestRuntimeProfiler()
        profiler.install(runner)
        generated_outputs: list[Path] = []

        async def run_once(output: Path):
            generated_outputs.append(output)
            return await _run_profile_once(
                runner,
                args.archive,
                output,
                output_base,
                config,
                keep_output=args.keep_output,
            )

        elapsed_samples: list[float] = []
        summaries = []
        output_summaries = []
        try:
            async with runner:
                for index in range(max(0, args.warmup)):
                    await run_once(_generated_output_path(output_base, "warmup", index))
                profiler.enabled = True
                for index in range(max(1, args.repeat)):
                    elapsed, summary, output_summary = await run_once(
                        _generated_output_path(output_base, "run", index)
                    )
                    elapsed_samples.append(elapsed)
                    summaries.append(summary)
                    output_summaries.append(output_summary)
        finally:
            profiler.restore()
            if not args.keep_output:
                for output in generated_outputs:
                    _cleanup_generated_output(output, output_base)

        last_summary = summaries[-1]
        report = {
            "elapsed_seconds": [round(value, 6) for value in elapsed_samples],
            "elapsed_median_seconds": round(statistics.median(elapsed_samples), 6),
            "successful_runs": sum(summary.success_count > 0 for summary in summaries),
            "success_count": last_summary.success_count,
            "failed_tasks": [str(item) for item in last_summary.failed_tasks],
            "failures": [getattr(item, "to_dict", lambda: str(item))() for item in last_summary.failures],
            "timing_medians_seconds": _timing_medians(profiler.request_timings),
            "timing_seconds_by_run": [_timing_totals(timings) for timings in profiler.request_timings],
            "derived_timing_seconds_by_run": [_derived_timing(timings) for timings in profiler.request_timings],
            "derived_timing_medians_seconds": _derived_timing_medians(profiler.request_timings),
            "timing_calls": {
                label: [len(timings.get(label, [])) for timings in profiler.request_timings]
                for label in sorted({label for timings in profiler.request_timings for label in timings})
            },
            "output_summaries": output_summaries,
            "recursive_rounds": max(1, args.recursive_rounds),
            "outputs_cleaned": not args.keep_output,
            "output_base": str(output_base),
        }
        rendered = render_report(report_from_payload("extraction.large-archive-profile", report))
        print("PROFILE_JSON=" + rendered)
        if args.json_output:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(rendered, encoding="utf-8")
        return 0 if all(summary.success_count > 0 for summary in summaries) else 1

    return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
