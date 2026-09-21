"""Stress native worker parallelism with small archive jobs."""
from __future__ import annotations

import argparse
import csv
import json
import os
import psutil
import shutil
import statistics
import sys
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler, render_report, report_from_payload
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.support.resources import get_sevenzip_bridge_worker_path


SCENARIO = "extraction.worker-small-file-scheduling"


ADMISSION_CASES: dict[str, dict[str, Any]] = {
    "adaptive-baseline": {
        "description": "Adaptive throughput controller.",
        "blocker": "adaptive-controller",
        "adaptive_enabled": None,
        "initial_active_jobs": 0,
        "expected_max_active": None,
    },
    "fixed-capacity": {
        "description": "Adaptive control disabled and all configured worker slots enabled.",
        "blocker": "none-fixed-capacity",
        "adaptive_enabled": False,
        "initial_active_jobs": -1,
        "expected_max_active": None,
    },
}


def _parse_admission_cases(value: str, adaptive_enabled: bool) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for item in value.split(","):
        name = item.strip()
        if not name:
            continue
        if name not in ADMISSION_CASES:
            raise ValueError(f"unknown admission case {name!r}; choose from {', '.join(ADMISSION_CASES)}")
        case = dict(ADMISSION_CASES[name])
        case["name"] = name
        case["adaptive_enabled"] = adaptive_enabled if case["adaptive_enabled"] is None else case["adaptive_enabled"]
        selected.append(case)
    if not selected:
        raise ValueError("at least one admission case is required")
    return selected


def _parse_capacities(value: str) -> list[int]:
    capacities: list[int] = []
    for item in value.split(","):
        try:
            capacity = int(item.strip())
        except ValueError as exc:
            raise ValueError(f"invalid worker capacity {item!r}") from exc
        if capacity < 1 or capacity > 32:
            raise ValueError("worker capacities must be between 1 and 32")
        if capacity not in capacities:
            capacities.append(capacity)
    if not capacities:
        raise ValueError("at least one worker capacity is required")
    return capacities


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100.0
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction, 3)


def _create_corpus(root: Path, *, jobs: int, files_per_archive: int, file_size_bytes: int) -> dict[str, Any]:
    archives = root / "archives"
    archives.mkdir(parents=True, exist_ok=True)
    # Stored members make each task an extraction/scheduling measurement rather
    # than a compression benchmark, while still exercising many filesystem ops.
    payload = bytes((index * 31 + 17) % 251 for index in range(file_size_bytes))
    archive_paths: list[Path] = []
    for archive_index in range(jobs):
        archive = archives / f"small-{archive_index:04d}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as stream:
            for file_index in range(files_per_archive):
                stream.writestr(f"files/{file_index:02d}.bin", payload)
        archive_paths.append(archive)
    return {
        "archives": archive_paths,
        "jobs": jobs,
        "files_per_archive": files_per_archive,
        "file_size_bytes": file_size_bytes,
        "payload_bytes_per_job": files_per_archive * file_size_bytes,
        "input_bytes": sum(path.stat().st_size for path in archive_paths),
    }


def _job_payload(
    *,
    job_id: str,
    request_id: str,
    archive: Path,
    output_dir: Path,
    format_hint: str = "zip",
) -> str:
    return json.dumps(
        {
            "job_id": job_id,
            "request_id": request_id,
            "archive_path": str(archive),
            "part_paths": [str(archive)],
            "output_dir": str(output_dir),
            "password": "",
            "format_hint": format_hint,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _run_batch(
    *,
    workspace: BenchmarkWorkspace,
    worker_path: Path,
    corpus: dict[str, Any],
    capacity: int,
    client_count: int,
    timeout_seconds: float,
    sample_interval_ms: int,
    admission_case: dict[str, Any],
    label: str,
    submission_offsets_seconds: list[float] | None = None,
    idle_before_indices: dict[int, float] | None = None,
    worker_config_overrides: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    jobs = int(corpus["jobs"])
    jobs_per_client = jobs // client_count
    archive_paths: list[Path] = list(corpus["archives"])
    format_hints = list(corpus.get("format_hints") or [])
    if submission_offsets_seconds is not None and len(submission_offsets_seconds) != jobs:
        raise ValueError("submission_offsets_seconds must contain one offset per job")
    if format_hints and len(format_hints) != jobs:
        raise ValueError("corpus format_hints must contain one hint per job")
    submitted_at: dict[str, float] = {}
    events: list[dict[str, Any]] = []
    results: dict[str, dict[str, Any]] = {}
    failures: dict[str, str] = {}
    completed: set[str] = set()
    lock = threading.Lock()
    done = threading.Condition(lock)
    started_at = time.perf_counter()
    initial_active_jobs = capacity if admission_case["initial_active_jobs"] == -1 else int(admission_case["initial_active_jobs"])
    worker_config = {
        "thread_capacity": capacity,
        "adaptive_enabled": admission_case["adaptive_enabled"],
        "initial_active_jobs": initial_active_jobs,
        "sample_interval_ms": sample_interval_ms,
    }
    worker_config.update(worker_config_overrides or {})
    worker = _NativeWorkerProcess(
        str(worker_path),
        None,
        worker_config,
    )
    worker_process = psutil.Process(worker.process.pid) if worker.process is not None else None
    sampler = ProcessSampler(interval_seconds=0.01)
    sampler.start()

    def process_counters(process: psutil.Process | None) -> dict[str, float | int | None]:
        if process is None:
            return {"cpu_ms": None, "read_bytes": None, "write_bytes": None, "rss_mib": None}
        try:
            cpu = process.cpu_times()
            io = process.io_counters()
            rss = process.memory_info().rss / 1024 / 1024
            return {
                "cpu_ms": (float(cpu.user) + float(cpu.system)) * 1000.0,
                "read_bytes": int(io.read_bytes),
                "write_bytes": int(io.write_bytes),
                "rss_mib": round(rss, 3),
            }
        except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
            return {"cpu_ms": None, "read_bytes": None, "write_bytes": None, "rss_mib": None}

    resource_before = process_counters(worker_process)

    def make_callback(job_id: str) -> Any:
        def on_line(line: str) -> bool:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                return False
            if not isinstance(payload, dict):
                return False
            now = time.perf_counter()
            with done:
                if payload.get("type") == "native_event":
                    events.append({"received_at": now, "sequence": len(events), **payload})
                elif payload.get("type") == "result":
                    results[job_id] = payload
                has_finished = any(
                    event.get("job_id") == job_id and event.get("event") == "job_finished"
                    for event in events
                )
                if job_id in results and has_finished:
                    completed.add(job_id)
                    done.notify_all()
                    return True
            return False

        return on_line

    def on_timeout(job_id: str) -> Any:
        def record(message: str) -> None:
            with done:
                failures[job_id] = message
                completed.add(job_id)
                done.notify_all()

        return record

    try:
        # Submit one request at a time to ensure the fairness policy, not a
        # round-robin producer, determines the admission order.
        for client_index in range(client_count):
            request_id = f"request-{client_index:02d}"
            for sequence in range(jobs_per_client):
                index = client_index * jobs_per_client + sequence
                idle_seconds = float((idle_before_indices or {}).get(index, 0.0))
                if idle_seconds > 0.0:
                    idle_deadline = started_at + timeout_seconds
                    with done:
                        while len(completed) < index:
                            remaining = idle_deadline - time.perf_counter()
                            if remaining <= 0:
                                raise TimeoutError(
                                    f"{label} timed out waiting for the first {index} jobs to become idle"
                                )
                            done.wait(timeout=min(0.2, remaining))
                    time.sleep(idle_seconds)
                if submission_offsets_seconds is not None:
                    submit_at = started_at + float(submission_offsets_seconds[index])
                    remaining = submit_at - time.perf_counter()
                    if remaining > 0.0:
                        time.sleep(remaining)
                job_id = f"{label}-{request_id}-{sequence:04d}"
                submitted_at[job_id] = time.perf_counter()
                payload = _job_payload(
                    job_id=job_id,
                    request_id=request_id,
                    archive=archive_paths[index],
                    output_dir=workspace.outputs / label / job_id,
                    format_hint=(
                        str(format_hints[index])
                        if format_hints
                        else str(corpus.get("format_hint") or "zip")
                    ),
                )
                worker.submit_async(payload, job_id, on_line=make_callback(job_id), on_timeout=on_timeout(job_id))
        submission_finished_at = time.perf_counter()
        deadline = submission_finished_at + timeout_seconds
        with done:
            while len(completed) < jobs:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    missing = sorted(set(submitted_at) - completed)
                    raise TimeoutError(f"{label} timed out with {len(missing)} incomplete jobs")
                done.wait(timeout=min(0.2, remaining))
                if not worker.is_alive() and len(completed) < jobs:
                    raise RuntimeError(f"native worker exited with {jobs - len(completed)} incomplete jobs")
        finished_at = time.perf_counter()
    finally:
        controller_events = worker.controller_events()
        resource_after = process_counters(worker_process)
        sampler.stop()
        worker.close()

    resource_metrics = {
        "worker_cpu_ms": None
        if resource_before["cpu_ms"] is None or resource_after["cpu_ms"] is None
        else round(float(resource_after["cpu_ms"]) - float(resource_before["cpu_ms"]), 3),
        "worker_read_bytes": None
        if resource_before["read_bytes"] is None or resource_after["read_bytes"] is None
        else int(resource_after["read_bytes"]) - int(resource_before["read_bytes"]),
        "worker_write_bytes": None
        if resource_before["write_bytes"] is None or resource_after["write_bytes"] is None
        else int(resource_after["write_bytes"]) - int(resource_before["write_bytes"]),
        "worker_rss_peak_mib": round(max((sample.children_rss_mib for sample in sampler.samples), default=0.0), 3),
        "worker_cpu_core_utilization": None,
        "host_cpu_utilization": None,
    }
    elapsed = max(0.000001, finished_at - started_at)
    if resource_metrics["worker_cpu_ms"] is not None:
        cpu_seconds = float(resource_metrics["worker_cpu_ms"]) / 1000.0
        resource_metrics["worker_cpu_core_utilization"] = round(cpu_seconds / elapsed, 6)
        resource_metrics["host_cpu_utilization"] = round(cpu_seconds / (elapsed * max(1, os.cpu_count() or 1)), 6)

    summary = _summarize_batch(
        capacity=capacity,
        submitted_at=submitted_at,
        events=events,
        results=results,
        failures=failures,
        started_at=started_at,
        submission_finished_at=submission_finished_at,
        finished_at=finished_at,
        admission_case=admission_case,
        resource_metrics=resource_metrics,
        controller_events=controller_events,
        sample_interval_ms=sample_interval_ms,
    )
    trace = {
        "label": label,
        "submitted_at_seconds": submitted_at,
        "events": events,
        "results": results,
        "failures": failures,
        "controller_events": controller_events,
        "submission_offsets_seconds": submission_offsets_seconds,
        "idle_before_indices": idle_before_indices,
        "worker_config_overrides": worker_config_overrides,
    }
    return summary, trace


def _summarize_batch(
    *,
    capacity: int,
    submitted_at: dict[str, float],
    events: list[dict[str, Any]],
    results: dict[str, dict[str, Any]],
    failures: dict[str, str],
    started_at: float,
    submission_finished_at: float,
    finished_at: float,
    admission_case: dict[str, Any],
    resource_metrics: dict[str, Any],
    controller_events: list[dict[str, Any]],
    sample_interval_ms: int,
) -> dict[str, Any]:
    ordered_events = sorted(events, key=lambda event: (int(event.get("sequence", 0)), float(event["received_at"])))
    by_job: dict[str, dict[str, float]] = {}
    admissions: list[dict[str, Any]] = []
    peak_active = 0
    active_area = 0.0
    queued_underutilized_area = 0.0
    queued_jobs = 0
    previous_at = started_at
    active = 0
    for event in ordered_events:
        received_at = float(event["received_at"])
        active_area += max(0.0, received_at - previous_at) * active
        if queued_jobs > 0:
            queued_underutilized_area += max(0.0, received_at - previous_at) * max(0, capacity - active)
        previous_at = received_at
        event_name = str(event.get("event") or "")
        if event_name == "job_queued":
            queued_jobs += 1
            continue
        if event_name not in {"job_admitted", "job_started", "job_finished"}:
            continue
        if event_name in {"job_admitted", "job_finished"}:
            queued_jobs = max(0, queued_jobs - 1) if event_name == "job_admitted" else queued_jobs
        active = int(event.get("active_jobs", active) or 0)
        peak_active = max(peak_active, active)
        job_id = str(event.get("job_id") or "")
        by_job.setdefault(job_id, {})[event_name] = received_at
        if event_name == "job_admitted":
            admissions.append(event)
    active_area += max(0.0, finished_at - previous_at) * active
    if queued_jobs > 0:
        queued_underutilized_area += max(0.0, finished_at - previous_at) * max(0, capacity - active)

    queue_ms = [
        (times["job_admitted"] - submitted_at[job_id]) * 1000.0
        for job_id, times in by_job.items()
        if job_id in submitted_at and "job_admitted" in times
    ]
    service_ms = [
        (times["job_finished"] - times["job_started"]) * 1000.0
        for times in by_job.values()
        if "job_started" in times and "job_finished" in times
    ]
    elapsed = max(0.000001, finished_at - started_at)
    passed = sum(result.get("status") == "ok" for result in results.values())
    expected_jobs = len(submitted_at)
    expected_max_active = admission_case["expected_max_active"]
    if expected_max_active is None and admission_case["name"] != "adaptive-baseline":
        expected_max_active = capacity
    first_enqueue_at = min(
        (float(event["received_at"]) for event in ordered_events if event.get("event") == "job_queued"),
        default=None,
    )
    lifecycle_decisions = {
        "activity_started",
        "activity_ended",
        "segment_started",
        "segment_interrupted",
    }
    non_empty_controller_events = [
        event for event in controller_events
        if str(event.get("decision") or "none") != "none"
    ]
    adjustment_events = [
        event for event in non_empty_controller_events
        if str(event.get("decision") or "none") not in lifecycle_decisions
    ]
    lifecycle_events = [
        event for event in non_empty_controller_events
        if str(event.get("decision") or "none") in lifecycle_decisions
    ]
    controller_offsets_ms = [
        max(0.0, (float(event["received_at"]) - first_enqueue_at) * 1000.0)
        for event in adjustment_events
        if first_enqueue_at is not None and "received_at" in event
    ]
    controller_limits = [
        int(event["active_limit"])
        for event in controller_events
        if event.get("active_limit") is not None
    ]
    controller_decisions = [
        str(event.get("decision") or "none")
        for event in adjustment_events
        if event.get("decision")
    ]
    return {
        "admission_case": admission_case["name"],
        "admission_blocker": admission_case["blocker"],
        "admission_description": admission_case["description"],
        "expected_max_active_jobs": expected_max_active,
        "capacity": capacity,
        "sample_interval_ms": sample_interval_ms,
        "job_count": expected_jobs,
        "passed_jobs": passed,
        "failed_jobs": expected_jobs - passed,
        "timeout_or_worker_failures": len(failures),
        "all_passed": passed == expected_jobs and not failures,
        "wall_ms": round(elapsed * 1000.0, 3),
        "submission_ms": round((submission_finished_at - started_at) * 1000.0, 3),
        "throughput_jobs_per_second": round(expected_jobs / elapsed, 3),
        "observed_peak_active_jobs": peak_active,
        "active_time_ms": round(active_area * 1000.0, 3),
        "thread_capacity_utilization": round(active_area / (elapsed * capacity), 6),
        "queued_underutilized_thread_ms": round(queued_underutilized_area * 1000.0, 3),
        "queued_underutilization_ratio": round(queued_underutilized_area / (elapsed * capacity), 6),
        "queue_latency_p50_ms": _percentile(queue_ms, 50),
        "queue_latency_p95_ms": _percentile(queue_ms, 95),
        "service_p50_ms": _percentile(service_ms, 50),
        "service_p95_ms": _percentile(service_ms, 95),
        "admitted_jobs": len(admissions),
        "controller_sample_count": len(controller_events),
        "controller_adjustment_count": len(adjustment_events),
        "controller_lifecycle_event_count": len(lifecycle_events),
        "controller_activity_session_count": max(
            (int(event.get("activity_session", 0) or 0) for event in controller_events),
            default=0,
        ),
        "controller_saturated_segment_count": max(
            (int(event.get("saturated_segment", 0) or 0) for event in controller_events),
            default=0,
        ),
        "controller_warm_start_count": sum(
            bool(event.get("warm_start_used"))
            for event in controller_events
            if str(event.get("decision") or "") == "activity_started"
        ),
        "controller_first_adjustment_after_enqueue_ms": min(controller_offsets_ms) if controller_offsets_ms else None,
        "controller_last_adjustment_after_enqueue_ms": max(controller_offsets_ms) if controller_offsets_ms else None,
        "controller_min_active_limit": min(controller_limits, default=None),
        "controller_peak_active_limit": max(controller_limits, default=None),
        "controller_final_active_limit": controller_limits[-1] if controller_limits else None,
        "controller_decisions": controller_decisions,
        "controller_throughput_modes": [
            str(event.get("throughput_mode") or "none") for event in controller_events
        ],
        **resource_metrics,
    }


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_case: dict[str, dict[int, list[dict[str, Any]]]] = {}
    for row in rows:
        by_case.setdefault(str(row["admission_case"]), {}).setdefault(int(row["capacity"]), []).append(row)
    metrics = (
        "throughput_jobs_per_second",
        "thread_capacity_utilization",
        "queued_underutilization_ratio",
        "queue_latency_p95_ms",
        "service_p95_ms",
        "observed_peak_active_jobs",
        "controller_adjustment_count",
        "controller_first_adjustment_after_enqueue_ms",
        "controller_peak_active_limit",
        "worker_cpu_core_utilization",
        "host_cpu_utilization",
        "worker_rss_peak_mib",
    )
    return {
        "all_passed": bool(rows) and all(bool(row["all_passed"]) for row in rows),
        "runs": len(rows),
        "by_case": {
            case: {
                "blocker": next(
                    sample["admission_blocker"]
                    for case_samples in samples_by_capacity.values()
                    for sample in case_samples
                ),
                "by_capacity": {
                    str(capacity): {
                        "runs": len(samples),
                        "all_passed": all(bool(sample["all_passed"]) for sample in samples),
                        **{
                            f"median_{metric}": round(statistics.median([float(sample[metric]) for sample in samples]), 6)
                            for metric in metrics
                            if all(sample.get(metric) is not None for sample in samples)
                        },
                    }
                    for capacity, samples in sorted(samples_by_capacity.items())
                },
            }
            for case, samples_by_capacity in sorted(by_case.items())
        },
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    columns = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark native worker throughput control for many small ZIP jobs.")
    parser.add_argument("--jobs", type=int, default=256)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--capacities", default="1,2,4,8", help="Comma-separated native worker thread capacities.")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--files-per-archive", type=int, default=8)
    parser.add_argument("--file-size-bytes", type=int, default=8192)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument(
        "--sample-interval-ms",
        type=int,
        default=500,
        help="Native adaptive-controller sample interval (100-5000 ms).",
    )
    parser.add_argument("--adaptive-enabled", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument(
        "--admission-cases",
        default=",".join(ADMISSION_CASES),
        help="Comma-separated admission cases: " + ", ".join(ADMISSION_CASES),
    )
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    try:
        capacities = _parse_capacities(args.capacities)
        admission_cases = _parse_admission_cases(args.admission_cases, bool(args.adaptive_enabled))
    except ValueError as exc:
        parser.error(str(exc))
    if args.jobs < 1 or args.clients < 1 or args.jobs % args.clients:
        parser.error("--jobs must be positive and evenly divisible by --clients")
    if args.runs < 1 or args.warmups < 0 or args.files_per_archive < 1 or args.file_size_bytes < 1:
        parser.error("runs, files per archive, and file size must be positive; warmups must be non-negative")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    if not 100 <= args.sample_interval_ms <= 5000:
        parser.error("--sample-interval-ms must be between 100 and 5000")
    try:
        worker_path = Path(get_sevenzip_bridge_worker_path()).resolve()
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if not worker_path.is_file():
        parser.error("native worker is unavailable")

    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        corpus = _create_corpus(
            workspace.corpus,
            jobs=args.jobs,
            files_per_archive=args.files_per_archive,
            file_size_bytes=args.file_size_bytes,
        )
        rows: list[dict[str, Any]] = []
        trace_paths: list[str] = []
        for admission_case in admission_cases:
            for capacity in capacities:
                for run in range(args.warmups + args.runs):
                    measured = run >= args.warmups
                    label = f"{admission_case['name']}-capacity-{capacity}-{'run' if measured else 'warmup'}-{run}"
                    print(f"{label}: submitting {args.jobs} small-file jobs", flush=True)
                    row, trace = _run_batch(
                        workspace=workspace,
                        worker_path=worker_path,
                            corpus=corpus,
                        capacity=capacity,
                        client_count=args.clients,
                        timeout_seconds=args.timeout_seconds,
                        sample_interval_ms=args.sample_interval_ms,
                        admission_case=admission_case,
                        label=label,
                    )
                    if measured:
                        row["run"] = run - args.warmups
                        row["adaptive_enabled"] = admission_case["adaptive_enabled"]
                        rows.append(row)
                        trace_path = workspace.write_result_json(f"traces/{label}.json", trace)
                        trace_paths.append(str(trace_path))
                    shutil.rmtree(workspace.outputs / label, ignore_errors=True)
                    print(
                        f"  throughput={row['throughput_jobs_per_second']} jobs/s "
                        f"utilization={row['thread_capacity_utilization']:.3f} "
                        f"queued_underutil={row['queued_underutilization_ratio']:.3f} "
                        f"peak_active={row['observed_peak_active_jobs']} passed={row['all_passed']}",
                        flush=True,
                    )
        summary = _aggregate(rows)
        report = {
            "parameters": {
                "jobs": args.jobs,
                "clients": args.clients,
                "capacities": capacities,
                "admission_cases": [case["name"] for case in admission_cases],
                "runs": args.runs,
                "warmups": args.warmups,
                "files_per_archive": args.files_per_archive,
                "file_size_bytes": args.file_size_bytes,
                "adaptive_enabled": bool(args.adaptive_enabled),
                "sample_interval_ms": args.sample_interval_ms,
            },
            "environment": {
                "worker_path": str(worker_path),
                "cpu_count": os.cpu_count(),
                "python": sys.version,
            },
            "corpus": {key: value for key, value in corpus.items() if key != "archives"},
            "results": rows,
            "summary": summary,
            "artifacts": {"result_dir": str(workspace.result_dir), "traces": trace_paths},
        }
        rendered = render_report(report_from_payload(SCENARIO, report))
        workspace.write_result_text("report.json", rendered)
        _write_csv(workspace.result_dir / "results.csv", rows)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
