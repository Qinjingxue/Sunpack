"""Event-trace experiments for passive native CPU-budget derating."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from benchmarks.scenarios.worker_resource_pressure import _create_archive, _copy_jobs
from benchmarks.scenarios.worker_small_file_scheduling import _run_batch
from sunpack.support.resources import get_sevenzip_bridge_worker_path, get_7z_path


SCENARIO = "extraction.worker-throughput-controller"
MI = 1 << 20
ADAPTIVE_CASE = {
    "name": "passive-budget",
    "description": "Passive throughput-based CPU-budget derating.",
    "blocker": "passive-budget-controller",
    "adaptive_enabled": True,
    "expected_max_active": None,
}
FIXED_CASE = {
    "name": "fixed-budget",
    "description": "Fixed CPU-credit budget used to build the oracle curve.",
    "blocker": "none-fixed-budget",
    "adaptive_enabled": False,
    "expected_max_active": None,
}


def _csv_ints(value: str) -> list[int]:
    result: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        number = int(item)
        if number < 1 or number > 32:
            raise ValueError("capacities must be between 1 and 32")
        if number not in result:
            result.append(number)
    if not result:
        raise ValueError("at least one capacity is required")
    return result


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100.0
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


class _Pressure:
    def __init__(self, mode: str, root: Path, *, workers: int = 1) -> None:
        self.mode = mode
        self.root = root
        self.workers = max(1, workers)
        self.processes: list[subprocess.Popen[str]] = []
        self._lock = threading.Lock()
        self.started_at: float | None = None
        self.stopped_at: float | None = None

    def start(self) -> None:
        with self._lock:
            if self.processes:
                return
            if self.mode == "cpu":
                command = "$x=0.1; while($true){$x=[Math]::Sqrt($x+1.0)}"
                count = self.workers
            elif self.mode == "io":
                path = str((self.root / "io-pressure.bin").resolve()).replace("'", "''")
                command = (
                    f"$p='{path}'; $b=New-Object byte[] (4MB); "
                    "while($true){[IO.File]::WriteAllBytes($p,$b); "
                    "$s=[IO.File]::OpenRead($p); $r=New-Object byte[] (4MB); "
                    "while($s.Read($r,0,$r.Length) -gt 0){}; $s.Dispose()}"
                )
                count = 1
            else:
                raise ValueError(f"unknown pressure mode {self.mode}")
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            for _ in range(count):
                self.processes.append(
                    subprocess.Popen(
                        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=flags,
                        text=True,
                    )
                )
            self.started_at = time.perf_counter()

    def stop(self) -> None:
        with self._lock:
            processes = self.processes
            self.processes = []
            self.stopped_at = time.perf_counter() if processes else self.stopped_at
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)


def _corpus(
    workspace: BenchmarkWorkspace,
    *,
    mode: str,
    jobs: int,
    source_mib: int,
    dictionary_mib: int,
    seven_zip: Path,
) -> dict[str, Any]:
    (workspace.corpus / mode).mkdir(parents=True, exist_ok=True)
    case = _create_archive(
        workspace.corpus / mode,
        mode,
        source_mib=source_mib,
        dictionary_mib=dictionary_mib,
        seven_zip=seven_zip,
    )
    archives = _copy_jobs(workspace.corpus / mode / "jobs", case, jobs)
    return {
        "archives": archives,
        "jobs": jobs,
        "format_hint": "7z",
        "format_hints": ["7z"] * jobs,
        "payload_bytes_per_job": int(case["payload_bytes"]),
        "case": {key: value for key, value in case.items() if key != "template"},
    }


def _controller_config(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "observation_window_seconds": args.observation_window_seconds,
        "throughput_change_ratio": args.throughput_change_ratio,
        "resource_diagnostics_enabled": True,
        "measurement_diagnostics_enabled": args.measurement_diagnostics,
    }

def _oracle_summary(rows: list[dict[str, Any]], payload_bytes: int) -> dict[str, Any]:
    grouped: dict[str, dict[int, list[dict[str, Any]]]] = {}
    for row in rows:
        grouped.setdefault(str(row["workload"]), {}).setdefault(int(row["capacity"]), []).append(row)
    result: dict[str, Any] = {}
    for workload, by_capacity in grouped.items():
        medians = {
            str(capacity): statistics.median(float(item["throughput_bytes_per_second"]) for item in samples)
            for capacity, samples in by_capacity.items()
        }
        maximum = max(medians.values())
        plateau = [int(capacity) for capacity, rate in medians.items() if rate >= maximum * 0.98]
        oracle_limit = min(plateau)
        result[workload] = {
            "throughput_bytes_per_second_by_capacity": medians,
            "maximum_throughput_bytes_per_second": maximum,
            "plateau_98_percent": sorted(plateau),
            "oracle_limit": oracle_limit,
            "oracle_throughput_bytes_per_second": medians[str(oracle_limit)],
            "payload_bytes_per_job": payload_bytes,
        }
    return result


def _trace_metrics(trace: dict[str, Any], *, oracle: dict[str, Any], payload_bytes: int) -> dict[str, Any]:
    events = list(trace.get("controller_events") or [])
    decisions = [str(event.get("decision") or "none") for event in events]
    budgets = [
        int(event["effective_cpu_budget"])
        for event in events
        if event.get("effective_cpu_budget") is not None
    ]
    wall_seconds = max(0.000001, float(trace.get("summary_wall_seconds", 0.0) or 0.0))
    throughput = float(trace.get("summary_throughput_bytes_per_second", 0.0) or 0.0)
    oracle_rate = float(oracle["oracle_throughput_bytes_per_second"])
    return {
        "controller_decisions": decisions,
        "budget_reduced_count": sum(decision == "budget_reduced" for decision in decisions),
        "budget_restored_count": sum(decision == "budget_restored" for decision in decisions),
        "baseline_established_count": sum(decision == "baseline_established" for decision in decisions),
        "minimum_effective_cpu_budget": min(budgets) if budgets else None,
        "maximum_effective_cpu_budget": max(budgets) if budgets else None,
        "cpu_budget_change_count": sum(a != b for a, b in zip(budgets, budgets[1:])),
        "oracle_efficiency": round(throughput / oracle_rate, 6) if oracle_rate > 0 else None,
        "cumulative_regret_bytes": round(max(0.0, oracle_rate - throughput) * wall_seconds, 3),
        "payload_bytes_per_job": payload_bytes,
    }

def _row(
    summary: dict[str, Any],
    trace: dict[str, Any],
    *,
    workload: str,
    controller: str,
    capacity: int,
    run: int,
    payload_bytes: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    wall_seconds = float(summary["wall_ms"]) / 1000.0
    throughput = payload_bytes * int(summary["passed_jobs"]) / max(0.000001, wall_seconds)
    summary_row = {
        "workload": workload,
        "controller": controller,
        "capacity": capacity,
        "run": run,
        "passed_jobs": summary["passed_jobs"],
        "all_passed": summary["all_passed"],
        "wall_seconds": round(wall_seconds, 6),
        "throughput_bytes_per_second": round(throughput, 3),
        "throughput_mib_per_second": round(throughput / MI, 3),
        "controller_sample_count": summary["controller_sample_count"],
        "worker_rss_peak_mib": summary["worker_rss_peak_mib"],
        "worker_cpu_core_utilization": summary["worker_cpu_core_utilization"],
    }
    trace_payload = dict(trace)
    trace_payload["summary_wall_seconds"] = wall_seconds
    trace_payload["summary_throughput_bytes_per_second"] = throughput
    trace_payload["workload"] = workload
    trace_payload["controller"] = controller
    trace_payload["capacity"] = capacity
    trace_payload["run"] = run
    return summary_row, trace_payload


def _run_adaptive(
    *,
    workspace: BenchmarkWorkspace,
    worker_path: Path,
    corpus: dict[str, Any],
    workload: str,
    capacity: int,
    run: int,
    args: argparse.Namespace,
    pressure: _Pressure | None = None,
    pressure_name: str = "none",
) -> tuple[dict[str, Any], dict[str, Any]]:
    timers: list[threading.Timer] = []
    pressure_started = False
    pressure_stopped = False

    def start_pressure() -> None:
        nonlocal pressure_started
        if pressure is not None:
            pressure.start()
            pressure_started = True

    def stop_pressure() -> None:
        nonlocal pressure_stopped
        if pressure is not None:
            pressure.stop()
            pressure_stopped = True

    def hook(event: dict[str, Any]) -> None:
        if (
            pressure is not None
            and str(event.get("decision") or "") == "activity_started"
            and not pressure_started
        ):
            start_timer = threading.Timer(args.disturbance_delay_seconds, start_pressure)
            start_timer.daemon = True
            start_timer.start()
            timers.append(start_timer)
            stop_timer = threading.Timer(
                args.disturbance_delay_seconds + args.disturbance_seconds,
                stop_pressure,
            )
            stop_timer.daemon = True
            stop_timer.start()
            timers.append(stop_timer)

    try:
        summary, trace = _run_batch(
            workspace=workspace,
            worker_path=worker_path,
            corpus=corpus,
            capacity=capacity,
            client_count=1,
            timeout_seconds=args.timeout_seconds,
            sample_interval_ms=args.sample_interval_ms,
            admission_case=dict(ADAPTIVE_CASE),
            label=f"{workload}-passive-{pressure_name}-capacity-{capacity}-run-{run}",
            worker_config_overrides=_controller_config(args),
            controller_event_hook=hook,
        )
    finally:
        for timer in timers:
            timer.cancel()
        if pressure is not None:
            pressure.stop()
            pressure_stopped = pressure.stopped_at is not None

    summary_row, trace_payload = _row(
        summary,
        trace,
        workload=workload,
        controller=f"passive-{pressure_name}",
        capacity=capacity,
        run=run,
        payload_bytes=int(corpus["payload_bytes_per_job"]),
    )
    trace_payload["injection"] = {
        "pressure_name": pressure_name,
        "pressure_started": pressure_started,
        "pressure_stopped": pressure_stopped,
        "pressure_duration_seconds": (
            None
            if pressure is None or pressure.started_at is None or pressure.stopped_at is None
            else round(max(0.0, pressure.stopped_at - pressure.started_at), 6)
        ),
    }
    return summary_row, trace_payload

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run fixed-budget, passive-derating, and disturbance experiments.")
    parser.add_argument("--workloads", default="cpu,io")
    parser.add_argument("--capacities", default="1,2,4,8,16")
    parser.add_argument("--jobs", type=int, default=32)
    parser.add_argument("--oracle-runs", type=int, default=5)
    parser.add_argument("--adaptive-runs", type=int, default=3)
    parser.add_argument("--source-mib", type=int, default=64)
    parser.add_argument("--io-source-mib", type=int, default=64)
    parser.add_argument("--dictionary-mib", type=int, default=64)
    parser.add_argument("--sample-interval-ms", type=int, default=250)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--disturbance-delay-seconds", type=float, default=1.0)
    parser.add_argument("--disturbance-seconds", type=float, default=10.0)
    parser.add_argument("--observation-window-seconds", type=float, default=1.0)
    parser.add_argument("--throughput-change-ratio", type=float, default=0.40)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    parser.add_argument(
        "--stationary-only",
        action="store_true",
        help="Run the fixed oracle and stationary passive-controller cases only; omit scheduled pressure.",
    )
    parser.add_argument(
        "--fixed-diagnostics",
        action="store_true",
        help="Enable native controller diagnostics for fixed-capacity runs so window samples are traced.",
    )
    parser.add_argument(
        "--measurement-diagnostics",
        action="store_true",
        help="Emit native controller window measurements for fixed and adaptive runs.",
    )
    parser.add_argument(
        "--oracle-only",
        action="store_true",
        help="Run only the fixed-capacity oracle sweep and omit adaptive/disturbance cases.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        workloads = [item.strip().lower() for item in args.workloads.split(",") if item.strip()]
        capacities = _csv_ints(args.capacities)
    except ValueError as exc:
        _parser().error(str(exc))
    if set(workloads) - {"cpu", "io"} or not workloads:
        _parser().error("workloads must be a non-empty subset of cpu,io")
    if (
        args.jobs < max(capacities)
        or args.oracle_runs < 1
        or args.adaptive_runs < 1
    ):
        _parser().error("jobs must cover the largest capacity and run counts must be positive")
    if args.sample_interval_ms < 100 or args.timeout_seconds <= 0:
        _parser().error("sample interval must be at least 100 ms and timeout must be positive")
    worker_path = Path(get_sevenzip_bridge_worker_path()).resolve()
    seven_zip = Path(get_7z_path()).resolve()
    if not worker_path.is_file() or not seven_zip.is_file():
        _parser().error("native worker or 7z.exe is unavailable")

    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        corpora = {
            workload: _corpus(
                workspace,
                mode=workload,
                jobs=args.jobs,
                source_mib=args.source_mib if workload == "cpu" else args.io_source_mib,
                dictionary_mib=args.dictionary_mib if workload == "cpu" else 0,
                seven_zip=seven_zip,
            )
            for workload in workloads
        }
        rows: list[dict[str, Any]] = []
        trace_paths: list[str] = []
        oracle_rows: list[dict[str, Any]] = []
        for workload in workloads:
            corpus = corpora[workload]
            for run in range(args.oracle_runs):
                order = capacities if run % 2 == 0 else list(reversed(capacities))
                for capacity in order:
                    print(f"oracle {workload} fixed capacity={capacity} run={run}", flush=True)
                    summary, trace = _run_batch(
                        workspace=workspace,
                        worker_path=worker_path,
                        corpus=corpus,
                        capacity=capacity,
                        client_count=1,
                        timeout_seconds=args.timeout_seconds,
                        sample_interval_ms=args.sample_interval_ms,
                        admission_case=dict(FIXED_CASE),
                        label=f"oracle-{workload}-fixed-capacity-{capacity}-run-{run}",
                        worker_config_overrides={
                            "resource_diagnostics_enabled": args.fixed_diagnostics,
                            "measurement_diagnostics_enabled": args.measurement_diagnostics,
                        },
                    )
                    row, trace_payload = _row(
                        summary,
                        trace,
                        workload=workload,
                        controller="fixed",
                        capacity=capacity,
                        run=run,
                        payload_bytes=int(corpus["payload_bytes_per_job"]),
                    )
                    rows.append(row)
                    oracle_rows.append(row)
                    if not summary["all_passed"]:
                        print(f"  failed: {summary.get('failures')}", flush=True)
                    trace_paths.append(str(workspace.write_result_json(
                        f"traces/{workload}-oracle-{capacity}-run-{run}.json", trace_payload
                    )))
                    shutil.rmtree(workspace.outputs / trace["label"], ignore_errors=True)
        oracle = _oracle_summary(oracle_rows, int(next(iter(corpora.values()))["payload_bytes_per_job"]))

        if args.oracle_only:
            report = {
                "parameters": vars(args) | {"workloads": workloads, "capacities": capacities},
                "environment": {
                    "worker_path": str(worker_path),
                    "seven_zip_path": str(seven_zip),
                    "cpu_count": os.cpu_count(),
                    "python": sys.version,
                },
                "corpus": {workload: value["case"] for workload, value in corpora.items()},
                "oracle": oracle,
                "results": rows,
                "summary": {
                    "rows": len(rows),
                    "all_passed": bool(rows) and all(bool(row.get("all_passed")) for row in rows),
                    "controller_implementation": {
                        "window": "1-second written-throughput observation by default",
                        "threshold": "40% change from saturated stable baseline",
                        "policy": "passive CPU-budget derating/restoration only",
                    },
                },
                "artifacts": {"result_dir": str(workspace.result_dir), "traces": trace_paths},
            }
            rendered = render_report(report_from_payload(SCENARIO, report))
            workspace.write_result_text("report.json", rendered)
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(rendered, encoding="utf-8")
            print(rendered)
            return 0 if report["summary"]["all_passed"] else 1

        for workload in workloads:
            corpus = corpora[workload]
            target_capacity = max(capacities)
            for run in range(args.adaptive_runs):
                print(f"adaptive {workload} stationary capacity={target_capacity} run={run}", flush=True)
                summary, trace = _run_batch(
                    workspace=workspace,
                    worker_path=worker_path,
                    corpus=corpus,
                    capacity=target_capacity,
                    client_count=1,
                    timeout_seconds=args.timeout_seconds,
                    sample_interval_ms=args.sample_interval_ms,
                    admission_case=dict(ADAPTIVE_CASE),
                    label=f"adaptive-{workload}-stationary-capacity-{target_capacity}-run-{run}",
                    worker_config_overrides=_controller_config(args),
                )
                row, trace_payload = _row(
                    summary,
                    trace,
                    workload=workload,
                    controller="adaptive-stationary",
                    capacity=target_capacity,
                    run=run,
                    payload_bytes=int(corpus["payload_bytes_per_job"]),
                )
                row.update(_trace_metrics(trace_payload, oracle=oracle[workload], payload_bytes=int(corpus["payload_bytes_per_job"])))
                rows.append(row)
                trace_paths.append(str(workspace.write_result_json(
                    f"traces/{workload}-adaptive-stationary-{run}.json", trace_payload
                )))
                shutil.rmtree(workspace.outputs / trace["label"], ignore_errors=True)

            if args.stationary_only:
                continue

            for disturbance in ("cpu", "io"):
                pressure = _Pressure(disturbance, workspace.corpus, workers=max(1, min(8, (os.cpu_count() or 2) // 4)))
                for run in range(max(1, min(2, args.adaptive_runs))):
                    print(f"adaptive {workload} scheduled-{disturbance} run={run}", flush=True)
                    summary_row, trace_payload = _run_adaptive(
                        workspace=workspace,
                        worker_path=worker_path,
                        corpus=corpus,
                        workload=workload,
                        capacity=target_capacity,
                        run=run,
                        args=args,
                        pressure=pressure,
                        pressure_name=disturbance,
                    )
                    summary_row.update(_trace_metrics(trace_payload, oracle=oracle[workload], payload_bytes=int(corpus["payload_bytes_per_job"])))
                    rows.append(summary_row)
                    trace_paths.append(str(workspace.write_result_json(
                        f"traces/{workload}-scheduled-{disturbance}-{run}.json", trace_payload
                    )))
                    shutil.rmtree(workspace.outputs / trace_payload["label"], ignore_errors=True)

        report = {
            "parameters": vars(args) | {"workloads": workloads, "capacities": capacities},
            "environment": {
                "worker_path": str(worker_path),
                "seven_zip_path": str(seven_zip),
                "cpu_count": os.cpu_count(),
                "python": sys.version,
            },
            "corpus": {workload: value["case"] for workload, value in corpora.items()},
            "oracle": oracle,
            "results": rows,
            "summary": {
                "rows": len(rows),
                "all_passed": bool(rows) and all(bool(row.get("all_passed")) for row in rows),
                "controller_implementation": {
                        "window": "1-second written-throughput observation by default",
                        "threshold": "20% change from current stable baseline",
                        "policy": "passive CPU-budget derating/restoration only",
                    },
            },
            "artifacts": {"result_dir": str(workspace.result_dir), "traces": trace_paths},
        }
        rendered = render_report(report_from_payload(SCENARIO, report))
        workspace.write_result_text("report.json", rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0 if report["summary"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
