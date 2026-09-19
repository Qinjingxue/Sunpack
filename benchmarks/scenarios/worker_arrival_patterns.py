"""Calibrate one persistent native worker against CLI and watch arrival patterns."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from benchmarks.scenarios.worker_initial_concurrency_matrix import (
    ARCHIVE_VARIANTS,
    _automatic_capacity,
    _create_variant,
    _write_payloads,
)
from benchmarks.scenarios.worker_small_file_scheduling import ADMISSION_CASES, _run_batch
from sunpack.support.resources import get_sevenzip_bridge_worker_path
from tests.helpers.tool_config import get_7z_cli_dll_path


SCENARIO = "extraction.worker-arrival-patterns"
ARRIVAL_PATTERNS = ("cli-bulk", "watch-clustered", "watch-discrete")


def _parse_numbers(value: str, *, integer: bool) -> list[int] | list[float]:
    values: list[int] | list[float] = []
    for raw in value.split(","):
        parsed: int | float = int(raw) if integer else float(raw)
        if parsed < 0 or (integer and parsed < 1):
            raise ValueError("calibration values must be non-negative")
        if parsed not in values:
            values.append(parsed)
    if not values:
        raise ValueError("at least one calibration value is required")
    return values


def _arrival_controls(
    pattern: str,
    *,
    jobs: int,
    burst_size: int,
    idle_gap_seconds: float,
    discrete_interval_seconds: float,
) -> dict[str, Any]:
    if pattern == "cli-bulk":
        return {"scheduled_idle_seconds": 0.0}
    if pattern == "watch-clustered":
        boundaries = range(burst_size, jobs, burst_size)
        idle_before_indices = {index: idle_gap_seconds for index in boundaries}
        return {
            "idle_before_indices": idle_before_indices,
            "scheduled_idle_seconds": sum(idle_before_indices.values()),
        }
    if pattern == "watch-discrete":
        return {
            "submission_offsets_seconds": [
                round(index * discrete_interval_seconds, 9) for index in range(jobs)
            ],
            "scheduled_idle_seconds": 0.0,
        }
    raise ValueError(f"unknown arrival pattern {pattern!r}")


def _mixed_corpus(
    root: Path,
    *,
    jobs: int,
    file_count: int,
    file_size_bytes: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = root / "source"
    payload_bytes = _write_payloads(
        source,
        file_count=file_count,
        file_size_bytes=file_size_bytes,
    )
    variants = [
        _create_variant(root, source, name, cpu_weight_mode="unit")
        for name in ARCHIVE_VARIANTS
    ]
    selected = [variants[index % len(variants)] for index in range(jobs)]
    return (
        {
            "jobs": jobs,
            "archives": [item["path"] for item in selected],
            "format_hints": [item["format_hint"] for item in selected],
            "payload_bytes_per_job": payload_bytes,
            "archive_variants": [item["variant"] for item in selected],
        },
        variants,
    )


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[tuple[float, int], list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(
            (float(row["warm_start_decay_seconds"]), int(row["warm_start_confirmations"])),
            [],
        ).append(row)
    candidates: dict[str, Any] = {}
    for (decay, confirmations), samples in sorted(grouped.items()):
        processing_wall = [
            max(0.001, float(sample["wall_ms"]) - float(sample["scheduled_idle_seconds"]) * 1000.0)
            for sample in samples
        ]
        key = f"decay-{decay:g}-confirmations-{confirmations}"
        candidates[key] = {
            "warm_start_decay_seconds": decay,
            "warm_start_confirmations": confirmations,
            "runs": len(samples),
            "all_passed": all(bool(sample["all_passed"]) for sample in samples),
            "median_processing_wall_ms": round(statistics.median(processing_wall), 3),
            "median_queue_latency_p95_ms": round(statistics.median(
                float(sample["queue_latency_p95_ms"] or 0.0) for sample in samples
            ), 3),
            "median_rss_peak_mib": round(statistics.median(
                float(sample["worker_rss_peak_mib"] or 0.0) for sample in samples
            ), 3),
            "activity_sessions": [int(sample["controller_activity_session_count"]) for sample in samples],
            "saturated_segments": [int(sample["controller_saturated_segment_count"]) for sample in samples],
            "warm_starts": [int(sample["controller_warm_start_count"]) for sample in samples],
        }
    passing = [key for key, value in candidates.items() if value["all_passed"]]
    recommended = min(
        passing,
        key=lambda key: (
            candidates[key]["median_processing_wall_ms"],
            candidates[key]["median_queue_latency_p95_ms"],
            candidates[key]["median_rss_peak_mib"],
        ),
        default=None,
    )
    return {
        "all_passed": bool(rows) and all(bool(row["all_passed"]) for row in rows),
        "recommended_candidate": recommended,
        "candidates": candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure adaptive scheduling with bulk, clustered, and discrete mixed-format arrivals."
    )
    parser.add_argument("--patterns", default=",".join(ARRIVAL_PATTERNS))
    parser.add_argument("--warm-start-decay-seconds", default="0,5,15,30")
    parser.add_argument("--warm-start-confirmations", default="1,2")
    parser.add_argument("--jobs", type=int, default=72)
    parser.add_argument("--burst-size", type=int, default=24)
    parser.add_argument("--idle-gap-seconds", type=float, default=1.0)
    parser.add_argument("--discrete-interval-seconds", type=float, default=0.15)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--files-per-archive", type=int, default=16)
    parser.add_argument("--file-size-bytes", type=int, default=262144)
    parser.add_argument("--sample-interval-ms", type=int, default=100)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--capacity", type=int, default=0)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    patterns = [item.strip() for item in args.patterns.split(",") if item.strip()]
    unknown = sorted(set(patterns) - set(ARRIVAL_PATTERNS))
    if unknown:
        parser.error(f"unknown patterns: {', '.join(unknown)}")
    if args.jobs < 1 or args.burst_size < 1 or args.runs < 1:
        parser.error("jobs, burst size, and runs must be positive")
    if args.jobs % len(ARCHIVE_VARIANTS):
        parser.error(f"--jobs must be divisible by {len(ARCHIVE_VARIANTS)} for a balanced format matrix")
    if args.idle_gap_seconds < 0 or args.discrete_interval_seconds < 0:
        parser.error("arrival intervals must be non-negative")
    try:
        decays = [float(value) for value in _parse_numbers(args.warm_start_decay_seconds, integer=False)]
        confirmations = [int(value) for value in _parse_numbers(args.warm_start_confirmations, integer=True)]
    except ValueError as exc:
        parser.error(str(exc))

    automatic_capacity, sizing = _automatic_capacity()
    capacity = args.capacity or automatic_capacity
    worker_path = Path(get_sevenzip_bridge_worker_path()).resolve()
    dll_path = Path(get_7z_cli_dll_path()).resolve()
    admission_case = dict(ADMISSION_CASES["adaptive-baseline"])
    admission_case["name"] = "adaptive-baseline"
    admission_case["adaptive_enabled"] = True

    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        corpus, variants = _mixed_corpus(
            workspace.corpus,
            jobs=args.jobs,
            file_count=args.files_per_archive,
            file_size_bytes=args.file_size_bytes,
        )
        rows: list[dict[str, Any]] = []
        trace_paths: list[str] = []
        for decay in decays:
            for confirmation_count in confirmations:
                for pattern in patterns:
                    controls = _arrival_controls(
                        pattern,
                        jobs=args.jobs,
                        burst_size=args.burst_size,
                        idle_gap_seconds=args.idle_gap_seconds,
                        discrete_interval_seconds=args.discrete_interval_seconds,
                    )
                    for run in range(args.runs):
                        label = f"{pattern}-decay-{decay:g}-confirm-{confirmation_count}-run-{run}"
                        print(f"{label}: submitting mixed ZIP/7z/RAR jobs", flush=True)
                        row, trace = _run_batch(
                            workspace=workspace,
                            worker_path=worker_path,
                            dll_path=dll_path,
                            corpus=corpus,
                            capacity=capacity,
                            client_count=1,
                            timeout_seconds=args.timeout_seconds,
                            sample_interval_ms=args.sample_interval_ms,
                            admission_case=admission_case,
                            label=label,
                            submission_offsets_seconds=controls.get("submission_offsets_seconds"),
                            idle_before_indices=controls.get("idle_before_indices"),
                            worker_config_overrides={
                                "warm_start_decay_seconds": decay,
                                "warm_start_confirmations": confirmation_count,
                            },
                        )
                        row.update({
                            "arrival_pattern": pattern,
                            "scheduled_idle_seconds": controls["scheduled_idle_seconds"],
                            "warm_start_decay_seconds": decay,
                            "warm_start_confirmations": confirmation_count,
                            "run": run,
                        })
                        rows.append(row)
                        trace_path = workspace.write_result_json(f"traces/{label}.json", trace)
                        trace_paths.append(str(trace_path))
                        shutil.rmtree(workspace.outputs / label, ignore_errors=True)
                        print(
                            f"  wall={row['wall_ms']:.1f}ms queue_p95={row['queue_latency_p95_ms']}ms "
                            f"sessions={row['controller_activity_session_count']} "
                            f"segments={row['controller_saturated_segment_count']} "
                            f"warm={row['controller_warm_start_count']}",
                            flush=True,
                        )
        summary = _summarize(rows)
        report = {
            "parameters": {
                key: str(value) if isinstance(value, Path) else value
                for key, value in vars(args).items()
            },
            "environment": {
                "cpu_count": os.cpu_count(),
                "capacity": capacity,
                **sizing,
                "worker_path": str(worker_path),
            },
            "archive_variants": [
                {key: str(value) if isinstance(value, Path) else value for key, value in variant.items()}
                for variant in variants
            ],
            "results": rows,
            "summary": summary,
            "artifacts": {"result_dir": str(workspace.result_dir), "traces": trace_paths},
        }
        rendered = render_report(report_from_payload(SCENARIO, report))
        workspace.write_result_text("report.json", rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
