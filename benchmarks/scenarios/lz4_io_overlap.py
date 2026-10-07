"""Measure native LZ4 input, decoder, output, and overlap wall times."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler
from benchmarks.scenarios.extraction_cli_format_matrix import (
    DEFAULT_LZ4_TOOL,
    _archive_for,
    _ensure_special_archives,
)
from benchmarks.scenarios.sevenzip_worker_matrix import _run_job
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess


SCENARIO = "extraction.lz4-io-overlap"
DEFAULT_WORKER = ROOT / "native" / "sevenzip_bridge" / "build-probe" / "Release" / "sunpack_sevenzip_worker.exe"
MIB = 1024 * 1024


def _median(rows: list[dict[str, Any]], key: str) -> float | None:
    values = [float(row[key]) for row in rows if row.get(key) is not None]
    return round(statistics.median(values), 3) if values else None


def _add_overlap_metrics(row: dict[str, Any]) -> None:
    input_compute = float(row.get("pipeline_input_compute_overlap_ms") or 0.0)
    compute_output = float(row.get("pipeline_compute_output_overlap_ms") or 0.0)
    all_overlap = float(row.get("pipeline_all_overlap_ms") or 0.0)
    compute = float(row.get("pipeline_compute_active_ms") or 0.0)
    io_compute = max(0.0, input_compute + compute_output - all_overlap)
    row["pipeline_io_compute_overlap_ms"] = round(io_compute, 3)
    row["pipeline_compute_exclusive_ms"] = round(max(0.0, compute - io_compute), 3)
    row["pipeline_io_compute_overlap_of_compute"] = round(io_compute / compute, 6) if compute else None
    wall = float(row.get("pipeline_wall_ms") or 0.0)
    row["pipeline_io_compute_overlap_of_wall"] = round(io_compute / wall, 6) if wall else None


def _job(archive: Path, output: Path, job_id: str) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "archive_path": str(archive),
        "part_paths": [str(archive)],
        "output_dir": str(output),
        "password": "",
        "format_hint": "lz4",
    }


def _run_mode(
    *,
    archive: Path,
    worker_path: Path,
    workspace: BenchmarkWorkspace,
    prefetch: str,
    runs: int,
    warmups: int,
    timeout: float,
    sample_interval: float,
) -> list[dict[str, Any]]:
    saved = {name: os.environ.get(name) for name in (
        "SUNPACK_SEVENZIP_PREFETCH",
        "SUNPACK_SEVENZIP_PROFILE_PIPELINE",
        "SUNPACK_SEVENZIP_PROFILE_READS",
    )}
    os.environ["SUNPACK_SEVENZIP_PREFETCH"] = "1" if prefetch == "on" else "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "1"
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "1"
    worker = _NativeWorkerProcess(str(worker_path), None)
    sampler = ProcessSampler(interval_seconds=sample_interval)
    rows: list[dict[str, Any]] = []
    try:
        sampler.start()
        for index in range(warmups + runs):
            output = workspace.outputs / f"lz4-{prefetch}-{index}"
            shutil.rmtree(output, ignore_errors=True)
            job_id = f"lz4-{prefetch}-{index}"
            try:
                row = _run_job(
                    worker,
                    _job(archive, output, job_id),
                    timeout_seconds=timeout,
                    sampler=sampler,
                )
                if row.get("pipeline_wall_ms") is None:
                    raise RuntimeError(
                        "worker returned no pipeline_timing; build it with "
                        "-DSUP7Z_ENABLE_PIPELINE_TIMING=ON"
                    )
                if not row.get("passed"):
                    raise RuntimeError(f"native LZ4 worker failed: {row.get('message')}")
                if row.get("output_total_bytes") != 300 * MIB:
                    raise RuntimeError(f"LZ4 output size mismatch: {row.get('output_total_bytes')} bytes")
                _add_overlap_metrics(row)
                row.update({"prefetch": prefetch, "run": index - warmups + 1})
                if index >= warmups:
                    rows.append(row)
                    print(
                        f"prefetch={prefetch} run={index - warmups + 1}/{runs} "
                        f"wall={row['pipeline_wall_ms']:.3f}ms "
                        f"read={row['pipeline_input_active_ms']:.3f}ms "
                        f"compute={row['pipeline_compute_active_ms']:.3f}ms "
                        f"write={row['pipeline_output_active_ms']:.3f}ms "
                        f"overlap={row['pipeline_io_compute_overlap_ms']:.3f}ms",
                        flush=True,
                    )
            finally:
                shutil.rmtree(output, ignore_errors=True)
    finally:
        sampler.stop()
        worker.close()
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-path", type=Path, default=DEFAULT_WORKER)
    parser.add_argument("--lz4-tool", type=Path, default=DEFAULT_LZ4_TOOL)
    parser.add_argument("--prefetch", choices=("on", "off", "compare"), default="on")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--sample-interval", type=float, default=0.01)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 0 or args.timeout <= 0 or args.sample_interval <= 0:
        parser.error("runs, timeout, and sample interval must be positive; warmups cannot be negative")

    worker_path = args.worker_path.resolve()
    if not worker_path.is_file():
        parser.error(f"timing-enabled native worker not found: {worker_path}")
    _ensure_special_archives(args.lz4_tool.resolve(), args.timeout)
    archive = _archive_for("lz4")
    modes = ["on", "off"] if args.prefetch == "compare" else [args.prefetch]

    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        samples: list[dict[str, Any]] = []
        for mode in modes:
            samples.extend(_run_mode(
                archive=archive,
                worker_path=worker_path,
                workspace=workspace,
                prefetch=mode,
                runs=args.runs,
                warmups=args.warmups,
                timeout=args.timeout,
                sample_interval=args.sample_interval,
            ))

        summary: dict[str, Any] = {}
        for mode in modes:
            selected = [row for row in samples if row["prefetch"] == mode]
            summary[mode] = {
                "runs": len(selected),
                "median_pipeline_wall_ms": _median(selected, "pipeline_wall_ms"),
                "median_input_active_ms": _median(selected, "pipeline_input_active_ms"),
                "median_compute_active_ms": _median(selected, "pipeline_compute_active_ms"),
                "median_compute_cpu_ms": _median(selected, "pipeline_compute_cpu_ms"),
                "median_output_active_ms": _median(selected, "pipeline_output_active_ms"),
                "median_input_compute_overlap_ms": _median(selected, "pipeline_input_compute_overlap_ms"),
                "median_compute_output_overlap_ms": _median(selected, "pipeline_compute_output_overlap_ms"),
                "median_io_compute_overlap_ms": _median(selected, "pipeline_io_compute_overlap_ms"),
                "median_compute_exclusive_ms": _median(selected, "pipeline_compute_exclusive_ms"),
                "median_io_compute_overlap_of_compute": _median(selected, "pipeline_io_compute_overlap_of_compute"),
                "median_io_compute_overlap_of_wall": _median(selected, "pipeline_io_compute_overlap_of_wall"),
                "median_input_read_file_wall_ms": _median(selected, "input_read_file_wall_ms"),
                "median_worker_wall_ms": _median(selected, "worker_wall_ms"),
            }
        report = {
            "scenario": SCENARIO,
            "parameters": {
                "archive": str(archive),
                "archive_bytes": archive.stat().st_size,
                "output_bytes": 300 * MIB,
                "worker_path": str(worker_path),
                "worker_prefetch": modes,
                "pipeline_timing_enabled": True,
                "read_profiling_enabled": True,
                "runs": args.runs,
                "warmups": args.warmups,
            },
            "summary": summary,
            "samples": samples,
        }
        rendered = json.dumps(report, ensure_ascii=False, indent=2)
        workspace.write_result_text("report.json", rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
