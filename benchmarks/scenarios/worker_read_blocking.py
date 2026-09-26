"""Measure synchronous input-stream ReadFile time for one large worker job.

The generated archive is a ZIP stored without compression, so its input size
is approximately the requested payload size and 7z.dll must fetch every byte
through ``IInStream::Read``. The worker opt-in timer surrounds only the
underlying synchronous ``ReadFile`` calls, not decompression, output writes,
or Python protocol handling.
"""
from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler, render_report, report_from_payload
from benchmarks.scenarios.sevenzip_worker_matrix import _case_job, _median, _run_job
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path
from tests.helpers.tool_config import get_7z_cli_dll_path


MIB = 1024 * 1024
GIB = 1024 * MIB


def _write_payload(path: Path, size_bytes: int) -> None:
    """Write non-repeating bytes so archive creation cannot exploit sparsity."""
    chunk_size = 8 * MIB
    with path.open("wb") as stream:
        remaining = size_bytes
        while remaining:
            chunk = os.urandom(min(chunk_size, remaining))
            stream.write(chunk)
            remaining -= len(chunk)


def _create_stored_zip(workspace: BenchmarkWorkspace, payload_gib: int, timeout_seconds: float) -> tuple[Path, int]:
    payload_bytes = payload_gib * GIB
    payload = workspace.corpus / "payload.bin"
    archive = workspace.corpus / "single-file-1gib-stored.zip"
    print(f"generating {payload_gib} GiB non-compressible payload", flush=True)
    _write_payload(payload, payload_bytes)
    seven_zip = ROOT / "tools" / "7z.exe"
    if not seven_zip.is_file():
        raise FileNotFoundError(f"7z.exe does not exist: {seven_zip}")
    print("creating stored ZIP archive", flush=True)
    result = subprocess.run(
        [str(seven_zip), "a", "-y", "-tzip", "-mx=0", str(archive), payload.name],
        cwd=payload.parent,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
    )
    if result.returncode != 0 or not archive.is_file():
        raise RuntimeError(f"stored ZIP creation failed: {result.stderr[-2000:]}")
    return archive, payload_bytes


def _run_case(
    *,
    workspace: BenchmarkWorkspace,
    archive: Path,
    payload_bytes: int | None,
    worker_path: Path,
    dll_path: Path,
    runs: int,
    timeout_seconds: float,
    sample_interval: float,
    prefetch_enabled: bool,
    prefetch_window_kib: int,
    prefetch_depth: int,
    run_start: int = 0,
) -> list[dict[str, Any]]:
    prior_environment = {
        name: os.environ.get(name)
        for name in ("SUNPACK_SEVENZIP_PROFILE_READS", "SUNPACK_SEVENZIP_PREFETCH", "SUNPACK_SEVENZIP_PREFETCH_WINDOW_KIB", "SUNPACK_SEVENZIP_PREFETCH_DEPTH")
    }
    worker: _NativeWorkerProcess | None = None
    sampler = ProcessSampler(interval_seconds=sample_interval)
    sampling = False
    rows: list[dict[str, Any]] = []
    case = {"path": archive, "format": "zip"}
    try:
        os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "1"
        os.environ["SUNPACK_SEVENZIP_PREFETCH"] = "1" if prefetch_enabled else "0"
        os.environ["SUNPACK_SEVENZIP_PREFETCH_WINDOW_KIB"] = str(prefetch_window_kib)
        os.environ["SUNPACK_SEVENZIP_PREFETCH_DEPTH"] = str(prefetch_depth)
        worker = _NativeWorkerProcess(str(worker_path), None)
        sampler.start()
        sampling = True
        for run in range(run_start, run_start + runs):
            mode = "on" if prefetch_enabled else "off"
            output = workspace.outputs / mode / f"run-{run}"
            job = _case_job(case, job_id=f"read-blocking-{mode}-{run}", output_dir=output, dll_path=dll_path)
            try:
                measured = _run_job(worker, job, timeout_seconds=timeout_seconds, sampler=sampler)
            finally:
                if not workspace.keep_workdir:
                    shutil.rmtree(output, ignore_errors=True)
            measured.update({
                "run": run,
                "archive_bytes": archive.stat().st_size,
                "payload_bytes": payload_bytes,
                "prefetch_enabled": prefetch_enabled,
                "prefetch_window_kib": prefetch_window_kib,
                "prefetch_depth": prefetch_depth,
            })
            rows.append(measured)
    finally:
        if sampling:
            sampler.stop()
        if worker is not None:
            worker.close()
        for name, previous in prior_environment.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
    return rows


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    columns = [
        "run", "status", "passed", "archive_bytes", "payload_bytes", "worker_wall_ms", "worker_cpu_ms",
        "input_stream_mode", "input_read_file_call_count", "input_read_file_wall_ms",
        "input_read_file_max_wall_ms", "input_read_file_wall_ratio", "input_prefetch_enabled",
        "input_prefetch_hit_count", "input_prefetch_miss_count", "input_prefetch_invalidation_count",
        "input_prefetch_consumer_wait_ms", "input_consumer_read_blocking_ms", "prefetch_enabled",
        "prefetch_window_kib", "prefetch_depth", "bytes_written", "files_written",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure ReadFile wall time inside IInStream::Read for one large archive.")
    parser.add_argument("--archive", type=Path, help="Existing ZIP archive to use instead of generating a stored archive.")
    parser.add_argument("--payload-gib", type=int, default=1, help="Generated source-file size in GiB (default: 1).")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--prefetch", choices=("on", "off", "compare"), default="compare")
    parser.add_argument("--prefetch-window-kib", type=int, default=512)
    parser.add_argument("--prefetch-depth", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    parser.add_argument("--sample-interval", type=float, default=0.02)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    if args.payload_gib < 1 or args.runs < 1:
        parser.error("--payload-gib and --runs must be positive")
    if args.timeout_seconds <= 0 or args.sample_interval <= 0:
        parser.error("--timeout-seconds and --sample-interval must be positive")
    if not 64 <= args.prefetch_window_kib <= 16 * 1024 or not 1 <= args.prefetch_depth <= 8:
        parser.error("--prefetch-window-kib must be 64..16384 and --prefetch-depth must be 1..8")

    worker_path = Path(get_sevenzip_bridge_worker_path()).resolve()
    dll_path = Path(get_7z_cli_dll_path()).resolve()
    if not worker_path.is_file() or not dll_path.is_file():
        parser.error("the native worker and 7z.dll must both exist")

    scenario = "extraction.worker-read-blocking"
    with BenchmarkWorkspace(scenario, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        if args.archive:
            archive = args.archive.resolve()
            if not archive.is_file():
                parser.error(f"archive does not exist: {archive}")
            payload_bytes = None
            source = "user_archive"
        else:
            archive, payload_bytes = _create_stored_zip(workspace, args.payload_gib, args.timeout_seconds)
            source = "generated_stored_zip"
        print(f"measuring archive={archive} size={archive.stat().st_size}B", flush=True)
        rows: list[dict[str, Any]] = []
        if args.prefetch == "compare":
            mode_runs = ((run, ("off", "on") if run % 2 == 0 else ("on", "off")) for run in range(args.runs))
        else:
            mode_runs = ((0, (args.prefetch,)),)
        for run_start, modes in mode_runs:
            for mode in modes:
                rows.extend(_run_case(
                    workspace=workspace,
                    archive=archive,
                    payload_bytes=payload_bytes,
                    worker_path=worker_path,
                    dll_path=dll_path,
                    runs=1 if args.prefetch == "compare" else args.runs,
                    timeout_seconds=args.timeout_seconds,
                    sample_interval=args.sample_interval,
                    prefetch_enabled=mode == "on",
                    prefetch_window_kib=args.prefetch_window_kib,
                    prefetch_depth=args.prefetch_depth,
                    run_start=run_start,
                ))
        by_prefetch = {
            mode: {
                "sample_count": len(group),
                "median_worker_wall_ms": _median([row.get("worker_wall_ms") for row in group]),
                "median_consumer_read_blocking_ms": _median([row.get("input_consumer_read_blocking_ms") for row in group]),
                "median_sync_read_file_wall_ms": _median([row.get("input_read_file_wall_ms") for row in group]),
                "median_prefetch_wait_ms": _median([row.get("input_prefetch_consumer_wait_ms") for row in group]),
            }
            for mode, group in (("off", [row for row in rows if not row["prefetch_enabled"]]), ("on", [row for row in rows if row["prefetch_enabled"]]))
            if group
        }
        summary = {
            "sample_count": len(rows),
            "passed_samples": sum(bool(row.get("passed")) for row in rows),
            "all_passed": bool(rows) and all(bool(row.get("passed")) for row in rows),
            "median_worker_wall_ms": _median([row.get("worker_wall_ms") for row in rows]),
            "median_input_read_file_wall_ms": _median([row.get("input_read_file_wall_ms") for row in rows]),
            "median_input_read_file_wall_ratio": _median([row.get("input_read_file_wall_ratio") for row in rows]),
            "median_input_read_file_max_wall_ms": _median([row.get("input_read_file_max_wall_ms") for row in rows]),
            "by_prefetch": by_prefetch,
        }
        report = {
            "parameters": {
                "runs": args.runs,
                "payload_gib": args.payload_gib,
                "timeout_seconds": args.timeout_seconds,
                "prefetch": args.prefetch,
                "prefetch_window_kib": args.prefetch_window_kib,
                "prefetch_depth": args.prefetch_depth,
            },
            "method": {
                "input": source,
                "archive": str(archive),
                "archive_format": "zip",
                "archive_compression": "store (-mx=0)" if source == "generated_stored_zip" else "user supplied",
                "timed_region": "synchronous ReadFile calls made by IInStream::Read implementations",
                "ratio": "sum(ReadFile wall time) / native worker job wall time",
                "cache_caveat": "Windows file-cache state is not purged or controlled; generated archives are likely warm. Use --archive with a representative pre-existing archive for a production-cache-state sample.",
                "prefetch_comparison": "Consumer blocking is synchronous ReadFile time plus wait for prefetch; background ReadFile may overlap output work and is not added to that metric.",
            },
            "environment": {"worker_path": str(worker_path), "python": sys.version, "cpu_count": os.cpu_count()},
            "results": rows,
            "summary": summary,
            "artifacts": {"result_dir": str(workspace.result_dir)},
        }
        rendered = render_report(report_from_payload(scenario, report))
        workspace.write_result_text("report.json", rendered)
        _write_csv(workspace.result_dir / "results.csv", rows)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
