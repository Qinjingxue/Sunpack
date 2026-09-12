"""Compare native worker output throughput for one large stored ZIP member."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import psutil
import shutil
import statistics
import sys
import threading
import time
from typing import Any
import zipfile

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler, render_report, report_from_payload
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path


SCENARIO = "extraction.worker-single-file-write"
MIB = 1 << 20
GIB = 1 << 30
MEMBER_NAME = "payload.bin"


def _payload_block(size: int, block_index: int) -> bytes:
    """Create a repeatable but block-distinct byte pattern without large allocations."""
    seed_size = min(size, 256 << 10)
    seed = bytes(
        (index * 31 + (index // 257) * 11 + block_index * 17 + 19) % 251
        for index in range(seed_size)
    )
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def _create_archive(root: Path, *, payload_bytes: int, chunk_bytes: int) -> dict[str, Any]:
    archive = root / "single-large-member.zip"
    digest = hashlib.sha256()
    started = time.perf_counter()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as stream:
        with stream.open(MEMBER_NAME, "w", force_zip64=True) as member:
            remaining = payload_bytes
            block_index = 0
            while remaining:
                block = _payload_block(min(chunk_bytes, remaining), block_index)
                member.write(block)
                digest.update(block)
                remaining -= len(block)
                block_index += 1
    return {
        "archive": archive,
        "archive_bytes": archive.stat().st_size,
        "payload_bytes": payload_bytes,
        "payload_sha256": digest.hexdigest(),
        "member_name": MEMBER_NAME,
        "build_seconds": round(time.perf_counter() - started, 3),
    }


def _prefetch_archive(path: Path, *, chunk_bytes: int) -> None:
    with path.open("rb", buffering=0) as stream:
        while stream.read(chunk_bytes):
            pass


def _digest_path(path: Path, *, chunk_bytes: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as stream:
        while block := stream.read(chunk_bytes):
            digest.update(block)
    return digest.hexdigest()


def _worker_counters(worker: _NativeWorkerProcess) -> dict[str, float | int | None]:
    if worker.process is None:
        return {"cpu_ms": None, "read_bytes": None, "write_bytes": None}
    try:
        process = psutil.Process(worker.process.pid)
        cpu = process.cpu_times()
        io = process.io_counters()
    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
        return {"cpu_ms": None, "read_bytes": None, "write_bytes": None}
    return {
        "cpu_ms": (float(cpu.user) + float(cpu.system)) * 1000.0,
        "read_bytes": int(io.read_bytes),
        "write_bytes": int(io.write_bytes),
    }


def _job_payload(
    *,
    job_id: str,
    archive: Path,
    output_dir: Path,
    dll_path: Path,
    dry_run: bool,
) -> str:
    return json.dumps(
        {
            "job_id": job_id,
            "seven_zip_dll_path": str(dll_path),
            "archive_path": str(archive),
            "part_paths": [str(archive)],
            "output_dir": str(output_dir),
            "password": "",
            "format_hint": "zip",
            "dry_run": dry_run,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _run_worker(
    *,
    workspace: BenchmarkWorkspace,
    label: str,
    phase: str,
    run: int,
    worker_path: Path,
    dll_path: Path,
    corpus: dict[str, Any],
    writer_threads: int,
    timeout_seconds: float,
    sample_interval: float,
    prefetch_archive: bool,
    cleanup_output: bool,
    dry_run: bool,
    output_root: Path | None = None,
) -> dict[str, Any]:
    archive = Path(corpus["archive"])
    output_dir = (output_root or workspace.outputs) / f"{phase}-{run:02d}-{label}"
    output_dir.mkdir(parents=True, exist_ok=True)
    if prefetch_archive:
        _prefetch_archive(archive, chunk_bytes=8 * MIB)

    worker = _NativeWorkerProcess(
        str(worker_path),
        None,
        {
            "thread_capacity": 1,
            "adaptive_enabled": False,
            "initial_active_jobs": 1,
            "writer_threads": writer_threads,
        },
    )
    sampler = ProcessSampler(interval_seconds=sample_interval)
    result: dict[str, Any] | None = None
    events: list[dict[str, Any]] = []
    failure: list[str] = []
    completed = threading.Event()
    job_id = f"{phase}-{run:02d}-{label}"
    payload = _job_payload(
        job_id=job_id,
        archive=archive,
        output_dir=output_dir,
        dll_path=dll_path,
        dry_run=dry_run,
    )

    def on_line(line: str) -> bool:
        nonlocal result
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(event, dict):
            return False
        events.append(event)
        if event.get("type") == "result" and str(event.get("job_id") or "") == job_id:
            result = event
        if event.get("type") == "native_event" and event.get("event") == "job_finished" and result is not None:
            completed.set()
            return True
        return False

    def on_timeout(message: str) -> None:
        failure.append(str(message))
        completed.set()

    sampler.start()
    counters_before = _worker_counters(worker)
    sample_start = len(sampler.samples)
    sampler.take()
    started = time.perf_counter_ns()
    try:
        worker.submit_async(payload, job_id, on_line=on_line, on_timeout=on_timeout)
        deadline = time.monotonic() + timeout_seconds
        while not completed.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"worker job timed out: {job_id}")
            completed.wait(timeout=min(0.1, remaining))
            if not worker.is_alive() and not completed.is_set():
                raise RuntimeError(f"worker exited while running job: {job_id}")
        if failure:
            raise RuntimeError(f"worker failed while running job: {job_id}; {failure[-1]}")
        if result is None:
            raise RuntimeError(f"worker closed before returning a result: {job_id}")
        finished = time.perf_counter_ns()
        sampler.take()
        counters_after = _worker_counters(worker)
    finally:
        sampler.stop()
        worker.close()

    output_file = output_dir / str(corpus["member_name"])
    output_exists = output_file.is_file()
    output_bytes = output_file.stat().st_size if output_exists else 0
    output_sha256 = _digest_path(output_file, chunk_bytes=8 * MIB) if output_exists else None
    wall_seconds = max(0.000001, (finished - started) / 1_000_000_000.0)
    samples = sampler.samples[sample_start:]
    worker_rss = [sample.children_rss_mib for sample in samples]
    status = str(result.get("status") or "")
    if dry_run:
        passed = status == "ok" and int(result.get("bytes_written", 0) or 0) == int(corpus["payload_bytes"])
    else:
        passed = (
            status == "ok"
            and output_bytes == int(corpus["payload_bytes"])
            and output_sha256 == str(corpus["payload_sha256"])
        )
    row = {
        "label": label,
        "phase": phase,
        "run": run,
        "status": status,
        "passed": passed,
        "dry_run": dry_run,
        "worker_wall_seconds": round(wall_seconds, 6),
        "throughput_mib_per_second": round(int(corpus["payload_bytes"]) / MIB / wall_seconds, 3),
        "worker_cpu_ms": None
        if counters_before["cpu_ms"] is None or counters_after["cpu_ms"] is None
        else round(float(counters_after["cpu_ms"]) - float(counters_before["cpu_ms"]), 3),
        "worker_read_bytes": None
        if counters_before["read_bytes"] is None or counters_after["read_bytes"] is None
        else int(counters_after["read_bytes"]) - int(counters_before["read_bytes"]),
        "worker_write_bytes": None
        if counters_before["write_bytes"] is None or counters_after["write_bytes"] is None
        else int(counters_after["write_bytes"]) - int(counters_before["write_bytes"]),
        "worker_rss_peak_mib": round(max(worker_rss), 3) if worker_rss else None,
        "files_written": int(result.get("files_written", 0) or 0),
        "bytes_written": int(result.get("bytes_written", 0) or 0),
        "output_exists": output_exists,
        "output_bytes": output_bytes,
        "output_sha256": output_sha256,
        "event_count": len(events),
        "progress_event_count": sum(event.get("type") == "progress" for event in events),
        "failure_stage": result.get("failure_stage"),
        "failure_kind": result.get("failure_kind"),
        "message": result.get("message", ""),
    }
    if cleanup_output:
        shutil.rmtree(output_dir, ignore_errors=True)
    elif output_root is not None:
        # Keep an explicit output root from accumulating runs across invocations.
        shutil.rmtree(output_dir, ignore_errors=True)
    return row


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    columns = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def _median(rows: list[dict[str, Any]], key: str) -> float | None:
    values = [float(row[key]) for row in rows if row.get(key) is not None]
    return round(statistics.median(values), 6) if values else None


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return round(ordered[position], 6)


def _mad(values: list[float]) -> float | None:
    """Raw median absolute deviation (unscaled)."""
    if not values:
        return None
    center = statistics.median(values)
    return statistics.median([abs(value - center) for value in values])


def _regression_gate(
    baseline_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    *,
    hard_percent: float,
) -> dict[str, Any]:
    """Noise-aware non-regression gate: a reproducible slowdown beyond the run-to-run
    noise band fails rather than getting a fixed budget.
    """
    baseline_values = [float(row["throughput_mib_per_second"]) for row in baseline_rows]
    candidate_values = [float(row["throughput_mib_per_second"]) for row in candidate_rows]
    if not baseline_values or not candidate_values:
        return {"evaluated": False, "reason": "no measured runs"}
    baseline_median = statistics.median(baseline_values)
    candidate_median = statistics.median(candidate_values)
    mad = _mad(baseline_values)
    # Noise estimate: 3 x MAD or 3 x (IQR / 1.349), whichever is tighter.
    noise_floor = 0.0
    if len(baseline_values) >= 3:
        mad_floor = 3.0 * float(mad) if mad is not None else 0.0
        candidates = [mad_floor]
        if len(baseline_values) >= 4:
            p25 = _percentile(baseline_values, 0.25)
            p75 = _percentile(baseline_values, 0.75)
            if p25 is not None and p75 is not None:
                candidates.append(3.0 * (p75 - p25) / 1.349)
        noise_floor = min(value for value in candidates if value > 0.0) if any(
            value > 0.0 for value in candidates
        ) else 0.0
    drop_ratio = (baseline_median - candidate_median) / baseline_median if baseline_median else 0.0
    allowed = max(hard_percent, (noise_floor / baseline_median) if baseline_median else 0.0)
    over_line = drop_ratio > allowed
    baseline_p05 = _percentile(baseline_values, 0.05)
    candidate_p05 = _percentile(candidate_values, 0.05)
    tail_ok = (
        baseline_p05 is None
        or candidate_p05 is None
        or candidate_p05 >= baseline_p05 * 0.95
    )
    # Reproducibility: both halves of the measured runs must agree.
    reproducible = False
    if len(candidate_values) >= 4:
        ordered = sorted(candidate_values)
        half = len(ordered) // 2
        first, second = statistics.median(ordered[:half]), statistics.median(ordered[half:])
        reproducible = (
            (baseline_median - first) / baseline_median > allowed
            and (baseline_median - second) / baseline_median > allowed
        )
        reproducible = bool(reproducible and not tail_ok)
    gate = {
        "evaluated": True,
        "baseline_median_mib_per_second": round(baseline_median, 6),
        "candidate_median_mib_per_second": round(candidate_median, 6),
        "baseline_mad_mib_per_second": None if mad is None else round(mad, 6),
        "noise_floor_mib_per_second": round(noise_floor, 6),
        "drop_percent": round(drop_ratio * 100.0, 3),
        "allowed_drop_percent": round(allowed * 100.0, 3),
        "hard_percent": round(hard_percent * 100.0, 3),
        "baseline_p05_mib_per_second": baseline_p05,
        "candidate_p05_mib_per_second": candidate_p05,
        "tail_ok": bool(tail_ok),
        "over_line": bool(over_line),
        "reproducible": reproducible,
        "passed": bool(not over_line),
    }
    return gate


def _summarize(
    rows: list[dict[str, Any]],
    labels: list[str],
    *,
    hard_percent: float = 0.02,
) -> dict[str, Any]:
    measured = [row for row in rows if row["phase"] == "run"]
    by_worker: dict[str, dict[str, Any]] = {}
    for label in labels:
        samples = [row for row in measured if row["label"] == label]
        by_worker[label] = {
            "runs": len(samples),
            "all_passed": bool(samples) and all(bool(row["passed"]) for row in samples),
            "median_wall_seconds": _median(samples, "worker_wall_seconds"),
            "median_throughput_mib_per_second": _median(samples, "throughput_mib_per_second"),
            "median_worker_cpu_ms": _median(samples, "worker_cpu_ms"),
            "median_worker_rss_peak_mib": _median(samples, "worker_rss_peak_mib"),
        }
    summary: dict[str, Any] = {
        "all_passed": bool(measured) and all(bool(row["passed"]) for row in measured),
        "runs": len(measured),
        "by_worker": by_worker,
    }
    if "baseline" in by_worker and "candidate" in by_worker:
        baseline = by_worker["baseline"]
        candidate = by_worker["candidate"]
        before = baseline["median_throughput_mib_per_second"]
        after = candidate["median_throughput_mib_per_second"]
        if before is not None and after is not None:
            summary["candidate_vs_baseline"] = {
                "throughput_mib_per_second_delta": round(after - before, 6),
                "throughput_percent_delta": round((after / before - 1.0) * 100.0, 3) if before else None,
                "throughput_ratio": round(after / before, 6) if before else None,
            }
        measured_by_label: dict[str, list[dict[str, Any]]] = {
            label: [row for row in measured if row["label"] == label] for label in labels
        }
        gate = _regression_gate(
            measured_by_label.get("baseline", []),
            measured_by_label.get("candidate", []),
            hard_percent=hard_percent,
        )
        summary["regression_gate"] = gate
        per_label_noise: dict[str, Any] = {}
        for label in labels:
            values = [float(row["throughput_mib_per_second"]) for row in measured_by_label[label]]
            per_label_noise[label] = {
                "median_mib_per_second": round(statistics.median(values), 6) if values else None,
                "mad_mib_per_second": None if not values else round(float(_mad(values)), 6),
                "p05_mib_per_second": _percentile(values, 0.05),
                "p95_mib_per_second": _percentile(values, 0.95),
                "runs": len(values),
            }
        summary["throughput_distribution"] = per_label_noise
        if gate.get("evaluated"):
            summary["all_passed"] = bool(summary["all_passed"] and gate["passed"])
    return summary


def _worker_specs(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[tuple[str, Path]]:
    if (args.baseline_worker_path is None) != (args.candidate_worker_path is None):
        parser.error("--baseline-worker-path and --candidate-worker-path must be supplied together")
    if args.baseline_worker_path is not None:
        specs = [("baseline", args.baseline_worker_path), ("candidate", args.candidate_worker_path)]
    else:
        worker = args.worker_path
        if worker is None:
            try:
                worker = Path(get_sevenzip_bridge_worker_path())
            except FileNotFoundError as exc:
                parser.error(str(exc))
        specs = [("worker", worker)]
    resolved = [(label, path.resolve()) for label, path in specs]
    missing = [str(path) for _label, path in resolved if not path.is_file()]
    if missing:
        parser.error("worker executable is unavailable: " + ", ".join(missing))
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare native worker output throughput for one large ZIP_STORED member.")
    parser.add_argument(
        "--payload-gib",
        type=float,
        default=2.0,
        help="payload size; the §9.2 noise floor scales as 1/sqrt(size), so small payloads are noisy",
    )
    parser.add_argument("--chunk-mib", type=int, default=8)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--writer-threads", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    parser.add_argument("--sample-interval", type=float, default=0.01)
    parser.add_argument("--worker-path", type=Path, help="Run one worker executable without a before/after comparison.")
    parser.add_argument("--baseline-worker-path", type=Path, help="Pre-change worker executable.")
    parser.add_argument("--candidate-worker-path", type=Path, help="Post-change worker executable.")
    parser.add_argument(
        "--max-regression-percent",
        type=float,
        default=2.0,
        help=(
            "§9.2 non-regression budget for the architecturally unchanged single-disk "
            "path, as a percentage; the effective allowance is "
            "max(this, 3 x MAD of the baseline runs)."
        ),
    )
    parser.add_argument("--prefetch-archive", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--dry-run", action="store_true", help="Measure 7z decode and callback throughput without output I/O.")
    parser.add_argument(
        "--write-through",
        action="store_true",
        help="Open output with write-through semantics for a physical-disk throughput measurement.",
    )
    parser.add_argument("--results-root", type=Path)
    parser.add_argument(
        "--output-root",
        type=Path,
        help=(
            "directory for extraction output; point this at a non-system volume for a "
            "quiet §9.2 measurement (the default workspace lives on the repo volume)"
        ),
    )
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    if args.payload_gib <= 0 or args.chunk_mib < 1 or args.runs < 1 or args.warmups < 0:
        parser.error("payload size, chunk size, and runs must be positive; warmups must be non-negative")
    if not 1 <= args.writer_threads <= 32:
        parser.error("--writer-threads must be between 1 and 32")
    if args.timeout_seconds <= 0 or args.sample_interval <= 0:
        parser.error("--timeout-seconds and --sample-interval must be positive")
    if args.max_regression_percent < 0:
        parser.error("--max-regression-percent must be non-negative")
    if args.write_through:
        os.environ["SUNPACK_ASYNC_WRITER_WRITE_THROUGH"] = "1"
    else:
        os.environ.pop("SUNPACK_ASYNC_WRITER_WRITE_THROUGH", None)
    worker_specs = _worker_specs(args, parser)
    try:
        dll_path = Path(get_7z_dll_path()).resolve()
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if not dll_path.is_file():
        parser.error(f"7z.dll is unavailable: {dll_path}")

    payload_bytes = int(args.payload_gib * GIB)
    chunk_bytes = args.chunk_mib * MIB
    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        print(f"building {args.payload_gib:g} GiB stored ZIP corpus ...", flush=True)
        corpus = _create_archive(workspace.corpus, payload_bytes=payload_bytes, chunk_bytes=chunk_bytes)
        print(
            f"  archive={corpus['archive_bytes'] / MIB:.1f} MiB build={corpus['build_seconds']:.2f}s "
            f"sha256={corpus['payload_sha256'][:12]}",
            flush=True,
        )
        rows: list[dict[str, Any]] = []
        labels = [label for label, _path in worker_specs]
        total_iterations = args.warmups + args.runs
        for iteration in range(total_iterations):
            phase = "warmup" if iteration < args.warmups else "run"
            run = iteration if phase == "warmup" else iteration - args.warmups
            ordered_specs = worker_specs if iteration % 2 == 0 else list(reversed(worker_specs))
            for label, worker_path in ordered_specs:
                print(f"{phase}-{run} {label}: extracting with {args.writer_threads} writer threads ...", flush=True)
                row = _run_worker(
                    workspace=workspace,
                    label=label,
                    phase=phase,
                    run=run,
                    worker_path=worker_path,
                    dll_path=dll_path,
                    corpus=corpus,
                    writer_threads=args.writer_threads,
                    timeout_seconds=args.timeout_seconds,
                    sample_interval=args.sample_interval,
                    prefetch_archive=bool(args.prefetch_archive),
                    cleanup_output=not args.keep_workdir,
                    dry_run=bool(args.dry_run),
                    output_root=args.output_root,
                )
                rows.append(row)
                print(
                    f"  {row['throughput_mib_per_second']:.1f} MiB/s "
                    f"wall={row['worker_wall_seconds']:.3f}s rss={row['worker_rss_peak_mib']} MiB passed={row['passed']}",
                    flush=True,
                )
        summary = _summarize(rows, labels, hard_percent=args.max_regression_percent / 100.0)
        report = {
            "parameters": {
                "payload_gib": args.payload_gib,
                "chunk_mib": args.chunk_mib,
                "runs": args.runs,
                "warmups": args.warmups,
                "writer_threads": args.writer_threads,
                "timeout_seconds": args.timeout_seconds,
                "sample_interval": args.sample_interval,
                "prefetch_archive": bool(args.prefetch_archive),
                "dry_run": bool(args.dry_run),
                "write_through": bool(args.write_through),
                "max_regression_percent": args.max_regression_percent,
            },
            "environment": {
                "workers": {label: str(path) for label, path in worker_specs},
                "seven_zip_dll_path": str(dll_path),
                "cpu_count": os.cpu_count(),
                "python": sys.version,
            },
            "corpus": {key: value for key, value in corpus.items() if key != "archive"},
            "results": rows,
            "summary": summary,
            "artifacts": {"result_dir": str(workspace.result_dir)},
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
