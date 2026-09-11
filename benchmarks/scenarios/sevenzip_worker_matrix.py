"""Direct performance matrix for the native 7z.dll worker.

This scenario deliberately bypasses SunPack's planning, verification, and
recursive extraction layers.  It measures the persistent native worker itself
against generated archives from the existing extraction-format corpus builder.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import queue
import shutil
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Any

import psutil

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler, render_report, report_from_payload
from benchmarks.scenarios.extraction_format_matrix import GENERATED_FORMATS, create_corpus
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path


SIZE_PROFILES: dict[str, dict[str, int]] = {
    "tiny": {"small_files": 16, "large_files": 1, "large_file_mib": 1},
    "small": {"small_files": 128, "large_files": 1, "large_file_mib": 4},
    "medium": {"small_files": 512, "large_files": 2, "large_file_mib": 16},
    "large": {"small_files": 2048, "large_files": 2, "large_file_mib": 32},
}


def _parse_csv_values(values: list[str], allowed: set[str], option: str) -> list[str]:
    selected: list[str] = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            if item not in allowed:
                raise ValueError(f"{option} value {item!r} is not one of: {', '.join(sorted(allowed))}")
            if item not in selected:
                selected.append(item)
    return selected


def _volume_paths(item: dict[str, Any]) -> list[Path]:
    source = Path(item["path"])
    archive_format = str(item["format"])
    if archive_format == "7z-split":
        return sorted(source.parent.glob(f"{source.name.rsplit('.', 1)[0]}.*"))
    if archive_format == "rar-split":
        prefix = source.name.split(".part", 1)[0]
        return sorted(source.parent.glob(f"{prefix}.part*.rar"))
    return [source]


def _payload_bytes(item: dict[str, Any]) -> int | None:
    value = item.get("expected_payload_bytes")
    return int(value) if isinstance(value, (int, float)) and value > 0 else None


def _output_summary(path: Path) -> dict[str, int]:
    if not path.is_dir():
        return {"file_count": 0, "total_bytes": 0}
    files = [candidate for candidate in path.rglob("*") if candidate.is_file()]
    return {
        "file_count": len(files),
        "total_bytes": sum(candidate.stat().st_size for candidate in files),
    }


def _worker_cpu_ms(worker: _NativeWorkerProcess) -> float | None:
    process = worker.process
    if process is None:
        return None
    try:
        times = psutil.Process(process.pid).cpu_times()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    return (float(times.user) + float(times.system)) * 1000.0


def _worker_stderr(worker: _NativeWorkerProcess) -> str:
    lines: list[str] = []
    while True:
        try:
            line = worker.stderr_queue.get_nowait()
        except queue.Empty:
            break
        if line is None:
            break
        lines.append(str(line))
    return "".join(lines)[-4000:]


def _run_job(
    worker: _NativeWorkerProcess,
    job: dict[str, Any],
    *,
    timeout_seconds: float,
    sampler: ProcessSampler,
) -> dict[str, Any]:
    payload = json.dumps(job, ensure_ascii=False, separators=(",", ":"))
    job_id = str(job["job_id"])
    cpu_before = _worker_cpu_ms(worker)
    sample_start = len(sampler.samples)
    sampler.take()
    started = time.perf_counter_ns()
    events: list[dict[str, Any]] = []
    result: dict[str, Any] | None = None
    failure: list[str] = []
    completed = threading.Event()

    def on_line(line: str) -> bool:
        nonlocal result
        text = str(line).strip()
        if not text.startswith("{"):
            return False
        try:
            event = json.loads(text)
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

    worker.submit_async(payload, job_id, on_line=on_line, on_timeout=on_timeout)
    deadline = time.monotonic() + max(1.0, timeout_seconds)
    while not completed.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"worker job timed out: {job_id}")
        completed.wait(timeout=min(0.1, remaining))
        if not worker.is_alive() and not completed.is_set():
            raise RuntimeError(f"worker exited while running job: {job_id}; {_worker_stderr(worker)}")

    if failure:
        raise RuntimeError(f"worker failed while running job: {job_id}; {failure[-1]}")
    if result is None:
        raise RuntimeError(f"worker closed before returning a result: {job_id}; {_worker_stderr(worker)}")

    finished = time.perf_counter_ns()
    sampler.take()
    cpu_after = _worker_cpu_ms(worker)
    window = sampler.samples[sample_start:]
    child_rss = [sample.children_rss_mib for sample in window]
    output = Path(str(job["output_dir"]))
    output_stats = _output_summary(output)
    status = str(result.get("status") or "")
    worker_wall_ms = round((finished - started) / 1_000_000.0, 3)
    input_trace = result.get("input_trace")
    if not isinstance(input_trace, dict):
        input_trace = {}
    read_file_wall_ms = round(float(input_trace.get("read_file_wall_ns", 0) or 0) / 1_000_000.0, 3)
    prefetch_wait_ms = round(float(input_trace.get("prefetch_consumer_wait_ns", 0) or 0) / 1_000_000.0, 3)
    sequential_read_bytes = int(input_trace.get("sequential_read_bytes", 0) or 0)
    nonsequential_read_bytes = int(input_trace.get("nonsequential_read_bytes", 0) or 0)
    logical_read_bytes = sequential_read_bytes + nonsequential_read_bytes
    return {
        "job_id": job_id,
        "status": status,
        "passed": status == "ok",
        "worker_wall_ms": worker_wall_ms,
        "worker_cpu_ms": None if cpu_before is None or cpu_after is None else round(cpu_after - cpu_before, 3),
        "input_stream_mode": input_trace.get("mode"),
        "input_read_file_call_count": int(input_trace.get("read_file_call_count", 0) or 0),
        "input_read_file_wall_ms": read_file_wall_ms,
        "input_read_file_max_wall_ms": round(float(input_trace.get("read_file_max_wall_ns", 0) or 0) / 1_000_000.0, 3),
        "input_read_file_wall_ratio": round(read_file_wall_ms / worker_wall_ms, 6) if worker_wall_ms else None,
        "input_logical_read_call_count": int(input_trace.get("logical_read_call_count", 0) or 0),
        "input_sequential_read_bytes": sequential_read_bytes,
        "input_nonsequential_read_bytes": nonsequential_read_bytes,
        "input_sequential_read_ratio": round(sequential_read_bytes / logical_read_bytes, 6) if logical_read_bytes else None,
        "input_sequential_run_count": int(input_trace.get("sequential_run_count", 0) or 0),
        "input_max_sequential_run_bytes": int(input_trace.get("max_sequential_run_bytes", 0) or 0),
        "input_seek_count": int(input_trace.get("seek_count", 0) or 0),
        "input_seek_forward_bytes": int(input_trace.get("seek_forward_bytes", 0) or 0),
        "input_seek_backward_bytes": int(input_trace.get("seek_backward_bytes", 0) or 0),
        "input_prefetch_enabled": bool(input_trace.get("prefetch_enabled", False)),
        "input_prefetch_hit_count": int(input_trace.get("prefetch_hit_count", 0) or 0),
        "input_prefetch_miss_count": int(input_trace.get("prefetch_miss_count", 0) or 0),
        "input_prefetch_invalidation_count": int(input_trace.get("prefetch_invalidation_count", 0) or 0),
        "input_prefetch_issued_count": int(input_trace.get("prefetch_issued_count", 0) or 0),
        "input_prefetch_published_count": int(input_trace.get("prefetch_published_count", 0) or 0),
        "input_prefetch_orphaned_count": int(input_trace.get("prefetch_orphaned_count", 0) or 0),
        "input_prefetch_consumer_wait_ms": prefetch_wait_ms,
        "input_consumer_read_blocking_ms": round(read_file_wall_ms + prefetch_wait_ms, 3),
        "worker_rss_before_mib": round(child_rss[0], 3) if child_rss else None,
        "worker_rss_peak_mib": round(max(child_rss), 3) if child_rss else None,
        "worker_rss_after_mib": round(child_rss[-1], 3) if child_rss else None,
        "event_count": len(events),
        "progress_event_count": sum(event.get("type") == "progress" for event in events),
        "files_written": int(result.get("files_written", 0) or 0),
        "bytes_written": int(result.get("bytes_written", 0) or 0),
        "output_file_count": output_stats["file_count"],
        "output_total_bytes": output_stats["total_bytes"],
        "failure_stage": result.get("failure_stage"),
        "failure_kind": result.get("failure_kind"),
        "message": result.get("message", ""),
        "native_status": result.get("native_status"),
        "operation_result_name": result.get("operation_result_name"),
    }


def _case_job(
    case: dict[str, Any],
    *,
    job_id: str,
    output_dir: Path,
    dll_path: Path,
) -> dict[str, Any]:
    volumes = _volume_paths(case)
    archive_format = str(case["format"])
    format_hint = archive_format.removesuffix("-split")
    job = {
        "job_id": job_id,
        "seven_zip_dll_path": str(dll_path),
        "archive_path": str(volumes[0]),
        "part_paths": [str(path) for path in volumes],
        "output_dir": str(output_dir),
        "password": "",
        "format_hint": format_hint,
    }
    if archive_format == "rar-split":
        job["archive_input"] = {
            "entry_path": str(volumes[0]),
            "open_mode": "native_volumes",
            "format_hint": "rar",
            "parts": [
                {"path": str(path), "volume_number": index, "canonical_name": path.name}
                for index, path in enumerate(volumes, start=1)
            ],
        }
    return job


def _build_cases(workspace: BenchmarkWorkspace, profiles: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    corpus_info: dict[str, Any] = {}
    for profile in profiles:
        profile_root = workspace.corpus / profile
        settings = SIZE_PROFILES[profile]
        corpus, skipped = create_corpus(
            profile_root,
            {},
            settings["small_files"],
            settings["large_files"],
            settings["large_file_mib"],
        )
        corpus_info[profile] = {
            "settings": settings,
            "generated_cases": len(corpus),
            "skipped": skipped,
        }
        for name, item in sorted(corpus.items()):
            cases.append({
                "case_id": f"{profile}:{name}",
                "profile": profile,
                "workload": item.get("workload"),
                "format": item.get("format"),
                "archive_path": str(item["path"]),
                "archive_bytes": Path(item["path"]).stat().st_size,
                "volume_count": len(_volume_paths(item)),
                "payload_bytes": _payload_bytes(item),
                "item": item,
            })
    return cases, corpus_info


def _median(values: list[float | None]) -> float | None:
    usable = [value for value in values if value is not None]
    return round(statistics.median(usable), 3) if usable else None


def _summarize(samples: list[dict[str, Any]]) -> dict[str, Any]:
    passed = [sample for sample in samples if sample.get("passed")]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        grouped.setdefault(str(sample["format"]), []).append(sample)
    by_format = {
        format_name: {
            "samples": len(rows),
            "passed": sum(bool(row.get("passed")) for row in rows),
            "median_worker_wall_ms": _median([row.get("worker_wall_ms") for row in rows]),
            "median_worker_rss_peak_mib": _median([row.get("worker_rss_peak_mib") for row in rows]),
        }
        for format_name, rows in sorted(grouped.items())
    }
    return {
        "sample_count": len(samples),
        "passed_samples": len(passed),
        "failed_samples": len(samples) - len(passed),
        "all_passed": len(samples) > 0 and len(passed) == len(samples),
        "median_worker_wall_ms": _median([sample.get("worker_wall_ms") for sample in samples]),
        "median_worker_cpu_ms": _median([sample.get("worker_cpu_ms") for sample in samples]),
        "median_worker_rss_peak_mib": _median([sample.get("worker_rss_peak_mib") for sample in samples]),
        "by_format": by_format,
    }


def _write_csv(path: Path, samples: list[dict[str, Any]]) -> None:
    columns = [
        "case_id", "profile", "workload", "format", "run", "archive_bytes", "payload_bytes", "volume_count",
        "status", "passed", "worker_wall_ms", "worker_cpu_ms", "worker_rss_before_mib",
        "worker_rss_peak_mib", "worker_rss_after_mib", "input_stream_mode", "input_read_file_call_count",
        "input_read_file_wall_ms", "input_read_file_max_wall_ms", "input_read_file_wall_ratio", "files_written", "bytes_written",
        "input_logical_read_call_count", "input_sequential_read_bytes", "input_nonsequential_read_bytes",
        "input_sequential_read_ratio", "input_sequential_run_count", "input_max_sequential_run_bytes",
        "input_seek_count", "input_seek_forward_bytes", "input_seek_backward_bytes",
        "input_prefetch_enabled", "input_prefetch_hit_count", "input_prefetch_miss_count",
        "input_prefetch_invalidation_count", "input_prefetch_consumer_wait_ms", "input_consumer_read_blocking_ms",
        "output_file_count", "output_total_bytes", "failure_stage", "failure_kind", "message",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(samples)


def _run_case(
    case: dict[str, Any],
    *,
    workspace: BenchmarkWorkspace,
    worker_path: Path,
    dll_path: Path,
    runs: int,
    warmups: int,
    timeout_seconds: float,
    sample_interval: float,
) -> list[dict[str, Any]]:
    case_slug = str(case["case_id"]).replace(":", "-")
    worker_start = time.perf_counter_ns()
    worker = _NativeWorkerProcess(str(worker_path), None)
    worker_start_ms = round((time.perf_counter_ns() - worker_start) / 1_000_000.0, 3)
    sampler = ProcessSampler(interval_seconds=sample_interval)
    rows: list[dict[str, Any]] = []
    try:
        sampler.start()
        for warmup in range(warmups):
            output = workspace.outputs / case_slug / f"warmup-{warmup}"
            job = _case_job(case["item"], job_id=f"{case_slug}-warmup-{warmup}", output_dir=output, dll_path=dll_path)
            try:
                _run_job(worker, job, timeout_seconds=timeout_seconds, sampler=sampler)
            finally:
                if not workspace.keep_workdir:
                    shutil.rmtree(output, ignore_errors=True)
        for run in range(runs):
            output = workspace.outputs / case_slug / f"run-{run}"
            job = _case_job(case["item"], job_id=f"{case_slug}-run-{run}", output_dir=output, dll_path=dll_path)
            try:
                measured = _run_job(worker, job, timeout_seconds=timeout_seconds, sampler=sampler)
            finally:
                if not workspace.keep_workdir:
                    shutil.rmtree(output, ignore_errors=True)
            measured.update({
                "case_id": case["case_id"],
                "profile": case["profile"],
                "workload": case["workload"],
                "format": case["format"],
                "run": run,
                "archive_bytes": case["archive_bytes"],
                "payload_bytes": case["payload_bytes"],
                "volume_count": case["volume_count"],
                "worker_start_ms": worker_start_ms,
            })
            rows.append(measured)
    finally:
        sampler.stop()
        worker.close()
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the native 7z.dll worker across archive formats and sizes.")
    parser.add_argument("--profile", action="append", default=[], metavar="NAME", help="Size profile(s), comma-separated or repeated.")
    parser.add_argument("--format", action="append", default=[], choices=GENERATED_FORMATS, dest="formats", help="Archive format(s) to include.")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--sample-interval", type=float, default=0.02)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    try:
        profiles = _parse_csv_values(args.profile, set(SIZE_PROFILES), "--profile") or list(SIZE_PROFILES)
    except ValueError as exc:
        parser.error(str(exc))
    formats = list(dict.fromkeys(args.formats)) or list(GENERATED_FORMATS)
    if args.runs < 1 or args.warmups < 0:
        parser.error("--runs must be positive and --warmups must be non-negative")
    if args.timeout_seconds <= 0 or args.sample_interval <= 0:
        parser.error("--timeout-seconds and --sample-interval must be positive")

    try:
        worker_path = Path(get_sevenzip_bridge_worker_path()).resolve()
        dll_path = Path(get_7z_dll_path()).resolve()
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if not worker_path.is_file():
        parser.error(f"worker does not exist: {worker_path}")
    if not dll_path.is_file():
        parser.error(f"7z.dll does not exist: {dll_path}")

    scenario = "extraction.sevenzip-worker-matrix"
    with BenchmarkWorkspace(scenario, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        cases, corpus_info = _build_cases(workspace, profiles)
        cases = [case for case in cases if case["format"] in formats]
        if not cases:
            raise RuntimeError("no generated cases matched the requested profiles and formats")

        samples: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        for index, case in enumerate(cases, start=1):
            print(f"[{index}/{len(cases)}] {case['case_id']} archive={case['archive_bytes']}B", flush=True)
            try:
                rows = _run_case(
                    case,
                    workspace=workspace,
                    worker_path=worker_path,
                    dll_path=dll_path,
                    runs=max(1, args.runs),
                    warmups=max(0, args.warmups),
                    timeout_seconds=args.timeout_seconds,
                    sample_interval=args.sample_interval,
                )
            except Exception as exc:
                failures.append({"case_id": case["case_id"], "error": repr(exc)})
                print(f"  ERROR {exc}", flush=True)
                continue
            samples.extend(rows)
            print(
                f"  median_wall_ms={_median([row['worker_wall_ms'] for row in rows])} "
                f"peak_rss_mib={_median([row['worker_rss_peak_mib'] for row in rows])} "
                f"passed={all(row['passed'] for row in rows)}",
                flush=True,
            )

        summary = _summarize(samples)
        summary["case_count"] = len(cases)
        summary["case_failures"] = failures
        report = {
            "parameters": {
                "profiles": profiles,
                "formats": formats,
                "runs": max(1, args.runs),
                "warmups": max(0, args.warmups),
                "timeout_seconds": args.timeout_seconds,
                "sample_interval": args.sample_interval,
            },
            "environment": {
                "worker_path": str(worker_path),
                "seven_zip_dll_path": str(dll_path),
                "worker_size_bytes": worker_path.stat().st_size,
                "seven_zip_dll_size_bytes": dll_path.stat().st_size,
                "python": sys.version,
                "platform": sys.platform,
                "cpu_count": os.cpu_count(),
                "current_root": str(ROOT),
            },
            "corpus": corpus_info,
            "results": samples,
            "summary": summary,
            "artifacts": {"result_dir": str(workspace.result_dir)},
        }
        rendered = render_report(report_from_payload(scenario, report))
        workspace.write_result_text("report.json", rendered)
        _write_csv(workspace.result_dir / "results.csv", samples)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0 if summary["all_passed"] and not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
