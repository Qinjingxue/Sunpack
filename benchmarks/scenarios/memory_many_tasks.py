"""Memory-growth measurement for the Python pipeline and the native 7z worker.

Two phases run against one shared mixed-format corpus (every format the
format-matrix corpus builder can generate, each archive >= the scanner's
1 MiB recognition floor):

- Phase "python": drives the persistent-runtime extract pipeline over repeated
  rounds of the whole corpus (one ``extract`` invocation per round) and
  samples the Python process RSS, private bytes, tracemalloc allocations,
  native reader-cache state and mapped-memory breakdown after every round, so
  the growth trajectory of the main Python program under many tasks is visible
  round by round, plus the residual after the engine is closed.

- Phase "worker": starts one persistent ``sunpack_sevenzip_worker.exe`` and
  submits one job per corpus archive per round (formats interleaved),
  sampling the worker process RSS after every job, so both per-format and
  cumulative worker growth under a large job count can be read off the
  trajectory.

Both phases deliberately reuse the project harness (BenchmarkWorkspace,
render_report/report_from_payload) and the extraction format-matrix corpus
builder instead of introducing a second corpus policy.
"""
from __future__ import annotations

import argparse
import asyncio
import gc
import json
import os
import queue
import shutil
import statistics
import sys
import threading
import time
import tracemalloc
from pathlib import Path
from typing import Any

import psutil

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from benchmarks.scenarios.extraction_format_matrix import GENERATED_FORMATS, create_corpus
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.support.resources import get_sevenzip_bridge_worker_path
from tests.helpers.tool_config import get_7z_cli_dll_path


def _mapped_memory(process: psutil.Process) -> dict[str, float]:
    totals = {"anonymous_private_mib": 0.0, "image_private_mib": 0.0, "mapped_private_mib": 0.0}
    try:
        maps = process.memory_maps(grouped=False)
    except (psutil.AccessDenied, NotImplementedError):
        return totals
    for item in maps:
        private = float(getattr(item, "private", 0) or 0) / 1024 / 1024
        path = str(getattr(item, "path", "") or "")
        if not path or path.startswith("["):
            totals["anonymous_private_mib"] += private
        elif path.lower().endswith((".dll", ".pyd", ".exe")):
            totals["image_private_mib"] += private
        else:
            totals["mapped_private_mib"] += private
    return {key: round(value, 2) for key, value in totals.items()}


def _python_sample(label: str, traced: bool) -> dict:
    """Sample the current (Python) process, mirroring memory residual-rss."""
    if traced:
        gc.collect()
    process = psutil.Process()
    info = process.memory_info()
    current = peak = 0
    if traced:
        current, peak = tracemalloc.get_traced_memory()
    row: dict[str, Any] = {
        "label": label,
        "rss_mib": round(info.rss / 1024 / 1024, 2),
        "private_mib": round(getattr(info, "private", 0) / 1024 / 1024, 2),
        "python_traced_mib": round(current / 1024 / 1024, 2),
        "python_peak_mib": round(peak / 1024 / 1024, 2),
        "threads": process.num_threads(),
        "handles": process.num_handles(),
    }
    try:
        from sunpack_native import reader_cache_stats

        reader = dict(reader_cache_stats())
        row.update({
            "reader_open_handles": int(reader.get("open_handles", 0)),
            "reader_cache_entries": int(reader.get("cache_entries", 0)),
            "reader_cache_mib": round(
                (int(reader.get("hot_cache_bytes", 0)) + int(reader.get("general_cache_bytes", 0))) / 1024 / 1024,
                2,
            ),
        })
    except (ImportError, AttributeError):
        pass
    row.update(_mapped_memory(process))
    return row


def _worker_sample(label: str, process: psutil.Process) -> dict:
    """Sample the native worker process itself (not the Python parent).

    The worker may already be gone (e.g. sampled after ``close()``), in which
    case the row reports ``rss_mib: None`` instead of raising.
    """
    try:
        info = process.memory_info()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"label": label, "rss_mib": None, "exited": True}
    try:
        times = process.cpu_times()
        cpu_ms = round((float(times.user) + float(times.system)) * 1000.0, 2)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        cpu_ms = None
    row: dict[str, Any] = {
        "label": label,
        "rss_mib": round(info.rss / 1024 / 1024, 2),
        "private_mib": round(getattr(info, "private", 0) / 1024 / 1024, 2),
        "cpu_ms": cpu_ms,
        "threads": process.num_threads(),
        "exited": False,
    }
    try:
        row["handles"] = process.num_handles()
    except (AttributeError, psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    row.update(_mapped_memory(process))
    return row


def _volume_paths(item: dict[str, Any]) -> list[Path]:
    source = Path(item["path"])
    archive_format = str(item["format"])
    if archive_format == "7z-split":
        return sorted(source.parent.glob(f"{source.name.rsplit('.', 1)[0]}.*"))
    if archive_format == "rar-split":
        prefix = source.name.split(".part", 1)[0]
        return sorted(source.parent.glob(f"{prefix}.part*.rar"))
    return [source]


def _run_worker_job(
    worker: _NativeWorkerProcess,
    job: dict[str, Any],
    *,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Submit one job to the persistent worker and wait for its result.

    Mirrors the completion protocol used by the sevenzip-worker-matrix
    scenario: the stdout dispatcher feeds lines to on_line, completion is
    signalled by the native ``job_finished`` event once the result arrived.
    """
    payload = json.dumps(job, ensure_ascii=False, separators=(",", ":"))
    job_id = str(job["job_id"])
    started = time.perf_counter_ns()
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
            raise RuntimeError(f"worker exited while running job: {job_id}")
    if failure:
        raise RuntimeError(f"worker failed while running job: {job_id}; {failure[-1]}")
    if result is None:
        raise RuntimeError(f"worker closed before returning a result: {job_id}")
    elapsed_ms = round((time.perf_counter_ns() - started) / 1_000_000.0, 3)
    return {
        "job_id": job_id,
        "status": str(result.get("status") or ""),
        "passed": str(result.get("status") or "") == "ok",
        "worker_wall_ms": elapsed_ms,
        "files_written": int(result.get("files_written", 0) or 0),
        "bytes_written": int(result.get("bytes_written", 0) or 0),
        "message": str(result.get("message", "")),
    }


def _run_python_phase(
    workspace: BenchmarkWorkspace,
    corpus: dict[str, dict[str, Any]],
    rounds: int,
) -> list[dict[str, Any]]:
    """Extract the whole corpus repeatedly through the persistent pipeline."""
    from sunpack.cli import persistent_runtime
    from sunpack.cli.cli import async_main

    tracemalloc.start(10)
    rows: list[dict[str, Any]] = []
    paths = [str(item["path"]) for item in corpus.values()]
    persistent_runtime.enable_persistent_runtime()
    try:
        rows.append(_python_sample("python-baseline", traced=True))

        async def run_rounds() -> None:
            for round_index in range(1, rounds + 1):
                out_dir = workspace.outputs / f"python-round-{round_index}"
                out_dir.mkdir(parents=True, exist_ok=True)
                started = time.perf_counter()
                code = await async_main([
                    "extract", *paths, "--direct-file", "--out-dir", str(out_dir),
                    "--cleanup", "k", "--no-flatten", "--no-pause", "--quiet",
                ])
                elapsed = time.perf_counter() - started
                if code:
                    raise RuntimeError(f"python phase round {round_index} failed: {code}")
                print(
                    f"python round {round_index}/{rounds} done in {elapsed:.2f}s "
                    f"({len(paths)} archives)",
                    file=sys.stderr,
                    flush=True,
                )
                rows.append(_python_sample(f"python-round-{round_index}", traced=True))
            await persistent_runtime.close_persistent_runtime()
            rows.append(_python_sample("python-after-engine-close", traced=True))

        asyncio.run(run_rounds())
        from sunpack_native import release_reader_handles_under

        release_reader_handles_under(str(workspace.root))
        rows.append(_python_sample("python-after-reader-handle-release", traced=True))
    finally:
        try:
            asyncio.run(persistent_runtime.close_persistent_runtime())
        except Exception:
            pass
    return rows


def _run_worker_phase(
    workspace: BenchmarkWorkspace,
    corpus: dict[str, dict[str, Any]],
    rounds: int,
    *,
    worker_path: Path,
    dll_path: Path,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    """Feed every corpus archive repeatedly through one persistent worker."""
    worker = _NativeWorkerProcess(str(worker_path), None)
    rows: list[dict[str, Any]] = []
    try:
        if worker.process is None:
            raise RuntimeError("worker did not start")
        worker_proc = psutil.Process(worker.process.pid)
        rows.append(_worker_sample("worker-baseline", worker_proc))
        cases = sorted(corpus.items())
        for round_index in range(1, rounds + 1):
            for case_index, (name, item) in enumerate(cases, 1):
                label = f"worker-r{round_index}-{name.replace(':', '-')}"
                output_dir = workspace.outputs / f"worker-round-{round_index}" / f"{case_index:03d}-{name.replace(':', '-')}"
                volumes = _volume_paths(item)
                job = {
                    "job_id": label,
                    "archive_path": str(volumes[0]),
                    "part_paths": [str(path) for path in volumes],
                    "output_dir": str(output_dir),
                    "password": "",
                    "format_hint": "",
                }
                outcome = _run_worker_job(worker, job, timeout_seconds=timeout_seconds)
                sample = _worker_sample(label, worker_proc)
                sample.update({
                    "round": round_index,
                    "case_index": case_index,
                    "format": str(item["format"]),
                    "workload": str(item.get("workload")),
                    "archive_bytes": Path(item["path"]).stat().st_size,
                    **outcome,
                })
                rows.append(sample)
                print(
                    f"worker round {round_index}/{rounds} case {case_index}/{len(cases)} "
                    f"{name} rss={sample['rss_mib']}MiB "
                    f"wall={outcome['worker_wall_ms']}ms status={outcome['status']}",
                    file=sys.stderr,
                    flush=True,
                )
            shutil.rmtree(workspace.outputs / f"worker-round-{round_index}", ignore_errors=True)
        worker.close()
        rows.append(_worker_sample("worker-after-close", worker_proc))
    finally:
        worker.close()
    return rows


def _trajectory_summary(rows: list[dict[str, Any]], baseline_label: str, tail_label: str) -> dict[str, Any]:
    baseline = next((row for row in rows if row["label"] == baseline_label), None)
    tail = next((row for row in rows if row["label"] == tail_label), None)
    if baseline is None or baseline.get("rss_mib") is None:
        return {}
    numeric = [row for row in rows if row.get("rss_mib") is not None]
    rss_values = [float(row["rss_mib"]) for row in numeric]
    if not rss_values:
        return {}
    final_row = tail if tail is not None and tail.get("rss_mib") is not None else numeric[-1]
    summary: dict[str, Any] = {
        "baseline_rss_mib": baseline["rss_mib"],
        "peak_rss_mib": max(rss_values),
        "final_rss_mib": final_row["rss_mib"],
        "growth_mib": round(float(final_row["rss_mib"]) - float(baseline["rss_mib"]), 2),
        "peak_growth_mib": round(max(rss_values) - float(baseline["rss_mib"]), 2),
        "exited": bool(tail is not None and tail.get("exited")),
    }
    deltas: list[dict[str, Any]] = []
    previous = float(baseline["rss_mib"])
    for row in rows:
        if row["label"] == baseline_label or row.get("rss_mib") is None:
            continue
        current = float(row["rss_mib"])
        deltas.append({
            "label": row["label"],
            "rss_mib": current,
            "delta_from_previous_mib": round(current - previous, 2),
            "delta_from_baseline_mib": round(current - float(baseline["rss_mib"]), 2),
        })
        previous = current
    summary["trajectory"] = deltas
    return summary


def _python_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary = _trajectory_summary(rows, "python-baseline", "python-after-reader-handle-release")
    after_close = next((row for row in rows if row["label"] == "python-after-engine-close"), None)
    baseline = next((row for row in rows if row["label"] == "python-baseline"), None)
    if after_close is not None and baseline is not None:
        summary["residual_after_engine_close_mib"] = round(after_close["rss_mib"] - baseline["rss_mib"], 2)
    return summary


def _worker_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary = _trajectory_summary(rows, "worker-baseline", "worker-after-close")
    by_format: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("format") is None:
            continue
        by_format.setdefault(str(row["format"]), []).append(row)
    per_format: dict[str, Any] = {}
    for format_name, format_rows in sorted(by_format.items()):
        first = format_rows[0]
        last = format_rows[-1]
        per_format[format_name] = {
            "jobs": len(format_rows),
            "first_rss_mib": first["rss_mib"],
            "last_rss_mib": last["rss_mib"],
            "growth_mib": round(last["rss_mib"] - first["rss_mib"], 2),
            "passed": sum(bool(row.get("passed")) for row in format_rows),
        }
    summary["per_format_growth_mib"] = per_format
    summary["total_jobs"] = sum(1 for row in rows if row.get("job_id"))
    summary["passed_jobs"] = sum(1 for row in rows if row.get("passed"))
    summary["failed_jobs"] = sum(1 for row in rows if row.get("job_id") and not row.get("passed"))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Memory growth of the Python pipeline and the native 7z worker across many tasks and formats."
    )
    parser.add_argument("--format", action="append", default=[], choices=GENERATED_FORMATS, dest="formats")
    parser.add_argument("--python-rounds", type=int, default=5)
    parser.add_argument("--worker-rounds", type=int, default=3)
    parser.add_argument("--small-files", type=int, default=1100, help="Small payload file count (keeps archives above the 1 MiB floor).")
    parser.add_argument("--large-files", type=int, default=1)
    parser.add_argument("--large-file-mib", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=300.0, help="Per worker-job wall-clock timeout.")
    parser.add_argument("--skip-python", action="store_true")
    parser.add_argument("--skip-worker", action="store_true")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    if args.python_rounds < 0 or args.worker_rounds < 1 or args.small_files < 1 or args.timeout_seconds <= 0:
        parser.error("--python-rounds must be >= 0, --worker-rounds >= 1, --small-files >= 1, --timeout-seconds > 0")
    if args.skip_python and args.skip_worker:
        parser.error("at least one of --skip-python / --skip-worker must be false")

    try:
        worker_path = Path(get_sevenzip_bridge_worker_path()).resolve()
        dll_path = Path(get_7z_cli_dll_path()).resolve()
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if not worker_path.is_file():
        parser.error(f"worker does not exist: {worker_path}")
    if not dll_path.is_file():
        parser.error(f"7z.dll does not exist: {dll_path}")

    scenario = "memory.many-tasks"
    with BenchmarkWorkspace(scenario, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        print("building mixed-format corpus ...", file=sys.stderr, flush=True)
        started = time.perf_counter()
        corpus, skipped = create_corpus(
            workspace.corpus,
            {},
            max(1, args.small_files),
            max(1, args.large_files),
            max(1, args.large_file_mib),
        )
        print(
            f"corpus ready in {time.perf_counter() - started:.1f}s: {len(corpus)} archives, "
            f"skipped={sorted(skipped)}",
            file=sys.stderr,
            flush=True,
        )
        if args.formats:
            selected = set(args.formats)
            corpus = {name: item for name, item in corpus.items() if item["format"] in selected}
        if not corpus:
            raise RuntimeError("no corpus archives matched the requested formats")

        python_rows: list[dict[str, Any]] = []
        worker_rows: list[dict[str, Any]] = []
        if not args.skip_python:
            print("python phase: driving persistent-runtime extract pipeline ...", file=sys.stderr, flush=True)
            python_rows = _run_python_phase(workspace, corpus, max(1, args.python_rounds))
        if not args.skip_worker:
            print("worker phase: driving persistent native worker ...", file=sys.stderr, flush=True)
            worker_rows = _run_worker_phase(
                workspace,
                corpus,
                max(1, args.worker_rounds),
                worker_path=worker_path,
                dll_path=dll_path,
                timeout_seconds=args.timeout_seconds,
            )

        report = {
            "parameters": {
                "python_rounds": max(0, args.python_rounds),
                "worker_rounds": max(1, args.worker_rounds),
                "small_files": max(1, args.small_files),
                "large_files": max(1, args.large_files),
                "large_file_mib": max(1, args.large_file_mib),
                "formats": sorted({str(item["format"]) for item in corpus.values()}),
                "skip_python": args.skip_python,
                "skip_worker": args.skip_worker,
                "worker_job_timeout_seconds": args.timeout_seconds,
            },
            "environment": {
                "python": sys.version,
                "platform": sys.platform,
                "cpu_count": os.cpu_count(),
                "current_root": str(ROOT),
                "worker_path": str(worker_path),
            },
            "corpus": {
                "archive_count": len(corpus),
                "by_format": {
                    format_name: sum(1 for item in corpus.values() if item["format"] == format_name)
                    for format_name in sorted({str(item["format"]) for item in corpus.values()})
                },
                "skipped_formats": sorted(skipped),
            },
            "python_samples": python_rows,
            "worker_samples": worker_rows,
            "summary": {
                "python": _python_summary(python_rows),
                "worker": _worker_summary(worker_rows),
            },
            "artifacts": {"result_dir": str(workspace.result_dir)},
        }
        rendered = render_report(report_from_payload(scenario, report))
        workspace.write_result_text("report.json", rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
