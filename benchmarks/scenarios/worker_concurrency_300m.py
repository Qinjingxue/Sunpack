"""Real single-worker versus multi-process 7z throughput on the 300 MiB matrix.

Python only orchestrates jobs and inspects metadata. Fixture bytes are generated
in Rust, and the existing format builder and worker protocol are reused.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import threading
import time
import psutil

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler
from benchmarks.scenarios.extraction_format_matrix import create_corpus
from benchmarks.scenarios.worker_read_patterns import _build_cases
from benchmarks.scenarios.sevenzip_worker_matrix import _case_job, _output_summary, _volume_paths
from benchmarks.scenarios.worker_vs_7z_300m import DEFAULT_FORMATS, _collect_environment, _git_commit
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path
from sunpack.core.support.output_paths import resolve_output_volume_key
from tests.helpers.tool_config import get_7z_cli_dll_path, require_7z

MIB = 1024 ** 2
STREAMS = {"gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "tzst"}


def host_busy_ms():
    times = psutil.cpu_times()
    return (times.user + times.system) * 1000


def cpu_ms(process):
    """Windows keeps counters on the owned process handle after CLI exit."""
    creation, exit_time, kernel, user = (wintypes.FILETIME() for _ in range(4))
    api = ctypes.WinDLL("kernel32", use_last_error=True).GetProcessTimes
    api.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    api.restype = wintypes.BOOL
    if not api(wintypes.HANDLE(int(process._handle)), *(ctypes.byref(v) for v in (creation, exit_time, kernel, user))):
        raise ctypes.WinError(ctypes.get_last_error())
    return sum((v.dwHighDateTime << 32) + v.dwLowDateTime for v in (kernel, user)) / 10000


def prepare(workspace, cache):
    manifest = cache / "cases.json"
    if manifest.is_file():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        cases = data["cases"]
        for case in cases:
            case["item"]["path"] = Path(case["item"]["path"])
            if not case["item"]["path"].is_file():
                raise FileNotFoundError(case["item"]["path"])
        return cases, data["corpus"]
    cache.mkdir(parents=True, exist_ok=True)
    generator = workspace.work / "mixed_payload.exe"
    subprocess.run(["rustc", "-O", str(ROOT / "benchmarks/harness/mixed_payload.rs"), "-o", str(generator)], check=True)
    subprocess.run([str(generator), str(cache / "payloads"), "150"], check=True)
    corpus, skipped = create_corpus(cache, {}, 8, 2, 150, progress=lambda s: print(s, flush=True),
                                    payloads={"few_large": cache / "payloads/few-large", "many_small": cache / "payloads/many-small"},
                                    copy_file=lambda source, dest: subprocess.run([str(generator), "--copy", str(source), str(dest)], check=True))
    # Existing case/solid-variant builder accepts a prepared corpus.
    from types import SimpleNamespace
    cases, info = _build_cases(SimpleNamespace(corpus=cache), list(DEFAULT_FORMATS), small_files=8,
                              large_files=2, large_file_mib=150, seven_zip_variants={"solid", "non-solid"},
                              large_content="mixed", cached_corpus=corpus, cache_info={"path": str(cache), "skipped": skipped})
    if len(cases) != 18:
        raise RuntimeError(f"Expected 18 generated format/variant cases, got {len(cases)}: {skipped}")
    info["generator"] = "Rust xorshift64 seed 20260729; 150 MiB repeated text + 150 MiB random; differs from historical Python random fixture"
    manifest.write_text(json.dumps({"cases": cases, "corpus": info}, default=str, indent=2), encoding="utf-8")
    return cases, info


def run_worker(worker, cases, outputs, concurrency, dll, timeout, dry_run=False):
    condition = threading.Condition()
    pending, completed, starts, results, failures = set(), [], {}, {}, {}
    cpu_events = []
    active, max_active = 0, 0
    before = cpu_ms(worker.process)
    volume_key = resolve_output_volume_key(str(outputs))
    if not volume_key:
        raise RuntimeError("Cannot resolve output volume; refusing per-job synthetic writers")
    sampler = ProcessSampler(interval_seconds=0.02)
    sampler.start()
    host_before = host_busy_ms()
    started = time.perf_counter()

    def callbacks(job_id):
        def on_line(_line, event):
            nonlocal active, max_active
            now = time.perf_counter()
            with condition:
                if event.get("type") == "native_event":
                    if event.get("event") == "job_started":
                        starts[job_id] = now
                        active += 1
                        max_active = max(active, max_active)
                    elif event.get("event") == "job_finished":
                        active -= int(job_id in starts)
                        completed.append({"job_id": job_id, "start_ms": (starts.get(job_id, now) - started) * 1000,
                                          "finish_ms": (now - started) * 1000})
                        pending.discard(job_id)
                        condition.notify_all()
                        return True
                elif event.get("type") == "result":
                    results[job_id] = event
                elif event.get("type") == "native_cpu":
                    cpu_events.append(event)
            return False
        def on_failure(message):
            with condition:
                failures[job_id] = message
                pending.discard(job_id)
                condition.notify_all()
        return on_line, on_failure

    try:
        next_job = 0
        while True:
            submissions = []
            with condition:
                if next_job == len(cases) and not pending:
                    break
                while next_job < len(cases) and len(pending) < concurrency:
                    job_id = f"{outputs.name}-{next_job}"
                    job = _case_job(cases[next_job]["item"], job_id=job_id, output_dir=outputs / str(next_job), dll_path=dll)
                    job["output_volume_key"] = volume_key
                    job["dry_run"] = dry_run
                    on_line, on_failure = callbacks(job_id)
                    pending.add(job_id)
                    submissions.append((job, job_id, on_line, on_failure))
                    next_job += 1
            # Pipe writes can block while the worker emits events; callbacks
            # must be free to acquire the condition and drain stdout meanwhile.
            for job, job_id, on_line, on_failure in submissions:
                worker.submit_async(json.dumps(job, ensure_ascii=False), job_id, on_line=on_line,
                                    on_timeout=on_failure, parsed_events=True)
            with condition:
                if pending and (next_job == len(cases) or len(pending) >= concurrency):
                    remaining = timeout - (time.perf_counter() - started)
                    if remaining <= 0:
                        raise TimeoutError(f"Incomplete worker jobs: {pending}")
                    condition.wait(min(remaining, 1))
                    if not worker.is_alive():
                        raise RuntimeError("worker exited")
        wall_ms = (time.perf_counter() - started) * 1000
        cpu = cpu_ms(worker.process) - before
        host_cpu = host_busy_ms() - host_before
    finally:
        sampler.stop()
    return {"wall_ms": wall_ms, "cpu_ms": cpu, "cpu_cores": cpu / wall_ms,
            "host_cpu_cores": host_cpu / wall_ms, "other_cpu_cores": max(0, host_cpu - cpu) / wall_ms,
            "rss_peak_mib": max(s.children_rss_mib for s in sampler.samples), "max_active": max_active,
            "passed": not failures and len(results) == len(cases) and all(r.get("status") == "ok" for r in results.values()),
            "failures": failures, "timeline": completed,
            "cpu_events": cpu_events,
            "diagnostics": [{k: v for k, v in r.items() if k in {"input_trace", "pipeline_timing", "cpu_budget", "status", "message"}} for r in results.values()]}


def run_cli(seven, cases, outputs, concurrency, timeout, dry_run=False):
    lock = threading.Lock()
    active, max_active = 0, 0
    sampler = ProcessSampler(interval_seconds=0.02)
    sampler.start()
    host_before = host_busy_ms()
    started = time.perf_counter()

    def extract(pair):
        nonlocal active, max_active
        index, case = pair
        with lock:
            active += 1
            max_active = max(active, max_active)
        begin = time.perf_counter()
        try:
            command = [str(seven), "t" if dry_run else "x", "-y", "-bd", "-bso0", "-bse0", "-aoa"]
            if not dry_run:
                command.append(f"-o{outputs / str(index)}")
            command.append(str(_volume_paths(case["item"])[0]))
            process = subprocess.Popen(command,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                _, error = process.communicate(timeout=timeout)
            except BaseException:
                process.kill()
                process.communicate()
                raise
            return {"returncode": process.returncode, "cpu_ms": cpu_ms(process),
                    "start_ms": (begin - started) * 1000, "finish_ms": (time.perf_counter() - started) * 1000,
                    "error": error.decode("utf-8", errors="replace")[-1000:]}
        finally:
            with lock:
                active -= 1
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            rows = list(pool.map(extract, enumerate(cases)))
        wall_ms = (time.perf_counter() - started) * 1000
        host_cpu = host_busy_ms() - host_before
    finally:
        sampler.stop()
    cpu = sum(r["cpu_ms"] for r in rows)
    return {"wall_ms": wall_ms, "cpu_ms": cpu, "cpu_cores": cpu / wall_ms,
            "host_cpu_cores": host_cpu / wall_ms, "other_cpu_cores": max(0, host_cpu - cpu) / wall_ms,
            "rss_peak_mib": max(s.children_rss_mib for s in sampler.samples), "max_active": max_active,
            "passed": all(r["returncode"] == 0 for r in rows), "timeline": rows}


def validate(row, cases, output, tar_bytes):
    stats = [_output_summary(output / str(i)) for i in range(len(cases))]
    row["output_stats"] = stats
    row["passed"] = row["passed"] and all(s["total_bytes"] == (tar_bytes if c["format"] in STREAMS else 300 * MIB)
                                             and s["file_count"] == (1 if c["format"] in STREAMS else 2)
                                             for c, s in zip(cases, stats))
    row["throughput_mib_s"] = len(cases) * 300 * 1000 / row["wall_ms"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--concurrency", default="8")
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--format", action="append", choices=DEFAULT_FORMATS)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--worker-capacity", type=int, help="Override native total CPU credits; default uses product defaults")
    parser.add_argument("--writer-threads", type=int, choices=range(1, 9), help="Diagnostic: override writers per volume")
    parser.add_argument("--no-mixed", action="store_true", help="Only homogeneous format batches")
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--prefetch", choices=("on", "off"), default="on", help="Use the product's format-aware prefetch policy by default")
    parser.add_argument("--dry-run", action="store_true", help="Diagnostic: decode/verify without output writes; compare 7z t")
    parser.add_argument("--resume", action="store_true", help="Reuse completed paired batches with identical binary/settings fingerprints")
    parser.add_argument("--cache-root", type=Path, default=ROOT / "benchmarks/.cache/worker-concurrency-300m")
    parser.add_argument("--json-out", type=Path, default=ROOT / "benchmarks/results/worker-concurrency-300m.json")
    args = parser.parse_args()
    widths = sorted(set(int(c) for c in args.concurrency.split(",")))
    if args.runs < 1 or not widths or min(widths) < 1 or max(widths) > 32:
        parser.error("runs > 0 and concurrency 1..32 required")
    worker_path = (args.worker or Path(get_sevenzip_bridge_worker_path())).resolve()
    seven, dll = require_7z().resolve(), Path(get_7z_cli_dll_path()).resolve()
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "1" if args.profile else "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "1" if args.profile else "0"
    os.environ["SUNPACK_SEVENZIP_PREFETCH"] = "1" if args.prefetch == "on" else "0"
    with BenchmarkWorkspace("extraction.worker-concurrency-300m") as workspace:
        cases, corpus = prepare(workspace, args.cache_root.resolve())
        tar_bytes = next(_volume_paths(c["item"])[0].stat().st_size for c in cases if c["format"] == "tar")
        if args.format:
            cases = [c for c in cases if c["format"] in args.format]
        binaries = {}
        for name, path in {"worker": worker_path, "7z": seven, "dll": dll}.items():
            literal = "'" + str(path).replace("'", "''") + "'"
            script = f"$stream=[IO.File]::OpenRead({literal}); $hash=[Security.Cryptography.SHA256]::Create(); try {{ [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '') }} finally {{ $stream.Dispose(); $hash.Dispose() }}"
            result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", script], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
            binaries[name] = {"path": str(path), "sha256": result.stdout.strip()}
        report = {"source_commit": _git_commit(), "binaries": binaries, "environment": _collect_environment(workspace.root),
                  "corpus": corpus, "cases": cases, "concurrency": widths, "runs": args.runs,
                  "worker_capacity": args.worker_capacity, "profile": args.profile, "dry_run": args.dry_run,
                  "writer_threads": args.writer_threads, "mixed_enabled": not args.no_mixed,
                  "prefetch": args.prefetch,
                  "complete": False,
                  "method": "Same cached input, unique outputs. Single persistent worker with product CPU budget; c fresh 7z processes. c jobs per homogeneous burst, fixed two rounds of all formats per mixed batch. Three paired trials, alternating order; no cache flush, no fsync. Output validation/cleanup outside timer. RSS sampled every 20ms; CPU from Windows process handles.",
                  "results": []}
        if args.resume and args.json_out.is_file():
            previous = json.loads(args.json_out.read_text(encoding="utf-8"))
            for key in ("source_commit", "binaries", "concurrency", "runs", "worker_capacity", "profile"):
                if previous[key] != report[key]:
                    raise ValueError(f"Cannot resume with changed {key}")
            if previous.get("dry_run", False) != args.dry_run:
                raise ValueError("Cannot resume a different output mode")
            if previous.get("writer_threads") != args.writer_threads or previous.get("mixed_enabled", True) != (not args.no_mixed):
                raise ValueError("Cannot resume a different writer/workload configuration")
            if previous.get("prefetch", "off") != args.prefetch:
                raise ValueError("Cannot resume a different prefetch configuration")
            if [c["case_id"] for c in previous["cases"]] != [c["case_id"] for c in cases]:
                raise ValueError("Cannot resume a different format selection")
            report["results"] = previous["results"]
        finished_batches = {(r["case_id"], r["concurrency"]) for r in report["results"]}
        workloads = [(c["case_id"], [c]) for c in cases]
        if not args.no_mixed:
            workloads.append(("mixed", cases * 2))
        for case_id, base in workloads:
            config = {} if args.worker_capacity is None else {"thread_capacity": args.worker_capacity}
            if args.writer_threads is not None:
                config["writer_threads"] = args.writer_threads
            worker = _NativeWorkerProcess(str(worker_path), None, config)
            try:
                for width in widths:
                    if (case_id, width) in finished_batches:
                        continue
                    batch = base if case_id == "mixed" else base * width
                    record = {"case_id": case_id, "concurrency": width, "jobs": len(batch), "worker": [], "7z": []}
                    for run in range(args.runs):
                        for engine in (("worker", "7z") if run % 2 == 0 else ("7z", "worker")):
                            output = workspace.outputs / f"batch-{len(report['results'])}-{run}-{engine}"
                            try:
                                row = (run_worker(worker, batch, output, width, dll, 900, args.dry_run) if engine == "worker"
                                       else run_cli(seven, batch, output, width, 900, args.dry_run))
                                if args.dry_run:
                                    row["throughput_mib_s"] = len(batch) * 300 * 1000 / row["wall_ms"]
                                else:
                                    validate(row, batch, output, tar_bytes)
                                record[engine].append(row)
                                if not row["passed"]:
                                    raise RuntimeError(f"Invalid {engine} output: {case_id} c={width}")
                            finally:
                                target = output.resolve()
                                if workspace.outputs.resolve() not in target.parents:
                                    raise ValueError("cleanup escaped workspace")
                                shutil.rmtree(target, ignore_errors=True)
                    record["median"] = {engine: {key: statistics.median(r[key] for r in record[engine])
                                                   for key in ("wall_ms", "throughput_mib_s", "rss_peak_mib", "cpu_cores", "max_active")}
                                        for engine in ("worker", "7z")}
                    record["speedup"] = record["median"]["7z"]["wall_ms"] / record["median"]["worker"]["wall_ms"]
                    report["results"].append(record)
                    args.json_out.parent.mkdir(parents=True, exist_ok=True)
                    args.json_out.write_text(json.dumps(report, default=str, ensure_ascii=False, indent=2), encoding="utf-8")
                    print(f"{case_id} c={width}: worker={record['median']['worker']['wall_ms']:.1f}ms 7z={record['median']['7z']['wall_ms']:.1f}ms speedup={record['speedup']:.2f} active={record['median']['worker']['max_active']}", flush=True)
            finally:
                worker.close()
        report["complete"] = True
        args.json_out.write_text(json.dumps(report, default=str, ensure_ascii=False, indent=2), encoding="utf-8")
        workspace.write_result_json("report.json", report)
        print(args.json_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
