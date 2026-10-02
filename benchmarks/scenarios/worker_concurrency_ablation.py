"""Diagnostic ablations for the parallel worker-versus-7z gap.

Reuses the 300 MiB cached corpus and the concurrency scenario's worker/CLI
drivers, then varies one worker-side knob per variant so the root cause of the
parallel deficit can be measured instead of guessed. Python only orchestrates
processes and reads metadata; all fixture bytes and extraction work stay native.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
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
from benchmarks.scenarios.worker_concurrency_300m import (
    cpu_ms,
    host_busy_ms,
    prepare,
    run_cli,
    run_worker,
    validate,
    _volume_paths,
)
from benchmarks.scenarios.sevenzip_worker_matrix import _case_job
from benchmarks.scenarios.worker_vs_7z_300m import _collect_environment, _git_commit
from sunpack.core.support.output_paths import resolve_output_volume_key
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from tests.helpers.tool_config import get_7z_cli_dll_path, require_7z

MIB = 1024 ** 2
# (name, worker process_config, extra environment). The first entry is the
# product default; every other entry changes exactly one input.
VARIANTS: dict[str, tuple[dict, dict]] = {
    "default": ({}, {}),
    "writers1": ({"writer_threads": 1}, {}),
    "writers8": ({"writer_threads": 8}, {}),
    "writers16": ({"writer_threads": 16}, {}),
    "writers32": ({"writer_threads": 32}, {}),
    "buffers256": ({}, {"SUNPACK_ASYNC_WRITER_BUFFERS": "256"}),
    "spacegate_off": ({}, {"SUNPACK_VOLUME_SPACE_GATE": "0"}),
    "cap8": ({"thread_capacity": 8}, {}),
    "cap16": ({"thread_capacity": 16}, {}),
    "cap64": ({"thread_capacity": 64}, {}),
    "prefetch_off": ({}, {"SUNPACK_SEVENZIP_PREFETCH": "0"}),
    "no_job_inflight": ({}, {"SUNPACK_ABLATE_JOB_INFLIGHT": "1"}),
}


def thread_cpu_ms(proc: psutil.Process) -> dict:
    """Per-thread Windows CPU split; counters stay readable after threads exit only for the process."""
    kernel, user = wintypes.FILETIME(), wintypes.FILETIME()
    creation, exit_time = wintypes.FILETIME(), wintypes.FILETIME()
    handle = ctypes.WinDLL("kernel32", use_last_error=True).OpenProcess
    handle.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    handle.restype = wintypes.HANDLE
    close = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    ph = handle(0x0400 | 0x0010, False, proc.pid)
    if not ph:
        return {}
    try:
        if not kernel32.GetProcessTimes(ph, *(ctypes.byref(v) for v in (creation, exit_time, kernel, user))):
            return {}
    finally:
        close(ph)
    ticks = lambda v: (v.dwHighDateTime << 32) + v.dwLowDateTime
    return {"user_ms": ticks(user) / 10000.0, "kernel_ms": ticks(kernel) / 10000.0}


class ThreadSampler:
    """Samples per-thread CPU time so thread count and lane spread are visible."""

    def __init__(self, interval=0.005):
        self.interval = interval
        self.samples: list[dict] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, proc: psutil.Process):
        def loop():
            while not self._stop.is_set():
                try:
                    threads = proc.threads()
                except Exception:
                    return
                total = sum(t.user_time + t.system_time for t in threads)
                self.samples.append({"wall": time.perf_counter(), "count": len(threads), "cpu_s": total})
                self._stop.wait(self.interval)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def summary(self) -> dict:
        if len(self.samples) < 2:
            return {}
        counts = [s["count"] for s in self.samples]
        # Instantaneous runnable-ish estimate: CPU delta over wall delta per sample.
        active = []
        for a, b in zip(self.samples, self.samples[1:]):
            dt = b["wall"] - a["wall"]
            if dt > 0:
                active.append((b["cpu_s"] - a["cpu_s"]) / dt)
        return {
            "threads_max": max(counts),
            "threads_median": statistics.median(counts),
            "cpu_cores_median": statistics.median(active),
            "cpu_cores_p90": sorted(active)[int(len(active) * 0.9)] if active else 0.0,
            "cpu_cores_max": max(active) if active else 0.0,
        }


def measure(worker, batch, output, width, dll, timeout, kind, dry_run=False):
    """Wrap the existing drivers so CPU split and thread spread are recorded."""
    sampler = ThreadSampler()
    sampler.start(worker.process)
    before = thread_cpu_ms(worker.process)
    started = time.perf_counter()
    row = run_worker(worker, batch, output, width, dll, timeout, dry_run)
    row["threads"] = sampler.summary()
    sampler.stop()
    after = thread_cpu_ms(worker.process)
    row["cpu_split"] = {k: after.get(k, 0) - before.get(k, 0) for k in ("user_ms", "kernel_ms")}
    row["kind"] = kind
    row["wall_recheck_ms"] = (time.perf_counter() - started) * 1000
    return row


def summarise(rows):
    keys = ("wall_ms", "cpu_cores", "rss_peak_mib", "max_active", "throughput_mib_s",
            "host_cpu_cores", "other_cpu_cores")
    out = {k: statistics.median(r[k] for r in rows) for k in keys if k in rows[0]}
    for key in ("user_ms", "kernel_ms"):
        out[key] = statistics.median(r["cpu_split"].get(key, 0) for r in rows)
    threads = [r.get("threads") or {} for r in rows]
    for key in ("threads_max", "threads_median", "cpu_cores_median", "cpu_cores_p90", "cpu_cores_max"):
        values = [t[key] for t in threads if key in t]
        if values:
            out[key] = statistics.median(values)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--format", action="append", required=True,
                        help="Case format selector, e.g. 7z, xz, txz, tar, tgz, gz, zip")
    parser.add_argument("--variant", action="append", help="Subset of ablation variants")
    parser.add_argument("--concurrency", default="1,4,8")
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--reference", action="store_true", help="Also run concurrent 7z.exe")
    parser.add_argument("--dry", action="store_true",
                        help="Decode/verify only: worker dry_run and 7z t, no output writes")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--keep-outputs", action="store_true")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()

    widths = sorted({int(x) for x in args.concurrency.split(",")})
    variants = args.variant or list(VARIANTS)
    for name in variants:
        if name not in VARIANTS:
            parser.error(f"unknown variant {name}")
    seven, dll = require_7z().resolve(), Path(get_7z_cli_dll_path()).resolve()
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "0"
    os.environ["SUNPACK_WRITER_PROBE"] = "0"
    worker_path = args.worker.resolve()

    report = {"source_commit": _git_commit(), "worker": str(worker_path),
              "variants": variants, "concurrency": widths, "runs": args.runs,
              "format_selector": args.format, "complete": False, "results": []}
    with BenchmarkWorkspace("extraction.worker-concurrency-ablation") as workspace:
        cases, corpus = prepare(workspace, ROOT / "benchmarks/.cache/worker-concurrency-300m")
        report["corpus"] = corpus
        report["environment"] = _collect_environment(workspace.root)
        tar_bytes = next(_volume_paths(c["item"])[0].stat().st_size for c in cases if c["format"] == "tar")
        selected = []
        for selector in args.format:
            for case in cases:
                if case["format"] == selector and case not in selected:
                    selected.append(case)
        report["cases"] = [c["case_id"] for c in selected]
        volume_key = resolve_output_volume_key(str(workspace.outputs))
        if not volume_key:
            raise RuntimeError("Cannot resolve output volume identity")

        for case in selected:
            for width in widths:
                batch = [case] * width
                records = {name: [] for name in variants}
                records["cli"] = []
                for run in range(args.runs):
                    order = list(variants) + (["cli"] if args.reference else [])
                    if run % 2:
                        order = list(reversed(order))
                    for name in order:
                        tag = f"{case['format']}-{width}-{name}-{run}"
                        output = workspace.outputs / tag
                        saved = {k: os.environ.get(k) for k in
                                 ("SUNPACK_ASYNC_WRITER_BUFFERS", "SUNPACK_VOLUME_SPACE_GATE",
                                  "SUNPACK_SEVENZIP_PREFETCH", "SUNPACK_ABLATE_JOB_INFLIGHT")}
                        try:
                            if name == "cli":
                                row = run_cli(seven, batch, output, width, args.timeout, args.dry)
                                row["cpu_split"] = {"user_ms": 0.0, "kernel_ms": 0.0}
                                row["threads"] = {}
                            else:
                                config, env = VARIANTS[name]
                                os.environ.update(env)
                                worker = _NativeWorkerProcess(str(worker_path), None, dict(config))
                                try:
                                    row = measure(worker, batch, output, width, dll, args.timeout,
                                                  name, args.dry)
                                finally:
                                    worker.close()
                            row["variant"] = name
                            row["run"] = run
                            row["jobs"] = len(batch)
                            if not args.dry:
                                validate(row, batch, output, tar_bytes)
                            row["throughput_mib_s"] = len(batch) * 300 * 1000 / row["wall_ms"]
                            if not row["passed"]:
                                raise RuntimeError(f"Invalid output {tag}: {row.get('failures')}")
                            records[name].append(row)
                            print(f"{case['case_id']} c={width} {name} r={run}: "
                                  f"wall={row['wall_ms']:.1f}ms cores={row['cpu_cores']:.2f} "
                                  f"user={row['cpu_split']['user_ms'] / 1000:.2f}s "
                                  f"kern={row['cpu_split']['kernel_ms'] / 1000:.2f}s", flush=True)
                        finally:
                            for key, value in saved.items():
                                if value is None:
                                    os.environ.pop(key, None)
                                else:
                                    os.environ[key] = value
                            if not args.keep_outputs:
                                shutil.rmtree(output, ignore_errors=True)
                entry = {"case_id": case["case_id"], "format": case["format"], "concurrency": width,
                         "jobs": width, "summaries": {}}
                for name, rows in records.items():
                    if not rows:
                        continue
                    entry[name] = rows
                    entry["summaries"][name] = summarise(rows)
                base = entry["summaries"].get("default", {}).get("wall_ms")
                for name, summary in entry["summaries"].items():
                    if base:
                        summary["speedup_vs_default"] = base / summary["wall_ms"]
                report["results"].append(entry)
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        report["complete"] = True
        args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        print(args.json_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
