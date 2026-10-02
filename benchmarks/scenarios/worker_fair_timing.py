"""Fair wall-clock comparison: extraction plus a forced flush of the produced tree.

The worker's completion means "bytes are on the device"; 7z.exe returns as soon as the
bytes are in the page cache, leaving write-behind to the kernel. Timing only the return
makes the two engines incomparable, so each run is measured twice:

  wall_ms  - process/worker return, exactly as worker-concurrency-300m reports it
  flush_ms - Rust sync_all over the produced tree, immediately after the return

wall_ms + flush_ms is the point where both engines are equally durable, and it is the
only comparison this scenario treats as decisive. A "wait until the host disk goes
quiet" probe was tried and removed: on this machine unrelated background writeback keeps
the disk busy for about a second regardless of workload size, so it measured the box,
not the extraction. Python only orchestrates processes and reads counters; fixture bytes
and all extraction work stay native.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

import psutil

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace
from benchmarks.scenarios.worker_concurrency_300m import prepare, run_worker, run_cli, validate, _volume_paths
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from tests.helpers.tool_config import get_7z_cli_dll_path, require_7z


def flush_tree(helper: Path, root: Path) -> float:
    """Rust sync_all over the tree; returns wall time in ms."""
    started = time.perf_counter()
    subprocess.run([str(helper), "--sync-tree", str(root)], check=True)
    return (time.perf_counter() - started) * 1000


def disk_write_bytes():
    return {name: c.write_bytes for name, c in psutil.disk_io_counters(perdisk=True).items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--format", action="append", required=True)
    parser.add_argument("--concurrency", default="8")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=900)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()

    widths = sorted({int(x) for x in args.concurrency.split(",")})
    seven, dll = require_7z().resolve(), Path(get_7z_cli_dll_path()).resolve()
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "0"
    os.environ["SUNPACK_WRITER_PROBE"] = "0"
    report = {"concurrency": widths, "runs": args.runs, "formats": args.format,
              "worker": str(args.worker.resolve()),
              "method": "extraction wall (as reported by worker-concurrency-300m) plus Rust sync_all "
                        "over the produced tree immediately after the return; validation and cleanup "
                        "stay outside both timers",
              "complete": False, "results": []}

    with BenchmarkWorkspace("extraction.worker-fair-timing") as workspace:
        cases, corpus = prepare(workspace, ROOT / "benchmarks/.cache/worker-concurrency-300m")
        helper = workspace.work / "native_fixture.exe"
        subprocess.run(["rustc", "-O", str(ROOT / "benchmarks/harness/mixed_payload.rs"),
                        "-o", str(helper)], check=True)
        report["corpus"] = corpus
        tar_bytes = next(_volume_paths(c["item"])[0].stat().st_size for c in cases if c["format"] == "tar")
        selected = []
        for name in args.format:
            case = next(c for c in cases if c["format"] == name)
            if case not in selected:
                selected.append(case)
        for case in selected:
            for width in widths:
                batch = [case] * width
                rows = {"worker": [], "cli": []}
                for run in range(args.runs):
                    order = ["worker", "cli"] if run % 2 == 0 else ["cli", "worker"]
                    for engine in order:
                        output = workspace.outputs / f"{case['format']}-{width}-{engine}-{run}"
                        if engine == "worker":
                            worker = _NativeWorkerProcess(str(args.worker.resolve()), None, {})
                            try:
                                row = run_worker(worker, batch, output, width, dll, args.timeout, False)
                            finally:
                                worker.close()
                        else:
                            row = run_cli(seven, batch, output, width, args.timeout, False)
                        before = disk_write_bytes()
                        row["flush_ms"] = flush_tree(helper, output)
                        after = disk_write_bytes()
                        row["flush_disk_mib"] = sum(
                            max(0, after[k] - before.get(k, after[k])) for k in after) / (1024 * 1024)
                        validate(row, batch, output, tar_bytes)
                        if not row["passed"]:
                            raise RuntimeError(f"{engine} failed: {row.get('failures')}")
                        row["run"] = run
                        rows[engine].append(row)
                        print(f"{case['format']} c={width} {engine} r={run}: "
                              f"wall={row['wall_ms']:.1f} flush={row['flush_ms']:.1f} "
                              f"flush_disk={row['flush_disk_mib']:.0f}MiB", flush=True)
                        shutil.rmtree(output, ignore_errors=True)
                entry = {"case_id": case["case_id"], "format": case["format"],
                         "concurrency": width, "jobs": len(batch)}
                for engine, samples in rows.items():
                    entry[engine] = {
                        "walls": [round(s["wall_ms"], 1) for s in samples],
                        "flushes": [round(s["flush_ms"], 1) for s in samples],
                        "wall_ms": statistics.median(s["wall_ms"] for s in samples),
                        "flush_ms": statistics.median(s["flush_ms"] for s in samples),
                        "total_ms": statistics.median(s["wall_ms"] + s["flush_ms"] for s in samples),
                        "flush_disk_mib": statistics.median(s["flush_disk_mib"] for s in samples),
                        "cores": statistics.median(s["cpu_cores"] for s in samples),
                        "rss_mib": statistics.median(s["rss_peak_mib"] for s in samples),
                    }
                entry["worker_over_cli_wall"] = entry["worker"]["wall_ms"] / entry["cli"]["wall_ms"]
                entry["worker_over_cli_total"] = entry["worker"]["total_ms"] / entry["cli"]["total_ms"]
                report["results"].append(entry)
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
                print(f"{case['format']} c={width}: worker wall={entry['worker']['wall_ms']:.1f} "
                      f"flush={entry['worker']['flush_ms']:.1f} total={entry['worker']['total_ms']:.1f} | "
                      f"cli wall={entry['cli']['wall_ms']:.1f} flush={entry['cli']['flush_ms']:.1f} "
                      f"total={entry['cli']['total_ms']:.1f} | wall-ratio={entry['worker_over_cli_wall']:.2f} "
                      f"total-ratio={entry['worker_over_cli_total']:.2f}", flush=True)
        report["complete"] = True
        args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        print(args.json_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
