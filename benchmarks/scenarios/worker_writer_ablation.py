"""Writer-phase and IO ablation sweep for the parallel worker deficit.

Runs the probe-instrumented worker in the benchmark-only sink modes so the
decode-only cost can be separated from the shared per-volume write facility.
Python only orchestrates; every byte is produced natively.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace
from benchmarks.scenarios.worker_concurrency_300m import prepare, run_worker, run_cli, validate, _volume_paths
from sunpack.core.support.output_paths import resolve_output_volume_key
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from tests.helpers.tool_config import get_7z_cli_dll_path, require_7z

MODES = ("real", "memory", "memory-nocopy", "eof", "cli", "writers1", "writers8", "writers16", "writers32")


def drain_probes(worker, expected):
    rows = []
    while len(rows) < expected:
        try:
            line = worker.stderr_queue.get(timeout=5)
        except queue.Empty as exc:
            raise RuntimeError(f"Missing writer probes {len(rows)}/{expected}") from exc
        if line and line.startswith("WRITER_PROBE "):
            rows.append(json.loads(line.removeprefix("WRITER_PROBE ")))
    return rows


def phase_totals(probes):
    if not probes:
        return {}
    phases = probes[0]["phases"]
    return {name: {"ms": sum(p["phases"][name]["ns"] for p in probes) / 1e6,
                   "calls": sum(p["phases"][name]["calls"] for p in probes),
                   "max_ms": max(p["phases"][name]["max_ns"] for p in probes) / 1e6}
            for name in phases}


def write_latency(probes):
    """Aggregate the per-job write-completion depth/latency counters."""
    if not probes:
        return {}
    count = sum(p.get("latency_count", 0) for p in probes)
    total_ns = sum(p.get("latency_ns", 0) for p in probes)
    return {
        "latency_count": count,
        "latency_mean_ms": (total_ns / count / 1e6) if count else 0.0,
        "latency_peak_ms": max((p.get("latency_peak_ns", 0) for p in probes), default=0) / 1e6,
        "inflight_peak": max((p.get("inflight_peak", 0) for p in probes), default=0),
        "queue_depth_peak": max((p.get("queue_depth_peak", 0) for p in probes), default=0),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--format", action="append", required=True)
    parser.add_argument("--concurrency", default="1,4,8")
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--mode", action="append", choices=MODES)
    parser.add_argument("--buffers", type=int, default=0,
                        help="Override SUNPACK_ASYNC_WRITER_BUFFERS for every worker mode")
    parser.add_argument("--reuse-corpus", type=Path,
                        help="Directory holding a prepared worker-concurrency corpus (skips fixture generation)")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()

    widths = sorted({int(x) for x in args.concurrency.split(",")})
    modes = args.mode or list(MODES)
    seven, dll = require_7z().resolve(), Path(get_7z_cli_dll_path()).resolve()
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "0"
    os.environ["SUNPACK_WRITER_PROBE"] = "1"
    if args.buffers:
        os.environ["SUNPACK_ASYNC_WRITER_BUFFERS"] = str(args.buffers)
    else:
        os.environ.pop("SUNPACK_ASYNC_WRITER_BUFFERS", None)
    report = {"format": args.format, "concurrency": widths, "runs": args.runs,
              "modes": modes, "buffers": args.buffers, "complete": False, "results": []}
    with BenchmarkWorkspace("extraction.worker-writer-ablation") as workspace:
        cases, corpus = prepare(workspace, args.reuse_corpus or ROOT / "benchmarks/.cache/worker-concurrency-300m")
        selected = []
        for name in args.format:
            case = next(c for c in cases if c["format"] == name)
            if case not in selected:
                selected.append(case)
        report["case"] = [c["case_id"] for c in selected]
        report["corpus"] = corpus
        tar_bytes = next(_volume_paths(c["item"])[0].stat().st_size for c in cases if c["format"] == "tar")
        volume_key = resolve_output_volume_key(str(workspace.outputs))
        for case in selected:
            for width in widths:
                record = {"case_id": case["case_id"], "format": case["format"],
                          "concurrency": width, "modes": {}}
                ordered = [m for m in modes if m != "cli"] + (["cli"] if "cli" in modes else [])
                for mode in ordered:
                    rows = []
                    for run in range(args.runs):
                        os.environ["SUNPACK_WRITER_PROBE_MODE"] = mode if mode in {"memory", "memory-nocopy", "eof"} else "real"
                        config = {"writer_threads": int(mode.removeprefix("writers"))} if mode.startswith("writers") else {}
                        output = workspace.outputs / f"{case['format']}-{width}-{mode}-{run}"
                        # 7z.exe 的 -aoa 只在单次调用内覆盖；跨 run 复用同一目录会让它
                        # 把重名条目写成 "name(1).bin"，校验看到的字节数翻倍。
                        shutil.rmtree(output, ignore_errors=True)
                        if mode == "cli":
                            row = run_cli(seven, [case] * width, output, width, 600, False)
                            validate(row, [case] * width, output, tar_bytes)
                            row["memory_sink"] = False
                        else:
                            worker = _NativeWorkerProcess(str(args.worker.resolve()), None, config)
                            try:
                                row = run_worker(worker, [case] * width, output, width, dll, 600, False)
                                row["probes"] = drain_probes(worker, width)
                            finally:
                                worker.close()
                            row["phase_total_ms"] = phase_totals(row["probes"])
                            row["memory_sink"] = mode in {"memory", "memory-nocopy"}
                            if not row["memory_sink"]:
                                validate(row, [case] * width, output, tar_bytes)
                        row["run"] = run
                        row["throughput_mib_s"] = width * 300 * 1000 / row["wall_ms"]
                        if not row["passed"]:
                            timeline = row.get("timeline", [])
                            listing = {}
                            for index in range(width):
                                root = output / str(index)
                                files = [p for p in root.rglob("*") if p.is_file()] if root.exists() else []
                                listing[index] = [(str(p.relative_to(output)), p.stat().st_size) for p in files]
                            raise RuntimeError(
                                f"{mode} failed: passed={row['passed']} failures={row.get('failures')} "
                                f"codes={[t.get('returncode') for t in timeline]} listing={listing}")
                        rows.append(row)
                        print(f"{case['format']} c={width} {mode} r={run}: wall={row['wall_ms']:.1f} "
                              f"cores={row['cpu_cores']:.2f} thr={row['throughput_mib_s']:.0f}MiB/s "
                              f"rss={row['rss_peak_mib']:.0f}", flush=True)
                        shutil.rmtree(output, ignore_errors=True)
                    record["modes"][mode] = {
                        "rows": rows,
                        "median": {key: statistics.median(r[key] for r in rows)
                                   for key in ("wall_ms", "cpu_cores", "cpu_ms", "rss_peak_mib",
                                               "max_active", "throughput_mib_s")},
                        "phases_ms": {name: statistics.median(
                            r.get("phase_total_ms", {}).get(name, {}).get("ms", 0) for r in rows)
                            for name in (rows[0].get("phase_total_ms") or {})},
                        "wait_reasons": {reason: statistics.median(
                            sum(p[reason] for p in r["probes"]) for r in rows)
                            for reason in ("file_full", "job_full", "buffers_empty")} if rows[0].get("probes") else {},
                        "write_latency": write_latency(rows[-1]["probes"]) if rows[-1].get("probes") else {},
                    }
            base = record["modes"].get("memory", {}).get("median", {}).get("wall_ms")
            for entry in record["modes"].values():
                if base:
                    entry["wall_vs_decode_only"] = entry["median"]["wall_ms"] / base
            report["results"].append(record)
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        report["complete"] = True
        args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        print(args.json_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
