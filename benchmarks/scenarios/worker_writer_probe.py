"""Bounded writer diagnosis, reusing the 300 MiB concurrency harness."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import statistics
import subprocess
import psutil

from benchmarks.harness import BenchmarkWorkspace
from benchmarks.scenarios.worker_concurrency_300m import prepare, run_worker, run_cli, validate, _volume_paths
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from tests.helpers.tool_config import get_7z_cli_dll_path, require_7z

ROOT = Path(__file__).resolve().parents[2]


def profiles(worker, expected):
    result = []
    while len(result) < expected:
        try:
            line = worker.stderr_queue.get(timeout=2)
        except queue.Empty as exc:
            raise RuntimeError(f"Missing writer probes: {len(result)}/{expected}") from exc
        if line and line.startswith("WRITER_PROBE "):
            result.append(json.loads(line.removeprefix("WRITER_PROBE ")))
    return result


def summarize(rows):
    result = {key: statistics.median(row[key] for row in rows)
              for key in ("wall_ms", "cpu_ms", "cpu_cores", "rss_peak_mib")}
    if rows[0].get("writer_profiles"):
        phases = rows[0]["writer_profiles"][0]["phases"]
        result["writer_ms_sum"] = {
            phase: statistics.median(sum(p["phases"][phase]["ns"] for p in row["writer_profiles"]) / 1e6
                                     for row in rows) for phase in phases}
        result["writer_calls_sum"] = {
            phase: statistics.median(sum(p["phases"][phase]["calls"] for p in row["writer_profiles"])
                                     for row in rows) for phase in phases}
        result["writer_wait_reasons"] = {
            reason: statistics.median(sum(p[reason] for p in row["writer_profiles"]) for row in rows)
            for reason in ("file_full", "job_full", "buffers_empty")}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", action="append", choices=("dry", "baseline", "real", "memory", "memory-nocopy", "eof", "writers1", "writers8"))
    parser.add_argument("--concurrency", default="1,8")
    parser.add_argument("--format", action="append", choices=("gz", "zip"))
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--prefetch", choices=("on", "off"), default="off")
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--sync-cleanup", action="store_true", help="Flush outputs through Rust after timing, before the next trial")
    args = parser.parse_args()
    widths = [int(x) for x in args.concurrency.split(",")]
    if args.runs < 1 or any(x < 1 or x > 32 for x in widths):
        parser.error("Positive runs and concurrency 1..32 required")
    os.environ["SUNPACK_SEVENZIP_PREFETCH"] = "1" if args.prefetch == "on" else "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "0"
    report = {"source": "current restored source; BZip2 untouched", "runs": args.runs,
              "prefetch": args.prefetch, "complete": False,
              "method": "300 MiB cached inputs. Per-volume shared writer. Two trials per mode, reversed mode order in second trial. No fsync/cache flush. Native output metadata validation and cleanup outside timer. Probe sums overlap across jobs and threads; do not add them as batch wall time.",
              "results": []}
    seven, dll = require_7z().resolve(), Path(get_7z_cli_dll_path()).resolve()
    with BenchmarkWorkspace("extraction.worker-writer-probe") as workspace:
        cases, corpus = prepare(workspace, ROOT / "benchmarks/.cache/worker-concurrency-300m")
        native_helper = workspace.work / "native_fixture.exe"
        if args.sync_cleanup:
            subprocess.run(["rustc", "-O", str(ROOT / "benchmarks/harness/mixed_payload.rs"), "-o", str(native_helper)], check=True)
        report["sync_cleanup_outside_timer"] = args.sync_cleanup
        report["corpus"] = corpus
        tar_bytes = next(_volume_paths(c["item"])[0].stat().st_size for c in cases if c["format"] == "tar")
        for fmt in args.format or ("gz", "zip"):
            case = next(c for c in cases if c["format"] == fmt)
            for width in widths:
                modes = args.mode or ["dry", "baseline", "real", "memory", "memory-nocopy", "eof"]
                records = {mode: {"format": fmt, "concurrency": width, "mode": mode, "rows": []} for mode in modes}
                for trial in range(args.runs):
                    for mode in (modes if trial % 2 == 0 else list(reversed(modes))):
                        diagnostic = mode not in {"dry", "baseline"}
                        os.environ["SUNPACK_WRITER_PROBE"] = "1" if diagnostic else "0"
                        os.environ["SUNPACK_WRITER_PROBE_MODE"] = mode if mode in {"memory", "memory-nocopy", "eof"} else "real"
                        binary = ROOT / "benchmarks/.cache/writer-probe" / ("probe.exe" if diagnostic else "baseline.exe")
                        config = {"writer_threads": int(mode.removeprefix("writers"))} if mode.startswith("writers") else {}
                        output = workspace.outputs / f"{fmt}-{width}-{mode}-{trial}"
                        worker = _NativeWorkerProcess(str(binary), None, config)
                        try:
                            disk_before = psutil.disk_io_counters(perdisk=True)
                            row = run_worker(worker, [case] * width, output, width, dll, 60, mode == "dry")
                            disk_after = psutil.disk_io_counters(perdisk=True)
                            row["physical_disk_delta"] = {
                                name: {"read_bytes": counters.read_bytes - disk_before[name].read_bytes,
                                       "write_bytes": counters.write_bytes - disk_before[name].write_bytes}
                                for name, counters in disk_after.items() if name in disk_before}
                            row["trial"] = trial
                            if diagnostic:
                                row["writer_profiles"] = profiles(worker, width)
                            if mode in {"memory", "memory-nocopy"}:
                                row["diagnostic_only_no_output"] = True
                                if any(p.is_file() for p in output.rglob("*")):
                                    raise RuntimeError("Memory-sink ablation unexpectedly created output files")
                            elif mode != "dry":
                                validate(row, [case] * width, output, tar_bytes)
                            if not row["passed"]:
                                raise RuntimeError(f"Failed {fmt}/{width}/{mode}: {row['failures']}")
                            records[mode]["rows"].append(row)
                            print(f"{fmt} c={width} {mode} r={trial}: {row['wall_ms']:.1f}ms CPU={row['cpu_cores']:.2f}", flush=True)
                            if args.sync_cleanup and mode not in {"dry", "memory", "memory-nocopy"}:
                                subprocess.run([str(native_helper), "--sync-tree", str(output)], check=True)
                        finally:
                            worker.close()
                            if output.resolve().parent != workspace.outputs.resolve():
                                raise RuntimeError("Cleanup escaped benchmark outputs")
                            shutil.rmtree(output, ignore_errors=True)
                for record in records.values():
                    record["median"] = summarize(record["rows"])
                    report["results"].append(record)
                # Fresh CLI processes are reference points for normal and no-output modes.
                if any(mode in modes for mode in ("dry", "baseline")):
                    for dry in (False, True):
                        cli_rows = []
                        for trial in range(args.runs):
                            output = workspace.outputs / f"cli-{fmt}-{width}-{dry}-{trial}"
                            try:
                                row = run_cli(seven, [case] * width, output, width, 60, dry)
                                if not dry:
                                    validate(row, [case] * width, output, tar_bytes)
                                if not row["passed"]:
                                    raise RuntimeError("CLI reference failed")
                                cli_rows.append(row)
                                if args.sync_cleanup and not dry:
                                    subprocess.run([str(native_helper), "--sync-tree", str(output)], check=True)
                            finally:
                                shutil.rmtree(output, ignore_errors=True)
                        report["results"].append({"format": fmt, "concurrency": width, "mode": "cli-dry" if dry else "cli", "rows": cli_rows, "median": summarize(cli_rows)})
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        report["complete"] = True
        args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
