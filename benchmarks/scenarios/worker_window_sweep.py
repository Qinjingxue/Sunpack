"""Paired sweep of the per-file residency window (benchmark-only).

Patches the single window constant, rebuilds the probe worker once per window
value, then runs every window value in alternating order per trial so drift does
not masquerade as an effect. Restores the original header on exit.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import re
import shutil
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace
from benchmarks.scenarios.worker_concurrency_300m import prepare, run_worker, validate, _volume_paths
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from tests.helpers.tool_config import get_7z_cli_dll_path

HEADER = ROOT / "native/sevenzip_bridge/src/internal/sevenzip_async_output.hpp"
BUILD = ROOT / "native/sevenzip_bridge/build-probe"
WORKER = BUILD / "Release/sunpack_sevenzip_worker.exe"
PATTERN = re.compile(r"static constexpr std::size_t kDefaultFileInFlightBytes = (\d+)U << 20;")
BINARIES = ROOT / "benchmarks/.cache/window-sweep"


def set_window(mib: int) -> None:
    text = HEADER.read_text(encoding="utf-8")
    replaced, count = PATTERN.subn(
        f"static constexpr std::size_t kDefaultFileInFlightBytes = {mib}U << 20;", text)
    if count != 1:
        raise RuntimeError(f"expected one window constant, replaced {count}")
    HEADER.write_text(replaced, encoding="utf-8", newline="")


def build() -> None:
    obj = BUILD / "sunpack_sevenzip_worker.dir/Release/worker.obj"
    if obj.exists():
        obj.unlink()
    subprocess.run(["cmake", "--build", str(BUILD), "--config", "Release",
                    "--target", "sunpack_sevenzip_worker", "--parallel"],
                   check=True, cwd=str(ROOT), capture_output=True)


def probes(worker, expected):
    rows = []
    while len(rows) < expected:
        try:
            line = worker.stderr_queue.get(timeout=10)
        except queue.Empty as exc:
            raise RuntimeError(f"missing probes {len(rows)}/{expected}") from exc
        if line and line.startswith("WRITER_PROBE "):
            rows.append(json.loads(line.removeprefix("WRITER_PROBE ")))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window-mib", default="8,16,32")
    parser.add_argument("--format", default="7z")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--trials", type=int, default=4)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()

    original = HEADER.read_text(encoding="utf-8")
    windows = [int(x) for x in args.window_mib.split(",")]
    dll = Path(get_7z_cli_dll_path()).resolve()
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "0"
    os.environ["SUNPACK_WRITER_PROBE"] = "1"
    os.environ["SUNPACK_ASYNC_WRITER_THREADS_PER_VOLUME"] = "8"
    report = {"format": args.format, "concurrency": args.concurrency, "trials": args.trials,
              "windows_mib": windows, "complete": False, "results": []}
    BINARIES.mkdir(parents=True, exist_ok=True)
    binaries = {}
    try:
        for window in windows:
            set_window(window)
            build()
            target = BINARIES / f"worker-window-{window}.exe"
            shutil.copy2(WORKER, target)
            binaries[window] = target
        with BenchmarkWorkspace("extraction.worker-window-sweep") as workspace:
            cases, corpus = prepare(workspace, ROOT / "benchmarks/.cache/worker-concurrency-300m")
            case = next(c for c in cases if c["format"] == args.format)
            tar_bytes = next(_volume_paths(c["item"])[0].stat().st_size for c in cases if c["format"] == "tar")
            samples = {w: [] for w in windows}
            for trial in range(args.trials):
                order = windows if trial % 2 == 0 else list(reversed(windows))
                for window in order:
                    output = workspace.outputs / f"{args.format}-{window}-{trial}"
                    worker = _NativeWorkerProcess(str(binaries[window]), None, {"writer_threads": 8})
                    try:
                        row = run_worker(worker, [case] * args.concurrency, output,
                                         args.concurrency, dll, 600, False)
                        row["probes"] = probes(worker, args.concurrency)
                    finally:
                        worker.close()
                    validate(row, [case] * args.concurrency, output, tar_bytes)
                    if not row["passed"]:
                        raise RuntimeError(f"window {window} failed: {row.get('failures')}")
                    samples[window].append(row)
                    shutil.rmtree(output, ignore_errors=True)
                    print(f"t={trial} window={window:3d} MiB: wall={row['wall_ms']:.1f} "
                          f"cores={row['cpu_cores']:.2f} "
                          f"file_full={sum(p['file_full'] for p in row['probes'])} "
                          f"depth={max(p['inflight_peak'] for p in row['probes'])}", flush=True)
            for window in windows:
                rows = samples[window]
                report["results"].append({
                    "window_mib": window,
                    "walls": [round(r["wall_ms"], 1) for r in rows],
                    "wall_ms": statistics.median(r["wall_ms"] for r in rows),
                    "wall_min_ms": min(r["wall_ms"] for r in rows),
                    "cores": statistics.median(r["cpu_cores"] for r in rows),
                    "throughput_mib_s": statistics.median(
                        args.concurrency * 300 * 1000 / r["wall_ms"] for r in rows),
                    "inflight_peak": statistics.median(
                        max(p["inflight_peak"] for p in r["probes"]) for r in rows),
                    "file_full": statistics.median(
                        sum(p["file_full"] for p in r["probes"]) for r in rows),
                    "buffers_empty": statistics.median(
                        sum(p["buffers_empty"] for p in r["probes"]) for r in rows),
                    "capacity_wait_ms": statistics.median(
                        sum(p["phases"]["capacity_wait"]["ns"] for p in r["probes"]) / 1e6 for r in rows),
                })
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        report["complete"] = True
        args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        for entry in report["results"]:
            print("{:3d} MiB: median={:.1f} min={:.1f} thr={:.0f} depth={:.0f} file_full={:.0f} "
                  "buffers_empty={:.0f} capacity_wait={:.0f}ms walls={}".format(
                      entry["window_mib"], entry["wall_ms"], entry["wall_min_ms"],
                      entry["throughput_mib_s"], entry["inflight_peak"], entry["file_full"],
                      entry["buffers_empty"], entry["capacity_wait_ms"], entry["walls"]))
    finally:
        HEADER.write_text(original, encoding="utf-8", newline="")
        build()
        print("restored original window constant and rebuilt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
