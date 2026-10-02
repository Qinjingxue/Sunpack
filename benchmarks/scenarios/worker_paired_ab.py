"""Paired A/B of two worker binaries on the cached 300 MiB corpus.

Alternates engine order per trial so drift and ordering bias show up as spread
rather than as a fake effect. Python only orchestrates; bytes stay native.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace
from benchmarks.scenarios.worker_concurrency_300m import prepare, run_worker, validate, _volume_paths
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from tests.helpers.tool_config import get_7z_cli_dll_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--format", default="7z")
    parser.add_argument("--concurrency", default="4,8")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--buffers", type=int, default=0)
    parser.add_argument("--before-file-inflight-mib", type=int, default=0,
                        help="Override SUNPACK_ASYNC_WRITER_FILE_INFLIGHT_MIB for the before engine")
    parser.add_argument("--after-file-inflight-mib", type=int, default=0,
                        help="Override SUNPACK_ASYNC_WRITER_FILE_INFLIGHT_MIB for the after engine")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()

    if args.buffers:
        os.environ["SUNPACK_ASYNC_WRITER_BUFFERS"] = str(args.buffers)
    else:
        os.environ.pop("SUNPACK_ASYNC_WRITER_BUFFERS", None)
    overrides = {}
    for name, value in (("before", args.before_file_inflight_mib),
                        ("after", args.after_file_inflight_mib)):
        if value:
            overrides[name] = {"SUNPACK_ASYNC_WRITER_FILE_INFLIGHT_MIB": str(value)}
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "0"
    os.environ["SUNPACK_WRITER_PROBE"] = "0"
    dll = Path(get_7z_cli_dll_path()).resolve()
    widths = [int(x) for x in args.concurrency.split(",")]
    engines = {"before": args.before.resolve(), "after": args.after.resolve()}
    report = {"before": str(engines["before"]), "after": str(engines["after"]),
              "format": args.format, "concurrency": widths, "trials": args.trials,
              "buffers": args.buffers, "file_inflight_mib": {
                  "before": args.before_file_inflight_mib or "default",
                  "after": args.after_file_inflight_mib or "default"},
              "complete": False, "results": []}

    with BenchmarkWorkspace("extraction.worker-paired-ab") as workspace:
        cases, corpus = prepare(workspace, ROOT / "benchmarks/.cache/worker-concurrency-300m")
        case = next(c for c in cases if c["format"] == args.format)
        tar_bytes = next(_volume_paths(c["item"])[0].stat().st_size for c in cases if c["format"] == "tar")
        for width in widths:
            rows = {"before": [], "after": []}
            for trial in range(args.trials):
                order = ["before", "after"] if trial % 2 == 0 else ["after", "before"]
                for name in order:
                    output = workspace.outputs / f"{args.format}-{width}-{name}-{trial}"
                    # The worker inherits os.environ at spawn, so the per-engine override is
                    # applied only around this engine's process.
                    saved = os.environ.get("SUNPACK_ASYNC_WRITER_FILE_INFLIGHT_MIB")
                    os.environ.pop("SUNPACK_ASYNC_WRITER_FILE_INFLIGHT_MIB", None)
                    os.environ.update(overrides.get(name, {}))
                    try:
                        worker = _NativeWorkerProcess(str(engines[name]), None, {"writer_threads": 8})
                        try:
                            row = run_worker(worker, [case] * width, output, width, dll, 600, False)
                        finally:
                            worker.close()
                    finally:
                        os.environ.pop("SUNPACK_ASYNC_WRITER_FILE_INFLIGHT_MIB", None)
                        if saved is not None:
                            os.environ["SUNPACK_ASYNC_WRITER_FILE_INFLIGHT_MIB"] = saved
                    validate(row, [case] * width, output, tar_bytes)
                    row["trial"] = trial
                    if not row["passed"]:
                        raise RuntimeError(f"{name} failed: {row.get('failures')}")
                    rows[name].append(row)
                    print(f"c={width} t={trial} {name}: wall={row['wall_ms']:.1f} "
                          f"cores={row['cpu_cores']:.2f} rss={row['rss_peak_mib']:.0f}", flush=True)
                    shutil.rmtree(output, ignore_errors=True)
            entry = {"concurrency": width, "jobs": width}
            for name, samples in rows.items():
                entry[name] = {
                    "walls": [round(s["wall_ms"], 1) for s in samples],
                    "wall_ms": statistics.median(s["wall_ms"] for s in samples),
                    "cores": statistics.median(s["cpu_cores"] for s in samples),
                    "rss_mib": statistics.median(s["rss_peak_mib"] for s in samples),
                    "throughput_mib_s": statistics.median(
                        width * 300 * 1000 / s["wall_ms"] for s in samples),
                }
            entry["wall_gain_percent"] = 100.0 * (1 - entry["after"]["wall_ms"] / entry["before"]["wall_ms"])
            report["results"].append(entry)
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        report["complete"] = True
        args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")
        print(json.dumps(report["results"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
