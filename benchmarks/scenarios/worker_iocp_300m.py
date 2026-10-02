"""Paired old writer / IOCP / CLI extraction plus explicit native output flush."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import time

import psutil

from benchmarks.harness import BenchmarkWorkspace
from benchmarks.scenarios.worker_concurrency_300m import prepare, run_worker, run_cli, validate, _volume_paths, STREAMS
from benchmarks.scenarios.worker_vs_7z_300m import DEFAULT_FORMATS, _git_commit
from benchmarks.scenarios.worker_writer_probe import summarize
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from tests.helpers.tool_config import get_7z_cli_dll_path, require_7z

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline-writer-threads", type=int, choices=range(1, 9), default=4)
    parser.add_argument("--candidate-writer-threads", type=int, choices=range(1, 9), default=4)
    parser.add_argument("--concurrency", default="1,8")
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--format", action="append", choices=DEFAULT_FORMATS)
    parser.add_argument("--all-formats", action="store_true", help="All 18 cached format/variant cases")
    parser.add_argument("--case-id", action="append", help="Select exact case IDs, preserving solid/split variants")
    parser.add_argument("--no-cli", action="store_true", help="Only compare the saved writer and IOCP")
    parser.add_argument("--mixed", action="store_true", help="Also compare one heterogeneous batch at maximum concurrency")
    parser.add_argument("--prefetch", choices=("on", "off"), default="on")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    widths = [int(x) for x in args.concurrency.split(",")]
    if args.runs < 1 or not widths or any(x < 1 or x > 32 for x in widths):
        parser.error("Positive runs and concurrency 1..32 required")
    os.environ["SUNPACK_SEVENZIP_PREFETCH"] = "1" if args.prefetch == "on" else "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "0"
    os.environ["SUNPACK_WRITER_PROBE"] = "0"
    report = {"complete": False, "runs": args.runs, "prefetch": args.prefetch,
              "baseline": str(args.baseline.resolve()), "candidate": str(args.candidate.resolve()),
              "writer_threads": {"baseline": args.baseline_writer_threads, "iocp": args.candidate_writer_threads},
              "method": "Same 300 MiB cached inputs; configured IOCP consumers, unchanged file/job/buffer limits. "
                        "Rotated paired order. wall_ms is extraction return; flush_ms is Rust sync_all "
                        "including helper launch immediately after run returns. extract_and_flush_ms "
                        "includes harness setup/sampler teardown between those boundaries. "
                        "Validation and byte comparison are outside all timers. Disk counters are host-wide.",
              "results": []}
    seven, dll = require_7z().resolve(), Path(get_7z_cli_dll_path()).resolve()
    report["source_commit"] = _git_commit()
    report["binaries"] = {}
    for name, binary in {"baseline": args.baseline, "candidate": args.candidate, "dll": dll}.items():
        literal = "'" + str(binary.resolve()).replace("'", "''") + "'"
        script = (f"$stream=[IO.File]::OpenRead({literal}); $hash=[Security.Cryptography.SHA256]::Create(); "
                  "try { [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '') } "
                  "finally { $stream.Dispose(); $hash.Dispose() }")
        result = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                                 script],
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        report["binaries"][name] = {"path": str(binary.resolve()), "sha256": result.stdout.strip()}
    with BenchmarkWorkspace("extraction.worker-iocp-300m") as workspace:
        cases, corpus = prepare(workspace, ROOT / "benchmarks/.cache/worker-concurrency-300m")
        report["corpus"] = corpus
        tar = next(_volume_paths(c["item"])[0] for c in cases if c["format"] == "tar")
        helper = workspace.work / "native_fixture.exe"
        subprocess.run(["rustc", "-O", str(ROOT / "benchmarks/harness/mixed_payload.rs"), "-o", str(helper)], check=True)
        selected = [c for c in cases if (args.all_formats or c["format"] in (args.format or ("gz", "zip")))
                    and (not args.case_id or c["case_id"] in args.case_id)]
        if args.case_id and set(args.case_id) - {c["case_id"] for c in selected}:
            parser.error("Unknown/unselected case IDs")
        workloads = [(c["case_id"], c["format"], [c], widths) for c in selected]
        if args.mixed:
            workloads.append(("mixed", "mixed", selected, [max(widths)]))
        report["cases"] = selected
        report["concurrency"] = widths
        report["cli_reference"] = not args.no_cli
        for case_index, (case_id, fmt, base, case_widths) in enumerate(workloads):
            for width in case_widths:
                batch = base if case_id == "mixed" else base * width
                modes = ["baseline", "iocp"] + ([] if args.no_cli else ["cli"])
                records = {m: {"case_id": case_id, "format": fmt, "concurrency": width,
                               "jobs": len(batch), "mode": m, "rows": []} for m in modes}
                for trial in range(args.runs):
                    # Baseline/candidate order flips; CLI also changes position.
                    order = modes if trial % 2 == 0 else list(reversed(modes))
                    for mode in order:
                        output = workspace.outputs / f"{case_index}-{width}-{mode}-{trial}"
                        worker = None
                        try:
                            if mode != "cli":
                                binary = args.baseline if mode == "baseline" else args.candidate
                                threads = args.baseline_writer_threads if mode == "baseline" else args.candidate_writer_threads
                                worker = _NativeWorkerProcess(str(binary.resolve()), None, {"writer_threads": threads})
                            before = psutil.disk_io_counters(perdisk=True)
                            started = time.perf_counter()
                            row = (run_cli(seven, batch, output, width, 180) if mode == "cli"
                                   else run_worker(worker, batch, output, width, dll, 180, False))
                            returned = time.perf_counter()
                            subprocess.run([str(helper), "--sync-tree", str(output)], check=True)
                            flushed = time.perf_counter()
                            after = psutil.disk_io_counters(perdisk=True)
                            row["flush_ms"] = (flushed - returned) * 1000
                            row["extract_and_flush_ms"] = (flushed - started) * 1000
                            row["physical_disk_delta"] = {
                                name: {"read_bytes": v.read_bytes - before[name].read_bytes,
                                       "write_bytes": v.write_bytes - before[name].write_bytes}
                                for name, v in after.items() if name in before}
                            validate(row, batch, output, tar.stat().st_size)
                            if not row["passed"]:
                                raise RuntimeError(f"Failed {fmt}/{width}/{mode}: {row.get('failures')}")
                            for index, item in enumerate(batch):
                                stream = item["format"] in STREAMS
                                reference = tar if stream else ROOT / "benchmarks/.cache/worker-concurrency-300m/payloads/few-large"
                                subprocess.run([str(helper), "--verify-output", "stream" if stream else "archive",
                                                str(reference), str(output / str(index))], check=True)
                            row["byte_verified"] = True
                            row["trial"] = trial
                            records[mode]["rows"].append(row)
                            print(f"{case_id} c={width} {mode} r={trial}: return={row['wall_ms']:.1f}ms "
                                  f"flush={row['flush_ms']:.1f}ms total={row['extract_and_flush_ms']:.1f}ms", flush=True)
                        finally:
                            if worker: worker.close()
                            if output.resolve().parent != workspace.outputs.resolve():
                                raise RuntimeError("Cleanup escaped benchmark outputs")
                            shutil.rmtree(output, ignore_errors=True)
                for record in records.values():
                    record["median"] = summarize(record["rows"])
                    for key in ("flush_ms", "extract_and_flush_ms"):
                        record["median"][key] = statistics.median(r[key] for r in record["rows"])
                    report["results"].append(record)
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        report["complete"] = True
        args.json_out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
