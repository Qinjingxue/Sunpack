"""Alternating native ENC compute benchmarks; Python only schedules processes.

Prebuild the Rust examples, then pass --binary LABEL=PATH. Both sides use
identical arguments and CPU affinity; each process warms up before sampling.
For MAC mode, --mode LABEL=serial|bounded selects the upstream/bounded path.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
from pathlib import Path
import statistics
import subprocess

import psutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=["ctr", "mac", "decrypt"], required=True)
    parser.add_argument("--binary", action="append", required=True, help="LABEL=PATH")
    parser.add_argument("--mode", action="append", default=[], help="LABEL=serial|bounded (MAC)")
    parser.add_argument("--input", action="append", default=[], help="LABEL=ENC_PATH (decrypt)")
    parser.add_argument("--password", default="sunpack-test")
    parser.add_argument("--mib", type=int, default=128)
    parser.add_argument("--threads", default="1,4")
    parser.add_argument("--algorithms", default="0,4,9")
    parser.add_argument("--rounds", type=int, default=9)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--passes", type=int, default=2)
    parser.add_argument("--affinity", help="Logical CPU IDs, only applied to benchmark processes")
    parser.add_argument("--executor-threads", type=int)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.rounds <= args.warmup or args.warmup < 0 or min(args.mib, args.passes) < 1:
        parser.error("positive size/passes and rounds greater than warmup required")
    binaries = {label: str(Path(path).resolve()) for label, path in
                (spec.split("=", 1) for spec in args.binary)}
    if len(binaries) != len(args.binary):
        parser.error("duplicate binary label")
    modes = dict(spec.split("=", 1) for spec in args.mode)
    if any(label not in binaries or mode not in {"serial", "bounded"} for label, mode in modes.items()):
        parser.error("MAC modes must be serial/bounded and refer to a binary label")
    if args.executor_threads is not None and args.executor_threads < 1:
        parser.error("executor threads must be positive")
    inputs = dict(spec.split("=", 1) for spec in args.input)
    if args.kind == "decrypt" and not inputs:
        parser.error("decrypt requires --input")
    threads = [int(n) for n in args.threads.split(",")]
    if min(threads) < 1:
        parser.error("threads must be positive")
    affinity = [int(n) for n in args.affinity.split(",")] if args.affinity else None
    if affinity:
        psutil.Process().cpu_affinity(affinity)  # Child processes inherit this mask.
    env = os.environ.copy()
    if args.executor_threads:
        env["RAYON_NUM_THREADS"] = str(args.executor_threads)
    cases = list(inputs.items()) if args.kind == "decrypt" else [("compute", "")]
    report = {"method": "Alternating order across passes; per-process warmup excluded; "
                        "native timing; decrypt includes cached reads/MAC/CTR, excludes KDF/writes.",
              "arguments": vars(args) | {"json_out": str(args.json_out)},
              "binaries": binaries, "affinity": affinity,
              "executor_threads": env.get("RAYON_NUM_THREADS"), "results": []}
    for case, path in cases:
        for budget in threads:
            samples = {label: [] for label in binaries}
            for turn in range(args.passes):
                labels = list(binaries)
                if turn % 2:
                    labels.reverse()
                for label in labels:
                    if args.kind == "decrypt":
                        extra = [path, args.password, str(budget), str(args.rounds)]
                    else:
                        extra = [str(args.mib), str(args.rounds), str(budget),
                                 modes.get(label, "bounded") if args.kind == "mac" else args.algorithms]
                    result = subprocess.run([binaries[label], *extra], check=True,
                                            capture_output=True, text=True, env=env,
                                            creationflags=subprocess.CREATE_NO_WINDOW)
                    rows = list(csv.DictReader(io.StringIO(result.stdout)))
                    samples[label].extend(row | {"pass": turn} for row in rows
                                          if int(row["round"]) >= args.warmup)
            algorithms = sorted({row.get("algorithm", case) for rows in samples.values() for row in rows})
            medians = {algorithm: {label: statistics.median(float(row["mib_per_second"]) for row in rows
                                                           if row.get("algorithm", case) == algorithm)
                                   for label, rows in samples.items()}
                       for algorithm in algorithms}
            report["results"].append({"case": case, "threads": budget,
                                      "medians_mib_s": medians, "samples": samples})
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(case, budget, medians, flush=True)
    report["complete"] = True
    args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
