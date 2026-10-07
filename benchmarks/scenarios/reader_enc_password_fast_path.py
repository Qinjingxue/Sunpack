"""Measure the production Rust verifier, including concurrent archive batches.

Inputs are independently generated ENC files; Python handles only orchestration
and metrics. Use RAYON_NUM_THREADS=1 in a separate process for a serial baseline.
"""
from __future__ import annotations

import argparse
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sunpack_native import NativeArchiveSession
from benchmarks.harness import BenchmarkWorkspace, measure, render_report, report_from_payload
from benchmarks.harness.memory import ProcessSampler
from benchmarks.harness.timing import timing_summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, action="append", required=True)
    parser.add_argument("--password", default="sunpack-test")
    parser.add_argument("--wrong-passwords", type=int, default=64)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    if args.rounds < 1 or args.jobs < 1 or args.wrong_passwords < 0:
        parser.error("rounds/jobs must be positive; wrong-passwords must be nonnegative")
    candidates = [f"wrong-candidate-{i}" for i in range(args.wrong_passwords)] + [args.password]
    results = {"configuration": vars(args) | {"path": [str(p) for p in args.path],
               "rayon_num_threads": os.environ.get("RAYON_NUM_THREADS", "default")}, "inputs": []}
    for path in args.path:
        session = NativeArchiveSession(str(path.resolve()))
        try:
            with ThreadPoolExecutor(max_workers=args.jobs) as pool, ProcessSampler(0.02) as sampler:
                before = sampler.take()
                def invoke():
                    outcomes = list(pool.map(lambda _: session.enc_fast_verify_passwords(candidates), range(args.jobs)))
                    assert all(o["status"] == "match" and o["matched_index"] == args.wrong_passwords for o in outcomes), outcomes
                    return outcomes
                measured = measure(invoke, runs=args.rounds)
                after = sampler.take()
                row = {"path": str(path), "size_bytes": path.stat().st_size,
                       "timing": timing_summary(measured), "rounds": [r.to_dict() for r in measured],
                       "logical_reader": dict(session.stats()),
                       "peak_rss_delta_mib": max(s.rss_mib for s in sampler.samples) - before.rss_mib,
                       "residual_rss_delta_mib": after.rss_mib - before.rss_mib}
                results["inputs"].append(row)
        finally:
            session.close()
    with BenchmarkWorkspace("reader.enc-password-fast-path") as workspace:
        rendered = render_report(report_from_payload("reader.enc-password-fast-path", results))
        workspace.write_result_text("report.json", rendered)
        print(rendered)


if __name__ == "__main__":
    main()
