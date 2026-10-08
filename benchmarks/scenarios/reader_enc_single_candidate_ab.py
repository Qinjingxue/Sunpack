"""Measure one-password recursive extraction with old/new scheduler decisions.

The baseline scheduler comes from the requested local Git revision. Both sides
use the current worker/native extension; this isolates the removed host KDF.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
from types import ModuleType

from sunpack.core.passwords.scheduler import PasswordScheduler
from sunpack.core.passwords.verifier.enc_fast import EncFastVerifier
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.config_factory import make_config


async def run(args):
    source = subprocess.run(["git", "show", f"{args.baseline}:sunpack/core/passwords/scheduler.py"],
                            check=True, capture_output=True, text=True, encoding="utf-8").stdout
    baseline = ModuleType("enc_scheduler_baseline")
    sys.modules[baseline.__name__] = baseline
    exec(compile(source, "baseline-scheduler.py", "exec"), baseline.__dict__)
    current = PasswordScheduler.plan_for_extraction
    verifier = EncFastVerifier.verify_batch
    methods = {"before": baseline.PasswordScheduler.plan_for_extraction, "after": current}
    samples = {label: [] for label in methods}
    work = Path("benchmarks/.work/enc").resolve()
    work.mkdir(parents=True, exist_ok=True)
    try:
        for trial in range(-1, args.rounds):
            for label in (["before", "after"] if trial % 2 == 0 else ["after", "before"]):
                PasswordScheduler.plan_for_extraction = methods[label]
                probe_times = []

                def measured_probe(self, *values, **kwargs):
                    started = time.perf_counter()
                    try:
                        return verifier(self, *values, **kwargs)
                    finally:
                        probe_times.append((time.perf_counter() - started) * 1000)

                EncFastVerifier.verify_batch = measured_probe
                with tempfile.TemporaryDirectory(prefix="single-candidate-", dir=work) as temp:
                    config = make_config({"recursive_extract": "2", "cli": {"quiet": True},
                                          "user_passwords": [args.password],
                                          "output": {"root": str(Path(temp) / "out")},
                                          "post_extract": {"archive_cleanup_mode": "k"}})
                    async with PipelineEngine(config) as engine:
                        started = time.perf_counter()
                        result = await engine.run([str(args.path.resolve())], origin=args.origin)
                        elapsed = (time.perf_counter() - started) * 1000
                    assert not result.summary.failed_tasks and result.summary.success_count == 2, result.summary
                    assert len(probe_times) == (1 if label == "before" else 0), probe_times
                    if trial >= 0:
                        samples[label].append({"trial": trial, "ms": elapsed,
                                               "host_enc_probes": len(probe_times),
                                               "host_probe_ms": sum(probe_times)})
        report = {"baseline": args.baseline, "path": str(args.path.resolve()), "origin": args.origin,
                  "method": "Fresh pipeline/worker each run; alternating order; one warmup; "
                            "current native binaries on both sides; existing ENC-to-ZIP recursion.",
                  "samples": samples,
                  "median_ms": {label: statistics.median(row["ms"] for row in rows)
                                for label, rows in samples.items()}, "complete": True}
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(report["median_ms"])
    finally:
        PasswordScheduler.plan_for_extraction = current
        EncFastVerifier.verify_batch = verifier
        sys.modules.pop(baseline.__name__, None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--password", default="sunpack-test")
    parser.add_argument("--origin", choices=["foreground", "watch"], default="foreground")
    parser.add_argument("--rounds", type=int, default=11)
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("rounds must be positive")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
