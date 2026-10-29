"""Rotate sync/thread/OVERLAPPED workers on the same existing input archives.

Uses the existing worker runner, sampler and workspace. Python orchestrates;
native extraction verifies archive CRCs and Rust hashes the first output of
each engine outside the timed region to check content equivalence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sunpack_native import fast_hash128_file

from benchmarks.harness import BenchmarkWorkspace
from benchmarks.scenarios.worker_concurrency_300m import run_worker
from benchmarks.scenarios.sevenzip_worker_matrix import _volume_paths
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from tests.helpers.tool_config import get_7z_cli_dll_path


def output_signature(root: Path) -> list[tuple[str, int, str]]:
    return sorted((str(path.relative_to(root)), path.stat().st_size, fast_hash128_file(str(path)))
                  for path in root.rglob("*") if path.is_file())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--case", action="append", required=True, metavar="FORMAT=PATH")
    parser.add_argument("--engines", default="sync,thread,overlapped",
                        help="Comma-separated sync,thread,overlapped,policy; policy uses format defaults")
    parser.add_argument("--layout", choices=("file", "ranges"), default="file")
    parser.add_argument("--concurrency", default="1,4,8")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--window-kib", type=int, default=512)
    parser.add_argument("--dry-run", action="store_true", help="Decode and verify CRC without output writes")
    parser.add_argument("--profile", action="store_true", help="Separate diagnostic run; adds input timing overhead")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    widths = [int(value) for value in args.concurrency.split(",")]
    if args.trials < 1 or not widths or min(widths) < 1 or not 64 <= args.window_kib <= 16384:
        parser.error("positive trials/concurrency and window-kib 64..16384 required")
    cases = []
    for value in args.case:
        name, path = value.split("=", 1)
        archive = Path(path).resolve(strict=True)
        cases.append({"format": name, "item": {"format": name, "path": archive}})
        if args.layout == "ranges":
            volumes = _volume_paths(cases[-1]["item"])
            ranges = [{"path": str(path), "start": 0, "end": path.stat().st_size} for path in volumes]
            cases[-1]["item"]["archive_input"] = {
                "entry_path": str(archive), "format_hint": name.removesuffix("-split"),
                "open_mode": "file_range" if len(ranges) == 1 else "concat_ranges",
                "parts" if len(ranges) == 1 else "ranges": ranges,
            }
    engines = {"sync": args.after.resolve(strict=True), "thread": args.before.resolve(strict=True),
               "overlapped": args.after.resolve(strict=True), "policy": args.after.resolve(strict=True)}
    selected = args.engines.split(",")
    if not selected or len(selected) != len(set(selected)) or any(name not in engines for name in selected):
        parser.error("--engines must select distinct sync,thread,overlapped,policy engines")
    engines = {name: engines[name] for name in selected}
    os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "1" if args.profile else "0"
    os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "0"
    os.environ["SUNPACK_WRITER_PROBE"] = "0"
    os.environ["SUNPACK_SEVENZIP_PREFETCH_WINDOW_KIB"] = str(args.window_kib)
    dll = Path(get_7z_cli_dll_path()).resolve()
    report = {"platform": platform.platform(), "cpu": platform.processor(), "engines": engines, "layout": args.layout,
              "binary_fast_hash128": {name: fast_hash128_file(str(path)) for name, path in engines.items()},
              "cases": cases, "trials": args.trials, "window_kib": args.window_kib,
              "cache": "one untimed warmup per engine/width/case; OS cache retained",
              "dry_run": args.dry_run, "profile": args.profile, "complete": False, "results": []}

    def save() -> None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, default=str, indent=2), encoding="utf-8")

    with BenchmarkWorkspace("extraction.worker-overlapped-input") as workspace:
        for case in cases:
            for width in widths:
                rows = {name: [] for name in engines}
                expected = None
                signatures = {}
                names = list(engines)
                # Each round rotates first position; alternating direction
                # also balances adjacent engine order over six trials.
                for trial in range(-1, args.trials):
                    rotation = max(trial, 0) % len(names)
                    order = names[rotation:] + names[:rotation]
                    if len(names) > 2 and trial >= 0 and trial % 2: order.reverse()
                    for name in order:
                        if name == "policy":
                            os.environ.pop("SUNPACK_SEVENZIP_PREFETCH", None)
                        else:
                            os.environ["SUNPACK_SEVENZIP_PREFETCH"] = "0" if name == "sync" else "1"
                        output = workspace.outputs / f"{case['format']}-{width}-{trial}-{name}"
                        worker = _NativeWorkerProcess(str(engines[name]), None)
                        try:
                            row = run_worker(worker, [case] * width, output, width, dll, 600, args.dry_run)
                        finally:
                            worker.close()
                        if not row["passed"]:
                            raise RuntimeError(f"{name} failed: {row}")
                        if trial >= 0 and not args.dry_run and name not in signatures:
                            signature = output_signature(output)
                            if not signature:
                                raise RuntimeError("successful extraction produced no files")
                            if expected is None: expected = signature
                            if signature != expected:
                                raise RuntimeError(f"output content differs: {case['format']} c={width} {name}")
                            signatures[name] = True
                        row["trial"] = trial
                        if trial >= 0:
                            rows[name].append(row)
                        print(f"{case['format']} c={width} t={trial} {name}: wall={row['wall_ms']:.1f} "
                              f"cpu={row['cpu_ms']:.1f} rss={row['rss_peak_mib']:.1f}", flush=True)
                        # BenchmarkWorkspace creates and owns this exact subtree.
                        shutil.rmtree(output, ignore_errors=True)
                entry = {"format": case["format"], "concurrency": width, "samples": rows,
                         "output_content_equal": None if args.dry_run else len(signatures) == len(engines)}
                for name, samples in rows.items():
                    entry[name] = {key: statistics.median(sample[key] for sample in samples)
                                   for key in ("wall_ms", "cpu_ms", "rss_peak_mib", "other_cpu_cores")}
                for baseline in (name for name in ("sync", "thread") if name in rows and "overlapped" in rows):
                    entry[f"gain_vs_{baseline}_percent"] = 100 * (1 - entry["overlapped"]["wall_ms"] / entry[baseline]["wall_ms"])
                    paired = [100 * (1 - after["wall_ms"] / before["wall_ms"])
                              for before, after in zip(rows[baseline], rows["overlapped"])]
                    entry[f"paired_gain_vs_{baseline}_percent"] = {
                        "median": statistics.median(paired), "min": min(paired), "max": max(paired)}
                report["results"].append(entry)
                save()
        report["complete"] = True
        save()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
