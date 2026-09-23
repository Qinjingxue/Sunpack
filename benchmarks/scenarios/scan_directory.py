"""Profile native directory scanning by stage.

The parent mode runs an interleaved benchmark. ``fresh-process`` starts one worker
per sample, which resets Python/PyO3 allocator state but intentionally does not
claim to flush the operating-system file cache.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import subprocess
import sys
from pathlib import Path
from time import perf_counter_ns
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sunpack.contracts.filesystem import FileEntry
from sunpack.filesystem.directory_scanner import DirectoryScanner
from benchmarks.harness import render_report, report_from_payload
from sunpack_native import profile_directory_scan


SCAN_STAGE_KEYS = (
    "options_compile_ns",
    "directory_enumeration_ns",
    "metadata_reads_ns",
    "path_matching_ns",
    "record_building_ns",
    "traversal_overhead_ns",
    "file_probe_population_ns",
    "scan_unattributed_ns",
    "native_unattributed_ns",
    "snapshot_building_ns",
)


def _prune_filter(config_path: Path) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    for item in config.get("filesystem", {}).get("scan_filters", []):
        if item.get("name") == "directory_prune" and item.get("enabled", True):
            return dict(item)
    raise RuntimeError(f"directory_prune filter not found in {config_path}")


def _native_options(scenario: str, config_path: Path) -> dict[str, Any]:
    scan_filters = [] if scenario == "filters_off" else [_prune_filter(config_path)]
    config = {
        "filesystem": {
            "directory_scan_mode": "*",
            "scan_filters_enabled": bool(scan_filters),
            "scan_filters": scan_filters,
        }
    }
    options = DirectoryScanner(".", config=config)._native_scan_options()
    if options is None:
        raise RuntimeError("benchmark requires native-compatible filters")
    return options


def run_sample(root: Path, scenario: str, config_path: Path) -> dict[str, Any]:
    options = _native_options(scenario, config_path)
    wall_started = perf_counter_ns()
    snapshot, native_profile = profile_directory_scan(
        str(root),
        None,
        options["patterns"],
        options["prune_dir_globs"],
        options["blocked_extensions"],
        options["blocked_file_names"],
        options["size_ranges"],
        options["mtime_ranges"],
        options["whitelist_rules"],
        True,
    )
    native_wall_ns = perf_counter_ns() - wall_started

    columns_started = perf_counter_ns()
    paths, is_dirs, sizes, mtimes_ns = snapshot.materialize_columns()
    column_export_ns = perf_counter_ns() - columns_started

    legacy_started = perf_counter_ns()
    entries = [
        FileEntry(
            path=Path(path),
            is_dir=bool(is_dir),
            size=size,
            mtime_ns=mtime_ns,
        )
        for path, is_dir, size, mtime_ns in zip(paths, is_dirs, sizes, mtimes_ns)
    ]
    legacy_materialization_ns = perf_counter_ns() - legacy_started

    result = dict(native_profile)
    measured_scan_ns = sum(
        result[key]
        for key in (
            "directory_enumeration_ns",
            "metadata_reads_ns",
            "path_matching_ns",
            "record_building_ns",
            "traversal_overhead_ns",
            "file_probe_population_ns",
        )
    )
    result["scan_unattributed_ns"] = max(
        0, result["scan_total_ns"] - measured_scan_ns
    )
    measured_native_ns = (
        result["options_compile_ns"]
        + result["scan_total_ns"]
        + result["file_probe_population_ns"]
        + result["snapshot_building_ns"]
    )
    result.update(
        {
            "scenario": scenario,
            "native_wall_ns": native_wall_ns,
            "native_unattributed_ns": max(0, native_wall_ns - measured_native_ns),
            "column_export_ns": column_export_ns,
            "legacy_materialization_ns": legacy_materialization_ns,
            "end_to_end_ns": native_wall_ns,
            "row_count": len(snapshot),
        }
    )
    del entries, paths, is_dirs, sizes, mtimes_ns, snapshot
    gc.collect()
    return result


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = round((len(ordered) - 1) * fraction)
    return ordered[index]


def summarize(samples: list[dict[str, Any]]) -> dict[str, Any]:
    end_to_end = [float(item["end_to_end_ns"]) for item in samples]
    stage_medians = {
        key.removesuffix("_ns") + "_ms": statistics.median(
            float(item[key]) / 1_000_000 for item in samples
        )
        for key in SCAN_STAGE_KEYS
    }
    median_total = statistics.median(end_to_end)
    stage_shares = {
        key.removesuffix("_ns") + "_pct": statistics.median(
            float(item[key]) * 100.0 / float(item["end_to_end_ns"])
            for item in samples
        )
        for key in SCAN_STAGE_KEYS
    }
    return {
        "runs": len(samples),
        "row_count": int(statistics.median(item["row_count"] for item in samples)),
        "entries_seen": int(
            statistics.median(item["entries_seen"] for item in samples)
        ),
        "directories_opened": int(
            statistics.median(item["directories_opened"] for item in samples)
        ),
        "end_to_end_ms": {
            "median": median_total / 1_000_000,
            "mean": statistics.mean(end_to_end) / 1_000_000,
            "stdev": (
                statistics.stdev(end_to_end) / 1_000_000
                if len(end_to_end) > 1
                else 0.0
            ),
            "p05": _percentile(end_to_end, 0.05) / 1_000_000,
            "p95": _percentile(end_to_end, 0.95) / 1_000_000,
        },
        "stage_median_ms": stage_medians,
        "stage_share_of_run_pct": stage_shares,
        "deferred_cost_median_ms": {
            "column_export": statistics.median(
                item["column_export_ns"] for item in samples
            ) / 1_000_000,
            "legacy_path_file_entry_materialization": statistics.median(
                item["legacy_materialization_ns"] for item in samples
            ) / 1_000_000,
        },
    }


def _fresh_process_sample(
    root: Path, scenario: str, config_path: Path, timeout_seconds: float
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        "--root",
        str(root),
        "--scenario",
        scenario,
        "--config",
        str(config_path),
    ]
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
        timeout=timeout_seconds,
    )
    return json.loads(completed.stdout)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, default=Path("sunpack_config.json"))
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=300.0, help="Per fresh-process sample wall-clock timeout.")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--cache-mode",
        choices=("warm", "fresh-process", "both"),
        default="both",
    )
    parser.add_argument(
        "--scenario",
        choices=("filters_off", "directory_prune", "both"),
        default="both",
    )
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    config_path = args.config.resolve()

    if args.worker:
        if args.scenario == "both":
            raise SystemExit("worker requires one scenario")
        print(json.dumps(run_sample(root, args.scenario, config_path)))
        return

    scenarios = (
        ["filters_off", "directory_prune"]
        if args.scenario == "both"
        else [args.scenario]
    )
    modes = (
        ["warm", "fresh-process"]
        if args.cache_mode == "both"
        else [args.cache_mode]
    )
    result: dict[str, Any] = {
        "root": str(root),
        "runs_per_group": args.runs,
        "cache_note": (
            "fresh-process resets Python/PyO3 process state; the Windows OS file "
            "cache is not flushed"
        ),
        "groups": {},
    }
    for mode in modes:
        grouped = {scenario: [] for scenario in scenarios}
        if mode == "warm":
            for scenario in scenarios:
                run_sample(root, scenario, config_path)
        for run_index in range(args.runs):
            ordered = scenarios if run_index % 2 == 0 else list(reversed(scenarios))
            for scenario in ordered:
                if mode == "fresh-process":
                    sample = _fresh_process_sample(root, scenario, config_path, args.timeout)
                else:
                    sample = run_sample(root, scenario, config_path)
                grouped[scenario].append(sample)
        result["groups"][mode] = {
            scenario: summarize(samples) for scenario, samples in grouped.items()
        }
    serialized = render_report(report_from_payload("scan.directory", result))
    if args.output is not None:
        args.output.resolve().write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
