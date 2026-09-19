"""Calibrate native-worker initial concurrency across real archive formats."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
import zipfile
from pathlib import Path
from typing import Any

import psutil

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from benchmarks.scenarios.extraction_format_matrix import RAR, SEVEN_ZIP, _run_7z, _run_rar
from benchmarks.scenarios.worker_small_file_scheduling import ADMISSION_CASES, _run_batch
from sunpack.support.resources import get_sevenzip_bridge_worker_path
from tests.helpers.tool_config import get_7z_cli_dll_path


SCENARIO = "extraction.worker-initial-concurrency-matrix"
ARCHIVE_VARIANTS = (
    "zip-store",
    "zip-deflate",
    "7z-nonsolid",
    "7z-solid",
    "rar-nonsolid",
    "rar-solid",
)
CPU_WEIGHT_MODES = ("unit", "legacy")


def _cpu_weight_for_variant(variant: str, mode: str) -> int:
    if mode == "unit":
        return 1
    if mode != "legacy":
        raise ValueError(f"unknown CPU weight mode {mode!r}")
    return {
        "zip-store": 1,
        "zip-deflate": 2,
        "7z-nonsolid": 3,
        "7z-solid": 4,
        "rar-nonsolid": 1,
        "rar-solid": 2,
    }[variant]


def _parse_int_list(value: str, *, minimum: int, maximum: int, label: str) -> list[int]:
    parsed: list[int] = []
    for item in value.split(","):
        try:
            number = int(item.strip())
        except ValueError as exc:
            raise ValueError(f"invalid {label} value {item!r}") from exc
        if number < minimum or number > maximum:
            raise ValueError(f"{label} values must be between {minimum} and {maximum}")
        if number not in parsed:
            parsed.append(number)
    if not parsed:
        raise ValueError(f"at least one {label} value is required")
    return parsed


def _parse_variants(values: list[str]) -> list[str]:
    selected: list[str] = []
    for value in values:
        for item in value.split(","):
            variant = item.strip()
            if not variant:
                continue
            if variant not in ARCHIVE_VARIANTS:
                raise ValueError(
                    f"unknown archive variant {variant!r}; choose from {', '.join(ARCHIVE_VARIANTS)}"
                )
            if variant not in selected:
                selected.append(variant)
    return selected or list(ARCHIVE_VARIANTS)


def _automatic_capacity() -> tuple[int, dict[str, int]]:
    logical_processors = max(1, os.cpu_count() or 1)
    available_memory_bytes = int(psutil.virtual_memory().available)
    memory_budget_bytes = available_memory_bytes * 7 // 10
    capacity = logical_processors
    return capacity, {
        "logical_processors": logical_processors,
        "available_memory_bytes": available_memory_bytes,
        "memory_budget_bytes": memory_budget_bytes,
    }


def _write_payloads(root: Path, *, file_count: int, file_size_bytes: int) -> int:
    root.mkdir(parents=True, exist_ok=True)
    common = bytes((index * 17 + 29) % 251 for index in range(file_size_bytes))
    for index in range(file_count):
        marker = f"sunpack-calibration-{index:04d}".encode("ascii")
        payload = (marker + common)[:file_size_bytes]
        (root / f"payload-{index:04d}.bin").write_bytes(payload)
    return file_count * file_size_bytes


def _create_variant(
    root: Path,
    source: Path,
    variant: str,
    *,
    cpu_weight_mode: str,
) -> dict[str, Any]:
    target: Path
    format_hint = variant.split("-", 1)[0]
    solid = variant.endswith("solid") and not variant.endswith("nonsolid")
    cpu_weight = _cpu_weight_for_variant(variant, cpu_weight_mode)
    if variant == "zip-store" or variant == "zip-deflate":
        target = root / f"{variant}.zip"
        compression = zipfile.ZIP_STORED if variant == "zip-store" else zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(target, "w", compression=compression, compresslevel=None if compression == zipfile.ZIP_STORED else 9) as stream:
            for path in sorted(source.iterdir()):
                stream.write(path, path.name)
    elif variant == "7z-nonsolid":
        target = root / f"{variant}.7z"
        if not _run_7z(["a", "-y", "-t7z", "-mx=5", "-ms=off", str(target), str(source)]):
            raise RuntimeError("7-Zip failed to create the non-solid calibration archive")
    elif variant == "7z-solid":
        target = root / f"{variant}.7z"
        if not _run_7z(["a", "-y", "-t7z", "-mx=5", "-ms=on", str(target), str(source)]):
            raise RuntimeError("7-Zip failed to create the solid calibration archive")
    elif variant == "rar-nonsolid":
        target = root / f"{variant}.rar"
        if not _run_rar(["a", "-idq", "-r", "-ep1", "-m5", "-s-", str(target), str(source)]):
            raise RuntimeError("RAR failed to create the non-solid calibration archive")
    elif variant == "rar-solid":
        target = root / f"{variant}.rar"
        if not _run_rar(["a", "-idq", "-r", "-ep1", "-m5", "-s", str(target), str(source)]):
            raise RuntimeError("RAR failed to create the solid calibration archive")
    else:  # pragma: no cover - parser owns the closed variant set.
        raise ValueError(variant)
    if not target.is_file():
        raise RuntimeError(f"calibration archive was not created: {target}")
    return {
        "variant": variant,
        "path": target,
        "format_hint": format_hint,
        "solid_archive": solid,
        "cpu_weight": cpu_weight,
        "profile_key": f"benchmark-initial-{variant}",
        "archive_bytes": target.stat().st_size,
    }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, dict[int, list[dict[str, Any]]]] = {}
    for row in rows:
        grouped.setdefault(str(row["archive_variant"]), {}).setdefault(
            int(row["initial_active_jobs"]), []
        ).append(row)
    by_variant: dict[str, Any] = {}
    for variant, by_initial in sorted(grouped.items()):
        candidates: dict[str, Any] = {}
        for initial, samples in sorted(by_initial.items()):
            candidates[str(initial)] = {
                "runs": len(samples),
                "all_passed": all(bool(sample["all_passed"]) for sample in samples),
                "median_throughput_jobs_per_second": round(statistics.median(
                    float(sample["throughput_jobs_per_second"]) for sample in samples
                ), 6),
                "median_queue_latency_p95_ms": round(statistics.median(
                    float(sample["queue_latency_p95_ms"]) for sample in samples
                ), 6),
                "median_observed_peak_active_jobs": round(statistics.median(
                    float(sample["observed_peak_active_jobs"]) for sample in samples
                ), 6),
                "median_worker_rss_peak_mib": round(statistics.median(
                    float(sample["worker_rss_peak_mib"]) for sample in samples
                ), 6),
            }
        solid = bool(next(iter(by_initial.values()))[0]["solid_archive"])
        best = max(
            candidates,
            key=lambda initial: candidates[initial]["median_throughput_jobs_per_second"],
        )
        throughputs = [item["median_throughput_jobs_per_second"] for item in candidates.values()]
        by_variant[variant] = {
            "solid_archive": solid,
            "observed_serialized": solid and all(
                float(candidate["median_observed_peak_active_jobs"]) <= 1.0
                for candidate in candidates.values()
            ),
            "best_measured_initial_active_jobs": int(best),
            "throughput_spread_percent": round(
                (max(throughputs) - min(throughputs)) * 100.0 / max(throughputs), 3
            ),
            "by_initial_active_jobs": candidates,
        }
    def cross_variant_scores(*, include_solid: bool) -> dict[str, Any]:
        normalized_by_initial: dict[int, list[float]] = {}
        for variant in by_variant.values():
            if variant["solid_archive"] and not include_solid:
                continue
            candidates = variant["by_initial_active_jobs"]
            best_throughput = max(
                float(candidate["median_throughput_jobs_per_second"])
                for candidate in candidates.values()
            )
            for initial, candidate in candidates.items():
                normalized_by_initial.setdefault(int(initial), []).append(
                    float(candidate["median_throughput_jobs_per_second"]) / best_throughput
                )
        cross_variant = {
            str(initial): {
                "mean_normalized_throughput": round(statistics.mean(scores), 6),
                "worst_normalized_throughput": round(min(scores), 6),
            }
            for initial, scores in sorted(normalized_by_initial.items())
        }
        recommended = max(
            cross_variant,
            key=lambda initial: (
                cross_variant[initial]["mean_normalized_throughput"],
                cross_variant[initial]["worst_normalized_throughput"],
            ),
            default=None,
        )
        return {
            "recommended_initial_active_jobs": int(recommended) if recommended is not None else None,
            "by_initial_active_jobs": cross_variant,
        }
    return {
        "all_passed": bool(rows) and all(bool(row["all_passed"]) for row in rows),
        "sample_count": len(rows),
        "by_archive_variant": by_variant,
        "cross_variant_all": cross_variant_scores(include_solid=True),
        "cross_variant_non_solid": cross_variant_scores(include_solid=False),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Calibrate native-worker initial concurrency across ZIP, 7z, RAR, solid, and non-solid archives."
    )
    parser.add_argument("--initial-active-jobs", default="8,12,16,20")
    parser.add_argument("--cpu-weight-mode", choices=CPU_WEIGHT_MODES, default="unit")
    parser.add_argument("--format", action="append", default=[], dest="formats")
    parser.add_argument("--capacity", type=int, default=0, help="0 mirrors the worker's CPU/RAM automatic capacity.")
    parser.add_argument("--jobs", type=int, default=48)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--files-per-archive", type=int, default=16)
    parser.add_argument("--file-size-bytes", type=int, default=65536)
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--sample-interval-ms", type=int, default=100)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    try:
        initials = _parse_int_list(args.initial_active_jobs, minimum=1, maximum=32, label="initial concurrency")
        variants = _parse_variants(args.formats)
    except ValueError as exc:
        parser.error(str(exc))
    automatic_capacity, resource_snapshot = _automatic_capacity()
    capacity = automatic_capacity if args.capacity == 0 else args.capacity
    if capacity < 1 or capacity > 32:
        parser.error("--capacity must be 0 or between 1 and 32")
    if any(initial > capacity for initial in initials):
        parser.error("initial concurrency candidates must not exceed the selected capacity")
    if args.jobs < 1 or args.clients < 1 or args.jobs % args.clients:
        parser.error("--jobs must be positive and evenly divisible by --clients")
    if args.runs < 1 or args.warmups < 0 or args.files_per_archive < 1 or args.file_size_bytes < 1:
        parser.error("runs and corpus sizes must be positive; warmups must be non-negative")
    if not SEVEN_ZIP.is_file() or not RAR.is_file():
        parser.error("bundled 7z.exe and Rar.exe are required for the calibration matrix")
    try:
        worker_path = Path(get_sevenzip_bridge_worker_path()).resolve()
        dll_path = Path(get_7z_cli_dll_path()).resolve()
    except FileNotFoundError as exc:
        parser.error(str(exc))

    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        payload_root = workspace.corpus / "payloads"
        payload_bytes = _write_payloads(
            payload_root,
            file_count=args.files_per_archive,
            file_size_bytes=args.file_size_bytes,
        )
        archive_root = workspace.corpus / "archives"
        archive_root.mkdir(parents=True, exist_ok=True)
        archives = [
            _create_variant(
                archive_root,
                payload_root,
                variant,
                cpu_weight_mode=args.cpu_weight_mode,
            )
            for variant in variants
        ]
        rows: list[dict[str, Any]] = []
        for archive in archives:
            corpus = {
                "archives": [archive["path"]] * args.jobs,
                "jobs": args.jobs,
                "files_per_archive": args.files_per_archive,
                "file_size_bytes": args.file_size_bytes,
                "payload_bytes_per_job": payload_bytes,
                "input_bytes": archive["archive_bytes"],
                "format_hint": archive["format_hint"],
                "solid_archive": archive["solid_archive"],
                "profile_key": archive["profile_key"],
            }
            for run in range(args.warmups + args.runs):
                ordered_initials = initials if run % 2 == 0 else list(reversed(initials))
                for initial in ordered_initials:
                    admission_case = dict(ADMISSION_CASES["adaptive-baseline"])
                    admission_case.update({
                        "name": "adaptive-baseline",
                        "adaptive_enabled": True,
                        "initial_active_jobs": initial,
                        "memory_reserve_bytes": 64 << 20,
                        "cpu_weight": archive["cpu_weight"],
                    })
                    measured = run >= args.warmups
                    run_number = run - args.warmups if measured else run
                    label = (
                        f"{archive['variant']}-initial-{initial}-"
                        f"{'run' if measured else 'warmup'}-{run_number}"
                    )
                    print(f"{label}: submitting {args.jobs} jobs", flush=True)
                    row, _trace = _run_batch(
                        workspace=workspace,
                        worker_path=worker_path,
                        dll_path=dll_path,
                        corpus=corpus,
                        capacity=capacity,
                        client_count=args.clients,
                        timeout_seconds=args.timeout_seconds,
                        sample_interval_ms=args.sample_interval_ms,
                        admission_case=admission_case,
                        label=label,
                    )
                    shutil.rmtree(workspace.outputs / label, ignore_errors=True)
                    if measured:
                        row.update({
                            "run": run_number,
                            "archive_variant": archive["variant"],
                            "archive_bytes": archive["archive_bytes"],
                            "solid_archive": archive["solid_archive"],
                            "cpu_weight": archive["cpu_weight"],
                            "initial_active_jobs": initial,
                        })
                        rows.append(row)
                    print(
                        f"  throughput={row['throughput_jobs_per_second']} jobs/s "
                        f"p95_queue={row['queue_latency_p95_ms']}ms "
                        f"peak_active={row['observed_peak_active_jobs']} passed={row['all_passed']}",
                        flush=True,
                    )
        summary = _summarize(rows)
        report = {
            "parameters": {
                "initial_active_jobs": initials,
                "cpu_weight_mode": args.cpu_weight_mode,
                "formats": variants,
                "capacity": capacity,
                "capacity_was_automatic": args.capacity == 0,
                "jobs": args.jobs,
                "clients": args.clients,
                "runs": args.runs,
                "warmups": args.warmups,
                "files_per_archive": args.files_per_archive,
                "file_size_bytes": args.file_size_bytes,
            },
            "environment": {
                **resource_snapshot,
                "worker_path": str(worker_path),
                "python": sys.version,
            },
            "corpus": {
                "payload_bytes_per_job": payload_bytes,
                "archives": [{**archive, "path": str(archive["path"])} for archive in archives],
            },
            "results": rows,
            "summary": summary,
            "artifacts": {"result_dir": str(workspace.result_dir)},
        }
        rendered = render_report(report_from_payload(SCENARIO, report))
        workspace.write_result_text("report.json", rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
