from __future__ import annotations

import argparse
import gc
import json
import os
import random
import statistics
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from sunpack_native import NativeArchiveSession, clear_reader_resources, reader_cache_stats

from benchmarks.harness import (
    BenchmarkWorkspace,
    ProcessSampler,
    measure,
    metrics_delta,
    render_report,
    report_from_payload,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLE = REPO_ROOT / "testfiles" / "sample.mp4"
SCENARIO = "reader.embedded-scan"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark full SunPack scan and native embedded archive scanning."
    )
    parser.add_argument("path", nargs="?", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--skip-cli", action="store_true")
    parser.add_argument(
        "--generate-gib",
        type=float,
        default=0.0,
        help="Generate a stored ZIP64 fixture of this size and benchmark it (for example, 10).",
    )
    parser.add_argument(
        "--generate-plan5-mib",
        type=int,
        default=0,
        help=(
            "Generate a Plan 5 mixed embedded-archive carrier of this size in MiB. "
            "The fixture contains 128 real ZIP/7z/RAR/TAR/gzip/bzip2/xz/zstd archives."
        ),
    )
    parser.add_argument(
        "--iocp-chunk-mib",
        action="append",
        type=float,
        help="Logical chunk size for IOCP mode; repeat to sweep values (default: 2 MiB).",
    )
    parser.add_argument(
        "--iocp-buffers",
        action="append",
        type=int,
        help="Maximum in-flight IOCP buffers; repeat to sweep values (default: 2).",
    )
    parser.add_argument(
        "--iocp-workers",
        action="append",
        type=int,
        help="IOCP scan workers; repeat to sweep values (default: 4).",
    )
    parser.add_argument("--sample-interval", type=float, default=0.1)
    parser.add_argument("--cli-timeout", type=float, default=600.0, help="Wall-clock timeout for the CLI scan subprocess.")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    parser.add_argument(
        "--baseline-report",
        type=Path,
        help="Compare the first native window with a previous report.json and fail on regression.",
    )
    parser.add_argument(
        "--max-regression-percent",
        type=float,
        default=5.0,
        help="Maximum allowed native wall-median regression (default: 5%%).",
    )
    return parser.parse_args()


def benchmark_cli(path: Path, timeout_seconds: float) -> dict:
    environment = os.environ.copy()
    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "sunpack",
                "scan",
                "--json",
                "--quiet",
                "--no-pause",
                str(path),
            ],
            cwd=REPO_ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {
            "wall_ms": round((time.perf_counter_ns() - started) / 1_000_000, 3),
            "exit_code": -124,
            "timed_out": True,
            "timeout_seconds": timeout_seconds,
        }
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if completed.returncode:
        raise RuntimeError(
            f"sunpack scan failed ({completed.returncode}):\n{completed.stderr}"
        )
    return {
        "wall_ms": round(elapsed_ms, 3),
        "exit_code": completed.returncode,
        "timed_out": False,
    }


def benchmark_native(
    path: Path,
    rounds: int,
    sample_interval: float,
    iocp_chunk_mib: float = 2.0,
    iocp_buffers: int = 8,
    iocp_workers: int = 2,
    expected_candidates: set[tuple[str, int]] | None = None,
) -> dict:
    clear_reader_resources()
    session = NativeArchiveSession(str(path))
    before = dict(reader_cache_stats())
    iocp_chunk_bytes = max(64 * 1024, int(iocp_chunk_mib * 1024**2))

    def invoke() -> dict:
        result = dict(
            session.scan_embedded_archives(
                iocp_chunk_bytes=iocp_chunk_bytes,
                iocp_buffers=iocp_buffers,
                iocp_workers=iocp_workers,
            )
        )
        assert result["complete"] is True
        assert int(result["read_bytes"]) == path.stat().st_size
        if expected_candidates is not None:
            actual = {
                (str(candidate["format"]), int(candidate["offset"]))
                for candidate in result["candidates"]
            }
            missing = expected_candidates - actual
            assert not missing, f"embedded scan missed {len(missing)} expected archives: {sorted(missing)[:8]}"
        return result

    sampler = ProcessSampler(interval_seconds=sample_interval)
    sampler.start()
    try:
        measured = measure(invoke, runs=rounds)
    finally:
        process_samples = sampler.stop()

    rows = [{
        "round": row.iteration + 1,
        "wall_ms": round(row.wall_ms, 3),
        "cpu_ms": round(row.cpu_ms, 3),
        "hits": len(row.value["hits"]),
        "candidates": len(row.value["candidates"]),
        "read_bytes": int(row.value["read_bytes"]),
    } for row in measured]
    last_result = measured[-1].value
    after_scan = dict(reader_cache_stats())
    gc.collect()
    cleared = dict(clear_reader_resources())
    after_clear = dict(reader_cache_stats())
    wall_values = [row["wall_ms"] for row in rows]
    size = path.stat().st_size
    median_ms = statistics.median(wall_values)
    peak = max(process_samples, key=lambda sample: sample.rss_mib, default=None)
    peak_private = max(process_samples, key=lambda sample: sample.private_mib, default=None)
    return {
        "rounds": rows,
        "wall_median_ms": round(median_ms, 3),
        "throughput_gb_s": round(size / 1_000_000_000 / (median_ms / 1000), 3),
        "throughput_gib_s": round(size / (1024**3) / (median_ms / 1000), 3),
        "io_mode": "iocp",
        "scan_read_bytes": int(last_result.get("scan_read_bytes") or 0),
        "scan_read_operations": int(last_result.get("scan_read_operations") or 0),
        "iocp_chunk_mib": round(iocp_chunk_mib, 3),
        "iocp_chunk_bytes": iocp_chunk_bytes,
        "iocp_buffers": iocp_buffers,
        "iocp_workers": iocp_workers,
        "reader_delta": metrics_delta(before, after_scan),
        "reader_after_scan": after_scan,
        "reader_after_clear": after_clear,
        "reader_cleanup": cleared,
        "memory": {
            "sample_interval_seconds": sample_interval,
            "sample_count": len(process_samples),
            "peak_rss_mib": round(peak.rss_mib, 3) if peak else 0.0,
            "peak_private_mib": round(peak_private.private_mib, 3) if peak_private else 0.0,
            "peak_rss_sample": peak.to_dict() if peak else None,
            "peak_private_sample": peak_private.to_dict() if peak_private else None,
            "after_scan_sample": process_samples[-1].to_dict() if process_samples else None,
        },
        "validated_candidates": last_result["candidates"],
    }


def generate_stored_zip64(path: Path, payload_gib: float) -> Path:
    """Create a large stored ZIP without retaining the payload in Python memory."""

    payload_size = int(payload_gib * 1024**3)
    if payload_size < 1:
        raise ValueError("payload_gib must be positive")
    path.parent.mkdir(parents=True, exist_ok=True)
    pattern = b"sunpack-embedded-scan-benchmark\n"
    block = (pattern * ((1024 * 1024 // len(pattern)) + 1))[: 1024 * 1024]
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("payload.bin")
        info.compress_type = zipfile.ZIP_STORED
        with archive.open(info, "w", force_zip64=payload_size > 0xFFFFFFFF) as writer:
            remaining = payload_size
            while remaining:
                chunk_size = min(remaining, len(block))
                writer.write(block[:chunk_size])
                remaining -= chunk_size
    return path


def generate_plan5_mixed_carrier(
    root: Path,
    target: Path,
    size_mib: int,
) -> tuple[Path, set[tuple[str, int]], dict[str, object]]:
    """Build the real Plan 5 matrix and center it in a streamed fixed-size carrier."""

    from tests.real.plan5_embedded_archives.plan5_support import build_large_embedded_case

    target_size = size_mib * 1024**2
    if target_size < 1:
        raise ValueError("size_mib must be positive")
    case = build_large_embedded_case(root / "plan5", count=128, payload_size=64)
    source_size = case.file_path.stat().st_size
    if source_size > target_size:
        raise ValueError(
            f"Plan 5 matrix is {source_size} bytes and does not fit in {target_size} bytes"
        )

    prefix_size = (target_size - source_size) // 2
    suffix_size = target_size - prefix_size - source_size
    zero_block = bytes(1024 * 1024)

    def write_zeros(writer, count: int) -> None:
        remaining = count
        while remaining:
            chunk_size = min(remaining, len(zero_block))
            writer.write(zero_block[:chunk_size])
            remaining -= chunk_size

    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as writer, case.file_path.open("rb") as source:
        write_zeros(writer, prefix_size)
        while chunk := source.read(1024 * 1024):
            writer.write(chunk)
        write_zeros(writer, suffix_size)

    expected = {
        (segment.archive_format, prefix_size + segment.offset)
        for segment in case.segments
    }
    formats = sorted({archive_format for archive_format, _offset in expected})
    required_formats = {"zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "zstd"}
    missing_formats = required_formats - set(formats)
    if missing_formats:
        raise RuntimeError(f"Plan 5 benchmark is missing formats: {sorted(missing_formats)}")
    return target, expected, {
        "size_mib": size_mib,
        "segment_count": len(case.segments),
        "formats": formats,
        "matrix_size_bytes": source_size,
        "matrix_offset": prefix_size,
        "padding": "streamed-zero-fill",
    }


def run_report(
    path: Path,
    args: argparse.Namespace,
    config: dict[str, object],
    expected_candidates: set[tuple[str, int]] | None = None,
) -> dict:
    path = path.resolve()
    if not path.is_file():
        raise SystemExit(f"sample does not exist: {path}")
    if args.rounds < 1:
        raise SystemExit("rounds must be positive")
    if args.sample_interval <= 0:
        raise SystemExit("sample-interval must be positive")
    if float(config.get("iocp_chunk_mib", 2.0)) <= 0:
        raise SystemExit("iocp-chunk-mib must be positive")
    if int(config.get("iocp_buffers", 2)) < 2:
        raise SystemExit("iocp-buffers must be at least 2")
    if int(config.get("iocp_workers", 4)) < 1:
        raise SystemExit("iocp-workers must be positive")
    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "cli_scan": None if args.skip_cli else benchmark_cli(path, float(config.get("cli_timeout", 600.0))),
        "native_embedded_scan": benchmark_native(
            path,
            args.rounds,
            args.sample_interval,
            float(config.get("iocp_chunk_mib", 2.0)),
            int(config.get("iocp_buffers", 2)),
            int(config.get("iocp_workers", 4)),
            expected_candidates,
        ),
    }


def compare_with_baseline(current: dict, baseline_path: Path, max_regression_percent: float) -> dict:
    if max_regression_percent < 0:
        raise ValueError("max_regression_percent must be nonnegative")
    baseline_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_summary = baseline_payload["summary"]
    baseline_window = (
        baseline_summary["window_results"][0]
        if "window_results" in baseline_summary
        else baseline_summary
    )
    current_native = current["native_embedded_scan"]
    baseline_native = baseline_window["native_embedded_scan"]
    current_median = float(current_native["wall_median_ms"])
    baseline_median = float(baseline_native["wall_median_ms"])
    regression_percent = (current_median / baseline_median - 1.0) * 100.0
    current_candidates = int(current_native["rounds"][0]["candidates"])
    baseline_candidates = int(baseline_native["rounds"][0]["candidates"])
    if current_candidates != baseline_candidates:
        raise RuntimeError(
            f"candidate count changed: baseline={baseline_candidates}, current={current_candidates}"
        )
    if regression_percent > max_regression_percent:
        raise RuntimeError(
            f"embedded scan regressed {regression_percent:.3f}% "
            f"(allowed {max_regression_percent:.3f}%)"
        )
    return {
        "baseline_report": str(baseline_path.resolve()),
        "baseline_wall_median_ms": baseline_median,
        "current_wall_median_ms": current_median,
        "wall_regression_percent": round(regression_percent, 3),
        "max_regression_percent": max_regression_percent,
        "candidate_count": current_candidates,
        "passed": True,
    }


def main() -> None:
    args = parse_args()
    if args.generate_gib < 0:
        raise SystemExit("generate-gib must be nonnegative")
    if args.generate_plan5_mib < 0:
        raise SystemExit("generate-plan5-mib must be nonnegative")
    if args.generate_gib > 0 and args.generate_plan5_mib > 0:
        raise SystemExit("generate-gib and generate-plan5-mib are mutually exclusive")
    iocp_chunks = args.iocp_chunk_mib or [2.0]
    iocp_buffers = args.iocp_buffers or [2]
    iocp_workers = args.iocp_workers or [4]
    configs = [
        {
            "io_mode": "iocp",
            "iocp_chunk_mib": chunk,
            "iocp_buffers": buffers,
            "iocp_workers": workers,
            "cli_timeout": args.cli_timeout,
        }
        for chunk in iocp_chunks
        for buffers in iocp_buffers
        for workers in iocp_workers
    ]
    if len(configs) > 1:
        random.Random(0x5343_494F).shuffle(configs)
    if args.generate_plan5_mib > 0:
        with BenchmarkWorkspace(
            SCENARIO,
            results_root=args.results_root,
            keep_workdir=args.keep_workdir,
        ) as workspace:
            path, expected, generated_fixture = generate_plan5_mixed_carrier(
                workspace.work,
                workspace.corpus / "plan5-embedded-mixed.bin",
                args.generate_plan5_mib,
            )
            results = [run_report(path, args, config, expected) for config in configs]
            result = {
                "path": str(path.resolve()),
                "size_bytes": path.stat().st_size,
                "generated_fixture": generated_fixture,
                "window_results": results,
            }
            if args.baseline_report:
                result["regression_check"] = compare_with_baseline(
                    results[0], args.baseline_report, args.max_regression_percent
                )
            rendered = render_report(report_from_payload(SCENARIO, result))
            workspace.write_result_text("report.json", rendered)
            print(rendered)
        return
    if args.generate_gib > 0:
        with BenchmarkWorkspace(
            SCENARIO,
            results_root=args.results_root,
            keep_workdir=args.keep_workdir,
        ) as workspace:
            path = generate_stored_zip64(
                workspace.corpus / "embedded-scan-large.zip", args.generate_gib
            )
            results = [run_report(path, args, config) for config in configs]
            generated_fixture = {
                "payload_gib": args.generate_gib,
                "compression": "stored",
                "zip64": True,
            }
            result = {
                "path": str(path.resolve()),
                "size_bytes": path.stat().st_size,
                "generated_fixture": generated_fixture,
                "window_results": results,
            }
            if args.baseline_report:
                result["regression_check"] = compare_with_baseline(
                    results[0], args.baseline_report, args.max_regression_percent
                )
            rendered = render_report(report_from_payload(SCENARIO, result))
            workspace.write_result_text("report.json", rendered)
            print(rendered)
        return
    results = [run_report(args.path, args, config) for config in configs]
    if len(results) == 1:
        print(render_report(report_from_payload(SCENARIO, results[0])))
    else:
        print(render_report(report_from_payload(SCENARIO, {
            "path": str(args.path.resolve()),
            "size_bytes": args.path.stat().st_size,
            "window_results": results,
        })))


if __name__ == "__main__":
    main()
