"""Full CLI extraction matrix with coarse internal phase timings.

This scenario deliberately uses the fixed 300 MiB ``few_large`` corpus and
the same non-direct-file CLI command as ``extraction.format-matrix``.  The
command is dispatched through :func:`sunpack.runtime.cli.cli.async_main`, so parsing,
configuration, planning, extraction, output handling, and CLI reporting are
all included in the measured wall time.  ``RequestRuntimeProfiler`` adds the
coarse internal phase breakdown to each measured request.

The native worker is selected explicitly so a benchmark result cannot
silently use a stale worker from ``build-x64`` after a source rollback.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import os
import shutil
import statistics
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import (
    BenchmarkWorkspace,
    render_report,
    report_from_payload,
)
from benchmarks.scenarios.extraction_large_archive import (
    RequestRuntimeProfiler,
    _derived_timing,
    _timing_totals,
)


SCENARIO = "extraction.cli-format-matrix"
CORPUS_ROOT = ROOT / "benchmarks" / ".cache" / "extraction-format-matrix-300mb" / "inputs"
PAYLOAD_BYTES = 2 * 150 * 1024 * 1024
FORMATS = (
    "zip",
    "7z",
    "7z-split",
    "rar",
    "rar-split",
    "tar",
    "gz",
    "bz2",
    "xz",
    "zst",
    "tgz",
    "tbz2",
    "txz",
    "tzst",
)

DEFAULT_WORKER = (
    ROOT
    / "native"
    / "sevenzip_bridge"
    / "build-cli-coarse"
    / "Release"
    / "sunpack_sevenzip_worker.exe"
)


def _archive_for(format_name: str) -> Path:
    case_root = CORPUS_ROOT / f"few_large-{format_name}"
    if not case_root.is_dir():
        raise FileNotFoundError(f"fixed 300 MiB corpus case is missing: {case_root}")
    candidates = sorted(path for path in case_root.iterdir() if path.is_file())
    if format_name == "7z-split":
        candidates = [path for path in candidates if path.name.endswith(".001")]
    elif format_name == "rar-split":
        candidates = [path for path in candidates if path.name.endswith(".part01.rar")]
    if len(candidates) != 1:
        raise RuntimeError(
            f"expected one CLI input for {format_name}, found {len(candidates)} in {case_root}"
        )
    return candidates[0]


def _validate_corpus(selected_formats: tuple[str, ...]) -> dict[str, Path]:
    archives = {format_name: _archive_for(format_name) for format_name in selected_formats}
    for format_name, archive in archives.items():
        if archive.stat().st_size <= 0:
            raise RuntimeError(f"archive is empty: {archive}")
    return archives


def _patch_worker_path(worker_path: Path):
    """Force the runner and resource helper to use the freshly built worker."""
    import sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner as runner_module
    import sunpack.core.support.resources as resources_module

    original_runner = runner_module.get_sevenzip_bridge_worker_path
    original_resources = resources_module.get_sevenzip_bridge_worker_path
    runner_module.get_sevenzip_bridge_worker_path = lambda: str(worker_path)
    resources_module.get_sevenzip_bridge_worker_path = lambda: str(worker_path)

    def restore() -> None:
        runner_module.get_sevenzip_bridge_worker_path = original_runner
        resources_module.get_sevenzip_bridge_worker_path = original_resources

    return restore


def _median_by_label(rows: list[dict[str, Any]], field: str) -> dict[str, float]:
    labels = sorted({label for row in rows for label in row.get(field, {})})
    return {
        label: round(
            statistics.median(float(row.get(field, {}).get(label, 0.0)) for row in rows),
            6,
        )
        for label in labels
    }


def _format_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [row for row in rows if row.get("passed")]
    return {
        "runs": len(rows),
        "successful_runs": len(successful),
        "median_cli_elapsed_seconds": (
            round(statistics.median(row["cli_elapsed_seconds"] for row in successful), 6)
            if successful
            else None
        ),
        "median_timing_seconds": _median_by_label(successful, "timing_seconds") if successful else {},
        "median_derived_timing_seconds": (
            _median_by_label(successful, "derived_timing_seconds") if successful else {}
        ),
        "output_shapes": sorted(
            {
                (row["output"]["file_count"], row["output"]["total_bytes"])
                for row in successful
            }
        ),
    }


def _output_summary(root: Path) -> dict[str, int]:
    file_count = 0
    total_bytes = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            file_count += 1
            total_bytes += path.stat().st_size
        except OSError:
            pass
    return {"file_count": file_count, "total_bytes": total_bytes}


async def _run_cli_once(
    archive: Path,
    output: Path,
    profiler: RequestRuntimeProfiler,
    timeout_seconds: float,
) -> dict[str, Any]:
    from sunpack.runtime.cli.cli import async_main

    argv = [
        "extract",
        "--recur",
        "*",
        "--cleanup",
        "k",
        "--no-flatten",
        "--no-builtin-pw",
        "--no-dir-pw",
        "--quiet",
        "--no-pause",
        "-o",
        str(output),
        str(archive),
    ]
    stdout = io.StringIO()
    stderr = io.StringIO()
    before = len(profiler.request_timings)
    started = time.perf_counter()
    error: str | None = None
    exit_code = -1
    try:
        exit_code = int(
            await asyncio.wait_for(
                async_main(argv, cwd=str(ROOT), stdout=stdout, stderr=stderr),
                timeout=timeout_seconds,
            )
        )
    except Exception as exc:  # Keep the matrix going so other formats remain useful.
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.perf_counter() - started

    if len(profiler.request_timings) <= before:
        timing_seconds: dict[str, float] = {}
        derived_timing_seconds: dict[str, float] = {}
        timing_calls: dict[str, int] = {}
    else:
        timings = profiler.request_timings[-1]
        timing_seconds = _timing_totals(timings)
        derived_timing_seconds = _derived_timing(timings)
        timing_calls = {label: len(values) for label, values in sorted(timings.items())}
    if error is None and exit_code != 0:
        error = (stderr.getvalue() or stdout.getvalue()).strip()[-2000:] or f"CLI exit code {exit_code}"
    return {
        "cli_elapsed_seconds": round(elapsed, 6),
        "exit_code": exit_code,
        "passed": error is None and exit_code == 0,
        "error": error,
        "output": _output_summary(output),
        "timing_seconds": timing_seconds,
        "derived_timing_seconds": derived_timing_seconds,
        "timing_calls": timing_calls,
    }


async def _run(args: argparse.Namespace) -> int:
    selected_formats = tuple(args.formats or FORMATS)
    archives = _validate_corpus(selected_formats)
    worker_path = args.worker_path.resolve()
    if not worker_path.is_file():
        raise FileNotFoundError(f"rebuilt worker does not exist: {worker_path}")
    if args.runs < 1 or args.warmups < 0:
        raise ValueError("--runs must be positive and --warmups cannot be negative")
    if args.timeout <= 0:
        raise ValueError("--timeout must be positive")

    all_rows: list[dict[str, Any]] = []
    warmup_rows: list[dict[str, Any]] = []
    profiler: RequestRuntimeProfiler | None = None
    restore_worker = _patch_worker_path(worker_path)
    from sunpack.runtime.cli import persistent_runtime

    try:
        persistent_runtime.enable_persistent_runtime()
        with BenchmarkWorkspace(
            SCENARIO,
            results_root=args.results_root,
            keep_workdir=args.keep_workdir,
        ) as workspace:
            for index, (format_name, archive) in enumerate(archives.items(), 1):
                print(
                    f"cli-format-matrix: {index}/{len(archives)} {format_name} "
                    f"({archive.stat().st_size} bytes)",
                    file=sys.stderr,
                    flush=True,
                )
                for warmup in range(args.warmups):
                    output = workspace.outputs / f"{format_name}-warmup-{warmup}"
                    shutil.rmtree(output, ignore_errors=True)
                    output.mkdir(parents=True, exist_ok=True)
                    try:
                        if profiler is None:
                            # The first warmup creates the persistent engine.
                            from sunpack.runtime.cli.cli import async_main

                            started = time.perf_counter()
                            stdout = io.StringIO()
                            stderr = io.StringIO()
                            code = int(
                                await asyncio.wait_for(
                                    async_main(
                                        [
                                            "extract",
                                            "--recur",
                                            "*",
                                            "--cleanup",
                                            "k",
                                            "--no-flatten",
                                            "--no-builtin-pw",
                                            "--no-dir-pw",
                                            "--quiet",
                                            "--no-pause",
                                            "-o",
                                            str(output),
                                            str(archive),
                                        ],
                                        cwd=str(ROOT),
                                        stdout=stdout,
                                        stderr=stderr,
                                    ),
                                    timeout=args.timeout,
                                )
                            )
                            warmup_rows.append(
                                {
                                    "format": format_name,
                                    "run": warmup + 1,
                                    "elapsed_seconds": round(time.perf_counter() - started, 6),
                                    "exit_code": code,
                                    "passed": code == 0,
                                    "error": (
                                        (stderr.getvalue() or stdout.getvalue()).strip()[-2000:]
                                        if code != 0
                                        else None
                                    ),
                                    "output": _output_summary(output),
                                }
                            )
                            engine = persistent_runtime.current_pipeline_engine()
                            if engine is None:
                                raise RuntimeError("CLI warmup did not create a persistent PipelineEngine")
                            profiler = RequestRuntimeProfiler()
                            profiler.install(engine)
                            profiler.enabled = True
                        else:
                            warmup_result = await _run_cli_once(
                                archive,
                                output,
                                profiler,
                                args.timeout,
                            )
                            warmup_rows.append(
                                {
                                    "format": format_name,
                                    "run": warmup + 1,
                                    "elapsed_seconds": warmup_result["cli_elapsed_seconds"],
                                    "exit_code": warmup_result["exit_code"],
                                    "passed": warmup_result["passed"],
                                    "error": warmup_result["error"],
                                    "output": warmup_result["output"],
                                }
                            )
                    finally:
                        shutil.rmtree(output, ignore_errors=True)

                if profiler is None:
                    raise RuntimeError("persistent CLI profiler was not installed")
                for run in range(1, args.runs + 1):
                    output = workspace.outputs / f"{format_name}-run-{run}"
                    shutil.rmtree(output, ignore_errors=True)
                    output.mkdir(parents=True, exist_ok=True)
                    try:
                        row = await _run_cli_once(archive, output, profiler, args.timeout)
                        row.update(
                            {
                                "format": format_name,
                                "run": run,
                                "archive": str(archive),
                                "archive_bytes": archive.stat().st_size,
                                "payload_bytes": PAYLOAD_BYTES,
                            }
                        )
                        all_rows.append(row)
                        print(
                            f"  run {run}/{args.runs}: {row['cli_elapsed_seconds']:.3f}s "
                            f"exit={row['exit_code']}",
                            file=sys.stderr,
                            flush=True,
                        )
                    finally:
                        shutil.rmtree(output, ignore_errors=True)

            per_format = {
                format_name: _format_summary(
                    [row for row in all_rows if row["format"] == format_name]
                )
                for format_name in selected_formats
            }
            successful = [row for row in all_rows if row.get("passed")]
            report = {
                "schema_version": 1,
                "parameters": {
                    "corpus_root": str(CORPUS_ROOT),
                    "payload_bytes": PAYLOAD_BYTES,
                    "formats": list(selected_formats),
                    "runs": args.runs,
                    "warmups": args.warmups,
                    "timeout_seconds": args.timeout,
                    "worker_path": str(worker_path),
                    "cli_mode": "in-process async_main, persistent runtime",
                },
                "environment": {
                    "revision": _git_revision(),
                    "python": sys.version,
                    "platform": sys.platform,
                    "cpu_count": os.cpu_count(),
                },
                "warmups": warmup_rows,
                "results": all_rows,
                "summary": {
                    "all_passed": len(successful) == len(all_rows) == len(selected_formats) * args.runs,
                    "successful_runs": len(successful),
                    "total_runs": len(all_rows),
                    "median_cli_elapsed_seconds": (
                        round(statistics.median(row["cli_elapsed_seconds"] for row in successful), 6)
                        if successful
                        else None
                    ),
                    "per_format": per_format,
                    "coarse_hotspots_median_seconds": _median_by_label(successful, "timing_seconds")
                    if successful
                    else {},
                    "coarse_derived_hotspots_median_seconds": _median_by_label(
                        successful, "derived_timing_seconds"
                    )
                    if successful
                    else {},
                },
            }
            rendered = render_report(report_from_payload(SCENARIO, report))
            workspace.write_result_text("report.json", rendered)
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(rendered, encoding="utf-8")
            print(rendered)
            return 0 if report["summary"]["all_passed"] else 1
    finally:
        if profiler is not None:
            profiler.enabled = False
            profiler.restore()
        with contextlib.suppress(Exception):
            await persistent_runtime.close_persistent_runtime()
        restore_worker()


def _git_revision() -> str | None:
    try:
        import subprocess

        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--format", action="append", dest="formats", choices=FORMATS)
    parser.add_argument("--worker-path", type=Path, default=DEFAULT_WORKER)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    try:
        return asyncio.run(_run(args))
    except Exception as exc:
        print(f"cli-format-matrix failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
