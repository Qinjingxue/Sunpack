from __future__ import annotations

"""End-to-end watch benchmark for the fixed 300 MiB CLI corpus formats."""

import argparse
import asyncio
import statistics
from pathlib import Path
from typing import Any

from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from benchmarks.scenarios.extraction_cli_format_matrix import (
    CORPUS_ROOT,
    DEFAULT_LZ4_TOOL,
    ENC_FIXTURE_PASSWORD,
    PAYLOAD_BYTES,
    _archive_for,
    _ensure_enc_archive,
    _ensure_special_archives,
)
from benchmarks.scenarios.watch_real_file import _run_once
from benchmarks.watch_broker import watch_broker_lease


SCENARIO = "watch.cli-format-matrix"
WATCH_FORMATS = ("zipx", "lz4", "enc")


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    passed = [row for row in rows if row["passed"]]
    return {
        "runs": len(rows),
        "successful_runs": len(passed),
        "median_end_to_end_seconds": (
            statistics.median(
                row["timings_seconds"]["end_to_end_copy_start_to_completion"] for row in passed
            )
            if passed
            else None
        ),
        "median_pipeline_seconds": (
            statistics.median(row["timings_seconds"]["pipeline_run"] for row in passed)
            if passed
            else None
        ),
        "median_copy_seconds": (
            statistics.median(row["timings_seconds"]["copy"] for row in passed)
            if passed
            else None
        ),
        "outputs_match_300_mib": all(
            row["output"]["total_bytes"] == PAYLOAD_BYTES for row in rows
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Watch-mode end-to-end matrix for ZIPX, LZ4 and ENC 300 MiB inputs."
    )
    parser.add_argument(
        "--format",
        action="append",
        choices=WATCH_FORMATS,
        dest="formats",
        help="format to measure; may be repeated (default: all three)",
    )
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--quiet-seconds", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--lz4-tool", type=Path, default=DEFAULT_LZ4_TOOL)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    formats = tuple(dict.fromkeys(args.formats or WATCH_FORMATS))
    if args.runs < 1:
        parser.error("--runs must be positive")
    if args.quiet_seconds < 0 or args.timeout <= 0:
        parser.error("--quiet-seconds must be nonnegative and --timeout must be positive")

    if {"zipx", "lz4"}.intersection(formats):
        _ensure_special_archives(args.lz4_tool.resolve(), args.timeout)
    if "enc" in formats:
        _ensure_enc_archive(args.timeout)
    sources = {format_name: _archive_for(format_name).resolve() for format_name in formats}
    for source in sources.values():
        if not source.is_file() or source.stat().st_size <= 0:
            parser.error(f"300 MiB corpus input is missing or empty: {source}")

    samples: list[dict[str, Any]] = []
    with watch_broker_lease() as broker_metadata, BenchmarkWorkspace(
        SCENARIO,
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        for format_name, source in sources.items():
            passwords = [ENC_FIXTURE_PASSWORD] if format_name == "enc" else []
            for run in range(1, args.runs + 1):
                case_key = f"{format_name}-run-{run:03d}"
                row = asyncio.run(
                    _run_once(
                        source,
                        workspace,
                        passwords=passwords,
                        cold_start_seconds=args.quiet_seconds,
                        timeout=args.timeout,
                        case_key=case_key,
                    )
                )
                row.update(
                    {
                        "format": format_name,
                        "run": run,
                        "payload_bytes": PAYLOAD_BYTES,
                        "passed": bool(
                            row["completed"] and row["output"]["total_bytes"] == PAYLOAD_BYTES
                        ),
                    }
                )
                samples.append(row)
                print(
                    f"watch-cli-format-matrix: {format_name} {run}/{args.runs} "
                    f"{row['timings_seconds']['end_to_end_copy_start_to_completion']:.3f}s "
                    f"passed={row['passed']}",
                    flush=True,
                )

        per_format = {
            format_name: _summary([row for row in samples if row["format"] == format_name])
            for format_name in formats
        }
        report = {
            "watch_broker": broker_metadata,
            "parameters": {
                "corpus_root": str(CORPUS_ROOT),
                "formats": list(formats),
                "payload_bytes": PAYLOAD_BYTES,
                "runs": args.runs,
                "quiet_seconds": args.quiet_seconds,
                "timeout_seconds": args.timeout,
                "enc_password_candidate_count": 1 if "enc" in formats else 0,
                "output_root_mode": "isolated_watch_root_per_format_and_run",
            },
            "samples": samples,
            "summary": {
                "all_passed": len(samples) == len(formats) * args.runs
                and all(row["passed"] for row in samples),
                "successful_runs": sum(bool(row["passed"]) for row in samples),
                "total_runs": len(samples),
                "per_format": per_format,
            },
        }
        rendered = render_report(report_from_payload(SCENARIO, report))
        workspace.write_result_text("report.json", rendered)
        print(rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
    return 0 if report["summary"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
