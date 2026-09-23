"""Measure the current Rust-owned compact worker-row pipeline."""
from __future__ import annotations

import argparse
import gc
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import psutil

from benchmarks.harness import render_report, report_from_payload


def compact_rows(count: int) -> list[list[object]]:
    return [
        [
            index,
            f"tree/{index // 1000:04d}/source-{index:07d}.bin",
            f"tree/{index // 1000:04d}/decoded-{index:07d}.bin",
            index + 1,
            index + 1,
            1,
            index & 0xFFFFFFFF,
            1,
            index & 0xFFFFFFFF,
            1,
            1,
            1,
            index + 1,
            "00",
        ]
        for index in range(count)
    ]


def run_native(count: int) -> dict[str, object]:
    from sunpack.pipeline.extraction.internal.sevenzip.worker_diagnostics import (
        build_worker_diagnostics,
        compact_success_worker_diagnostics,
    )
    from sunpack.pipeline.extraction.output_inventory import collect_output_inventory

    process = psutil.Process()
    initial_rss = process.memory_info().rss
    payload = {
        "type": "result",
        "status": "ok",
        "verified_manifest": {
            "version": 3,
            "validated": True,
            "file_count": count,
            "inventory": [1, count, max(1, count // 1000), count * (count + 1) // 2, 0],
            "rows": compact_rows(count),
        },
    }
    rows_rss = process.memory_info().rss
    started = time.perf_counter()
    diagnostics = build_worker_diagnostics(
        stdout="", stderr="", returncode=0, result_payload=payload
    )
    parsed_rss = process.memory_info().rss
    inventory = collect_output_inventory("C:/benchmark-output", payload)
    inventory_rss = process.memory_info().rss
    compact_success_worker_diagnostics(diagnostics)
    gc.collect()
    elapsed = time.perf_counter() - started
    steady_rss = process.memory_info().rss

    assert inventory.stats.file_count == count
    assert "rows" not in payload["verified_manifest"]
    assert "files" not in payload["verified_manifest"]
    assert "native_rows" not in payload["verified_manifest"]
    peak_rss = max(rows_rss, parsed_rss, inventory_rss, steady_rss)
    return {
        "records": count,
        "pipeline_seconds": elapsed,
        "initial_rss_mib": initial_rss / 1024**2,
        "rows_rss_mib": rows_rss / 1024**2,
        "parsed_rss_mib": parsed_rss / 1024**2,
        "inventory_rss_mib": inventory_rss / 1024**2,
        "steady_rss_mib": steady_rss / 1024**2,
        "peak_increment_from_rows_mib": (peak_rss - rows_rss) / 1024**2,
        "peak_increment_from_initial_mib": (peak_rss - initial_rss) / 1024**2,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=100_000)
    parser.add_argument("--timeout", type=float, default=300.0, help="Child-process wall-clock timeout.")
    parser.add_argument("--child", action="store_true")
    args = parser.parse_args()
    count = max(1, args.records)
    if args.child:
        print(json.dumps(run_native(count)))
        return 0

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--records",
            str(count),
            "--child",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=max(1.0, args.timeout),
    )
    print(render_report(report_from_payload("memory.worker-manifest", json.loads(completed.stdout))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
