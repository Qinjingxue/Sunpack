from __future__ import annotations

import asyncio
import gc
import json
import os
import shutil
import sys
import tracemalloc
import zipfile
from pathlib import Path

import psutil

from benchmarks.harness import benchmark_temp_dir, render_report, report_from_payload

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))


def mapped_memory(process: psutil.Process) -> dict[str, float]:
    totals = {"anonymous_private_mib": 0.0, "image_private_mib": 0.0, "mapped_private_mib": 0.0}
    try:
        maps = process.memory_maps(grouped=False)
    except (psutil.AccessDenied, NotImplementedError):
        return totals
    for item in maps:
        private = float(getattr(item, "private", 0) or 0) / 1024 / 1024
        path = str(getattr(item, "path", "") or "")
        if not path or path.startswith("["):
            totals["anonymous_private_mib"] += private
        elif path.lower().endswith((".dll", ".pyd", ".exe")):
            totals["image_private_mib"] += private
        else:
            totals["mapped_private_mib"] += private
    return {key: round(value, 2) for key, value in totals.items()}


def sample(label: str) -> dict:
    gc.collect()
    process = psutil.Process()
    info = process.memory_info()
    traced, peak = tracemalloc.get_traced_memory()
    row = {
        "label": label,
        "rss_mib": round(info.rss / 1024 / 1024, 2),
        "private_mib": round(getattr(info, "private", 0) / 1024 / 1024, 2),
        "python_traced_mib": round(traced / 1024 / 1024, 2),
        "python_peak_mib": round(peak / 1024 / 1024, 2),
        "threads": process.num_threads(),
        "handles": process.num_handles(),
    }
    try:
        from sunpack_native import reader_cache_stats
        reader = dict(reader_cache_stats())
        row.update({
            "reader_open_handles": int(reader.get("open_handles", 0)),
            "reader_cache_entries": int(reader.get("cache_entries", 0)),
            "reader_cache_mib": round(
                (int(reader.get("hot_cache_bytes", 0)) + int(reader.get("general_cache_bytes", 0))) / 1024 / 1024,
                2,
            ),
        })
    except (ImportError, AttributeError):
        pass
    row.update(mapped_memory(process))
    return row


def main() -> int:
    tracemalloc.start(10)
    from sunpack.runtime.cli.cli import async_main
    from sunpack.runtime.cli import persistent_runtime

    root = benchmark_temp_dir("sunpack-residual-rss-")
    rows = []
    persistent_runtime.enable_persistent_runtime()
    try:
        rows.append(sample("baseline"))

        async def run_batches() -> None:
            # The persistent server owns exactly one event loop for its whole
            # lifetime, and PipelineEngine rejects requests from a different
            # loop, so every batch must run inside this single loop via the
            # async CLI entry point instead of a fresh asyncio.run per batch.
            for batch in range(1, 5):
                input_dir = root / f"input-{batch}"
                output_dir = root / f"output-{batch}"
                input_dir.mkdir()
                paths = []
                for index in range(50):
                    archive_path = input_dir / f"archive-{batch}-{index:04d}.zip"
                    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
                        archive.writestr("payload.bin", os.urandom(128 * 1024))
                    paths.append(str(archive_path))
                code = await async_main([
                    "extract", *paths, "--direct-file", "--out-dir", str(output_dir),
                    "--cleanup", "k", "--no-flatten", "--no-pause", "--quiet",
                ])
                if code:
                    raise RuntimeError(f"batch {batch} failed: {code}")
                rows.append(sample(f"batch-{batch}"))
            # close_persistent_runtime is async; awaiting it here (on the
            # server's own loop) actually shuts the engine down.
            await persistent_runtime.close_persistent_runtime()
            rows.append(sample("after-engine-close"))

        asyncio.run(run_batches())
        from sunpack_native import release_reader_handles_under
        release_reader_handles_under(str(root))
        rows.append(sample("after-reader-handle-release"))
        print(render_report(report_from_payload("memory.residual-rss", rows)))
    finally:
        try:
            asyncio.run(persistent_runtime.close_persistent_runtime())
        except Exception:
            pass
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
