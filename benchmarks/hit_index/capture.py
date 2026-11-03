"""Isolated native trace capture and fresh-process full-scan measurements."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time

from .build import ROOT, CACHE, NATIVE, command, environment


def instrumented_module() -> Path:
    dest = CACHE / "capture-source"
    tracked = command(["git", "ls-files", "--cached", "--others", "--exclude-standard", "native"]).splitlines()
    # Reuse the real Rust workspace, C bindings and format parsers. Never change
    # the installed extension, original sources, .venv or project dependencies.
    for name in tracked:
        source = ROOT / name
        if not source.is_file():
            continue
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    path = dest / "native/sunpack_native/src/scan/embedded.rs"
    source = path.read_text(encoding="utf-8")
    hook = "let batch = scan_sample_batch(sample, carry, base);"
    if source.count(hook) != 1:
        raise RuntimeError("Canonical matching-job hook changed; update capture explicitly")
    source = source.replace(hook, hook + '\n        benchmark_capture_batch(&batch.results, base + carry as u64, file_size, chunk_bytes).expect("benchmark hit trace write");')
    hook = "let storage = builder.finish()?;"
    if source.count(hook) != 1:
        raise RuntimeError("Canonical capture completion hook changed")
    source = source.replace(hook, hook + "\n    benchmark_capture_finish()?;")
    source += "\n" + (NATIVE / "capture.rs").read_text(encoding="utf-8")
    path.write_text(source, encoding="utf-8")
    target_dir = CACHE / "capture-target"
    command(["cargo", "build", "--offline", "--profile", "ci", "--manifest-path", dest / "native/Cargo.toml", "--target-dir", target_dir, "-p", "sunpack-native"], env=environment())
    module_root = CACHE / "capture-module"
    package = module_root / "sunpack_native"
    package.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target_dir / "ci/sunpack_native.dll", package / "sunpack_native.pyd")
    (package / "__init__.py").write_text("from .sunpack_native import *\n", encoding="utf-8")
    return module_root


def scan_child(path: Path, trace: Path | None, chunk: int, workers: int, buffers: int) -> dict:
    import psutil
    import sunpack_native
    from sunpack_native import sunpack_native as native_binary
    from sunpack_native import NativeArchiveSession, clear_reader_resources, reader_cache_stats
    process = psutil.Process()
    def memory():
        m = process.memory_info()
        return {name: int(getattr(m, name, 0)) for name in ("rss", "private", "peak_wset", "peak_pagefile")} | {"handles": process.num_handles()}
    if trace:
        os.environ["SUNPACK_BENCH_HIT_TRACE"] = str(trace)
    else:
        os.environ.pop("SUNPACK_BENCH_HIT_TRACE", None)
    before = memory()
    io_before = dict(reader_cache_stats())
    start = time.perf_counter_ns()
    cpu = time.process_time_ns()
    session = NativeArchiveSession(str(path))
    try:
        result = dict(session.scan_embedded_archives(iocp_chunk_bytes=chunk, iocp_workers=workers, iocp_buffers=buffers))
    finally:
        session.close()
    clear_reader_resources()
    elapsed = time.perf_counter_ns() - start
    cpu_elapsed = time.process_time_ns() - cpu
    # Preserve exact semantic results, excluding machine-dependent metrics.
    candidates = sorted((dict(x) for x in result["candidates"]), key=lambda x: (int(x["offset"]), str(x["format"])))
    return {"status": "ok", "native_module": native_binary.__file__,
            "native_binary_xxh128": sunpack_native.fast_hash128_file(Path(native_binary.__file__)), "bytes": path.stat().st_size,
            "scan_and_release_ns": elapsed, "cpu_ns": cpu_elapsed, "memory_before": before,
            "memory_after": memory(), "reader_before": io_before, "reader_after": dict(reader_cache_stats()),
            "complete": result["complete"], "read_bytes": result["read_bytes"],
            "hits": result["hits"], "candidates": candidates, "capture_only": trace is not None}


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--path", type=Path)
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--chunk", type=int, default=2097152)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--buffers", type=int, default=2)
    args = parser.parse_args()
    if args.build:
        print(instrumented_module())
    elif args.path:
        print(json.dumps(scan_child(args.path, args.trace, args.chunk, args.workers, args.buffers), ensure_ascii=False))
    else:
        parser.error("--path or --build required")


if __name__ == "__main__":
    main()
