"""Measure the unchanged production embedded scan in a copied release build.

Runs bounded 16-way fresh-process reference/coarse/fine groups by default. Native
diagnostics run after the pipeline timer, so only the reference child supplies
end-to-end latency and process memory. No experimental codec is involved.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import statistics
import sys
import time

from .build import CACHE, NATIVE, ROOT, command, environment
from .capture import instrumented_module
from .corpus import invoke_json
from .parallel import DEFAULT_PARALLEL_JOBS, run_jobs
from .profile_hooks import instrument


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "benchmarks/results/scan.hit-index/20261103T152105Z-2f736653/corpus.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--reference-identity", type=Path, required=True,
                        help="Frozen release selection.json containing native source and binary identities")
    parser.add_argument("--blocks", type=int, default=12)
    parser.add_argument("--lifecycle-cycles", type=int, default=16)
    parser.add_argument("--parallel-jobs", type=int, default=DEFAULT_PARALLEL_JOBS)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    if args.blocks < 1:
        parser.error("--blocks must be positive")
    if args.lifecycle_cycles < 1:
        parser.error("--lifecycle-cycles must be positive")
    from sunpack_native import fast_hash128_file

    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    identity = json.loads(args.reference_identity.read_text(encoding="utf-8"))
    for name, expected in identity["source_xxh128"].items():
        if fast_hash128_file(ROOT / name) != expected:
            raise RuntimeError(f"Reference production source changed: {name}; rebuild the reference first")
    binary = args.reference / "sunpack_native/sunpack_native.pyd"
    if fast_hash128_file(binary) != identity["reference_binary_xxh128"]:
        raise RuntimeError("Reference release binary identity changed")
    profile_root = out / "instrumented/module"
    if not args.skip_build:
        profile_root = instrumented_module(destination=out / "instrumented", transform=instrument,
            profile="release", target_dir=CACHE / "production-profile-target")
    fixtures = out / "fixtures"
    generator = out / "profile_fixture.exe"
    command(["rustc", "--edition=2021", "-O", NATIVE / "profile_fixture.rs", "-o", generator], env=environment())
    command([generator, fixtures])
    cases = json.loads(args.manifest.read_text(encoding="utf-8"))["real_inputs"]
    for name in ["zero-64m", "noise-64m", "false-zip-arithmetic", "false-zip-irregular"]:
        path = fixtures / f"{name}.opaque"
        row = {"name": name, "input": str(path), "bytes": path.stat().st_size,
               "input_xxh128": fast_hash128_file(path), "recipe": "profile_fixture.rs seed 1729"}
        if name.startswith("false-zip"):
            row["semantic_reference"] = {"raw_hit_count": 131072, "hits": [], "candidates": []}
        elif name == "zero-64m":
            row["semantic_reference"] = {"raw_hit_count": 0, "hits": [], "candidates": []}
        cases.append(row)
    for case in cases:
        if fast_hash128_file(Path(case["input"])) != case["input_xxh128"]:
            raise RuntimeError(f"Frozen input changed: {case['name']}")
    instrumentation_files = [Path(__file__), Path(__file__).with_name("profile_hooks.py"),
                             Path(__file__).with_name("capture.py"),
                             NATIVE / "scan_profile.rs", NATIVE / "storage_profile.rs", NATIVE / "profile_fixture.rs"]
    metadata = {"head": command(["git", "rev-parse", "HEAD"]).strip(),
        "instrumentation_xxh128": {str(p.relative_to(ROOT)): fast_hash128_file(p) for p in instrumentation_files},
        "source_xxh128": identity["source_xxh128"], "reference_binary_xxh128": fast_hash128_file(binary),
        "profile_binary_xxh128": fast_hash128_file(profile_root / "sunpack_native/sunpack_native.pyd"),
        "rustc": command(["rustc", "--version"]).strip(), "profile": "release",
        "parallel_jobs": args.parallel_jobs, "blocks": args.blocks, "lifecycle_cycles": args.lifecycle_cycles, "cases": cases,
        "chunk": 2097152, "buffers": 2, "workers": 4,
        "timing_context": "shared-host" if args.parallel_jobs > 1 else "isolated",
        "scope": "embedded scan only; warm Windows cache; controlled real-format fixtures and diagnostic inputs"}
    (out / "selection.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    profiles = out / "native-profiles"
    profiles.mkdir(exist_ok=True)

    def group(job):
        block, case = job
        results = []
        versions = [("reference", args.reference), ("profile", profile_root), ("fine", profile_root)]
        rotation = block % len(versions)
        versions = versions[rotation:] + versions[:rotation]
        for version, module in versions:
            env = environment().copy()
            env["PYTHONPATH"] = os.pathsep.join([str(module), str(ROOT)])
            env.pop("SUNPACK_BENCH_PROFILE", None)
            env.pop("SUNPACK_BENCH_PROFILE_FINE", None)
            path = profiles / f"{case['name']}-{version}-{block}.json"
            if version != "reference":
                env["SUNPACK_BENCH_PROFILE"] = str(path)
            if version == "fine":
                env["SUNPACK_BENCH_PROFILE_FINE"] = "1"
            result = invoke_json([sys.executable, "-m", "benchmarks.hit_index.capture", "--path", case["input"]], env=env)
            if result.get("status") != "ok" or not result.get("complete") or result["read_bytes"] != case["bytes"]:
                failure = {"case": case["name"], "block": block, "version": version,
                           "parallel_jobs": args.parallel_jobs, "result": result}
                (out / f"failure-{case['name']}-{version}-{block}.json").write_text(
                    json.dumps(failure, indent=2, ensure_ascii=False), encoding="utf-8")
                raise RuntimeError(f"Incomplete production scan {case['name']}: {result}")
            expected = case.get("semantic_reference")
            if expected and any(result[k] != value for k, value in expected.items()):
                raise RuntimeError(f"Frozen semantic reference differs: {case['name']} {version}")
            result.update(case=case["name"], block=block, version=version)
            if version != "reference":
                result["profile"] = json.loads(path.read_text(encoding="utf-8"))
                if result["profile"]["fine"] != (version == "fine"):
                    raise RuntimeError("Stale instrumentation module: rebuild it")
            results.append(result)
        if any(results[0][k] != other[k] for other in results[1:] for k in ("hits", "raw_hit_count", "candidates", "read_bytes", "complete")):
            raise RuntimeError(f"Profiling changed scan semantics: {case['name']}")
        return results

    rows = []
    start = time.perf_counter()
    with (out / "rows.jsonl").open("w", encoding="utf-8") as stream:
        for result in run_jobs(group, ((b,c) for b in range(args.blocks) for c in cases), parallel_jobs=args.parallel_jobs):
            rows.extend(result)
            for row in result:
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
            stream.flush()
            if len(rows) % 48 == 0:
                print(f"measured {len(rows)}/{len(cases)*args.blocks*3} scans", flush=True)
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["case"], row["version"]].append(row)
    summary = []
    for case in cases:
        ref = grouped[case["name"], "reference"]
        prof = grouped[case["name"], "profile"]
        fine = grouped[case["name"], "fine"]
        med = lambda values: statistics.median(values)
        by_size = sorted(prof, key=lambda row: row["profile"]["storage"]["bytes"])
        storage = by_size[len(by_size) // 2]["profile"]["storage"]
        # Physical append order may change trailing alignment and compression
        # of the serialized witness. Semantic tuples and codec costs stay fixed.
        stable = ["hits", "type_counts", "top_directory_bytes", "leaf_directory_bytes", "position_bytes", "type_bytes", "mixed_tuple_bytes", "codec_hits", "staging_descriptor_bytes", "staging_boundary_bytes"]
        if any(any(row["profile"]["storage"][k] != storage[k] for k in stable) for row in prof):
            raise RuntimeError(f"Nondeterministic production storage shape: {case['name']}")
        summary.append({"case": case["name"], "input_bytes": case["bytes"], "raw_hits": ref[0]["raw_hit_count"],
            "reference_wall_ns": med(x["scan_and_release_ns"] for x in ref),
            "reference_cpu_ns": med(x["cpu_ns"] for x in ref),
            "reference_peak_private_delta": med(max(0,x["memory_after"]["peak_pagefile"] - x["memory_before"]["peak_pagefile"]) for x in ref),
            "reference_retained_private_delta": med(x["memory_after"]["private"] - x["memory_before"]["private"] for x in ref),
            "profile_pipeline_ns": med(x["profile"]["pipeline_ns"] for x in prof),
            "fine_pipeline_ns": med(x["profile"]["pipeline_ns"] for x in fine),
            "io_match_wall_ns": med(x["profile"]["io_match_wall_ns"] for x in prof),
            "stages": {name: {"ns": med(x["profile"]["stages"][name]["ns"] for x in prof),
                              "calls": med(x["profile"]["stages"][name]["calls"] for x in prof)} for name in prof[0]["profile"]["stages"]},
            "fine_stages": {name: {"ns": med(x["profile"]["stages"][name]["ns"] for x in fine),
                                   "calls": med(x["profile"]["stages"][name]["calls"] for x in fine)} for name in fine[0]["profile"]["stages"]},
            "storage": storage, "retained": prof[0]["profile"]["retained"],
            "storage_ranges": {key: [min(row["profile"]["storage"][key] for row in prof),
                                      max(row["profile"]["storage"][key] for row in prof)]
                               for key in ("bytes", "alignment_bytes", "heap_capacity_bytes", "zstd3_with_lengths_bytes")},
            "reader_scan": ref[0]["reader_scan"], "reader_after": ref[0]["reader_after"]})
    def lifecycle(case):
        env = environment().copy()
        env["PYTHONPATH"] = os.pathsep.join([str(args.reference), str(ROOT)])
        env.pop("SUNPACK_BENCH_PROFILE", None)
        result = invoke_json([sys.executable, "-m", "benchmarks.hit_index.capture", "--path", case["input"],
                              "--cycles", args.lifecycle_cycles], env=env)
        if args.lifecycle_cycles == 1:
            semantic = {k: result[k] for k in ("hits", "raw_hit_count", "candidates", "read_bytes", "complete") if k in result}
            result = {"status": result.get("status"), "semantic_reference": semantic, "cycles": [result]}
        reference = grouped[case["name"], "reference"][0]
        if (result.get("status") != "ok" or len(result.get("cycles", [])) != args.lifecycle_cycles
                or any(result.get("semantic_reference", {}).get(k) != reference[k]
                       for k in ("hits", "raw_hit_count", "candidates", "read_bytes", "complete"))):
            raise RuntimeError(f"Lifecycle scan differs: {case['name']}: {result}")
        return {"case": case["name"], **result}
    lifecycle_cases = [c for c in cases if c["name"] in {"zip-many-32768", "zip-variable-32768", "mixed-carrier-128", "false-zip-irregular", "zero-64m"}]
    lifetime = list(run_jobs(lifecycle, lifecycle_cases, parallel_jobs=args.parallel_jobs))
    (out / "lifecycle.json").write_text(json.dumps(lifetime, indent=2, ensure_ascii=False), encoding="utf-8")
    report = {"execution_seconds": time.perf_counter() - start, "scans": len(rows),
              "lifecycle_scans": len(lifetime) * args.lifecycle_cycles,
              "all_semantics_equal": True, "selection": str(out / "selection.json"), "summary": summary}
    (out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k:v for k,v in report.items() if k != "summary"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
