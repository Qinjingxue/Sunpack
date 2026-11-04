"""Pinned typed-hit index baselines, conformance, corpus and lifecycle evaluation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import shutil
import sys
import time

from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from benchmarks.hit_index import analysis
from benchmarks.hit_index.build import ROOT, CACHE, backends, bridge, command, environment
from benchmarks.hit_index.cases import Case, PROTOCOL, configurations, schedule, synthetic
from benchmarks.hit_index.corpus import invoke_json, public_cases, real_cases, full_scan_cases
from benchmarks.hit_index.parallel import DEFAULT_PARALLEL_JOBS, run_jobs

SCENARIO = "scan.hit-index"


def options():
    p = argparse.ArgumentParser(__doc__)
    p.add_argument("--suite", choices=["quick", "conformance", "evaluation"], default="quick")
    p.add_argument("--fetch", action="store_true", help="Retrieve only pinned upstream source/data checkouts")
    p.add_argument("--algorithms", nargs="+", choices=PROTOCOL["algorithms"])
    p.add_argument("--blocks", type=int)
    p.add_argument("--samples", type=int)
    p.add_argument("--target-ms", type=int)
    p.add_argument("--parallel-jobs", "--jobs", type=int, default=DEFAULT_PARALLEL_JOBS,
                   help="Concurrent native benchmark processes (default: 16; use 1 for isolated latency)")
    p.add_argument("--public", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--real", action="store_true", help="Generate real fixtures and capture canonical post-filter hit traces")
    p.add_argument("--full-scan", action="store_true", help="Run existing native scan/release on the frozen real inputs")
    p.add_argument("--candidate-module-root", type=Path, help="Frozen sunpack_native package root for full-scan A/B")
    p.add_argument("--reference-module-root", type=Path, help="Frozen reference extension built with the same profile as the candidate")
    p.add_argument("--candidate-bridge", type=Path, help="Separately built private Rust probe DLL for index/Builder A/B")
    p.add_argument("--reference-bridge", type=Path, help="Frozen reference probe; default is built from the working tree")
    p.add_argument("--conformance-report", type=Path, help="Prior conformance report for the same frozen candidate/source")
    p.add_argument("--corpus-manifest", type=Path, help="Reuse frozen real traces/inputs instead of recapturing")
    p.add_argument("--case", action="append", help="Include names containing this text; repeated values form a union")
    p.add_argument("--shard-count", type=int, default=1)
    p.add_argument("--shard-index", type=int, default=0)
    p.add_argument("--results-root", type=Path)
    p.add_argument("--keep-workdir", action="store_true")
    p.add_argument("--strict", action="store_true", help="Fail on candidate correctness/coverage failures; upstream failures remain disclosed")
    return p.parse_args()


def native_call(exe: Path, case: Case, config: dict, dll: Path, *, mode: str, params: dict, block: int) -> dict:
    args = [exe, *case.argv(), "--algorithm", config["algorithm"], "--block", config["block"],
            "--bridge", dll, "--mode", mode, "--queries", params["queries"], "--samples", params["inner_samples"],
            "--warmups", params["warmups"], "--target-ms", params["target_ms"], "--op-rotation", block]
    row = invoke_json(args)
    row.update(case=case.name, family=case.family, configuration=config["name"], block=block)
    return row


def builder_cases() -> list[Case]:
    return [Case("builder-dense", "builder-dense", {"profile": "gaps", "small-gap": 4, "n": 1048576,
                "universe": 4194304, "types": "uniform", "seed": 1729}),
            Case("builder-sparse-slots", "builder-sparse", {"profile": "uniform", "n": 4096,
                "universe": 2949120000, "chunk": 65536, "types": "one", "seed": 1729}),
            Case("builder-spill", "builder-spill", {"profile": "uniform", "n": 90000,
                "universe": 2949120000, "chunk": 65536, "types": "uniform", "seed": 1729})]


def main():
    args = options()
    if args.parallel_jobs < 1:
        raise ValueError("parallel-jobs must be positive")
    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        raise ValueError("invalid shard")
    if args.full_scan and not (args.real or args.corpus_manifest):
        raise ValueError("--full-scan requires --real or --corpus-manifest")
    if args.candidate_module_root and not args.full_scan:
        raise ValueError("--candidate-module-root requires --full-scan")
    params = dict(PROTOCOL["measurement"]["evaluation" if args.suite == "evaluation" else "quick"])
    params.update(parallel_jobs=args.parallel_jobs,
                  timing_context="shared-host" if args.parallel_jobs > 1 else "isolated")
    for name, value in [("process_blocks", args.blocks), ("inner_samples", args.samples), ("target_ms", args.target_ms)]:
        if value is not None:
            if value < 1:
                raise ValueError("measurement dimensions must be positive")
            params[name] = value
    if args.suite == "conformance":
        params["process_blocks"] = 1
    executable, pins = backends(fetch=args.fetch)
    validator = executable.with_name("hit_index_validate.exe")
    dll = args.reference_bridge or bridge()
    if args.candidate_bridge and args.candidate_bridge.resolve() == dll.resolve():
        raise ValueError("Candidate probe must be frozen separately from the reference build cache")
    from sunpack_native import fast_hash128_file
    env = environment()
    source_paths = [ROOT / "native/sunpack_native/src" / name for name in
                    ["scan/hit_storage.rs", "scan/embedded.rs", "io/scratch.rs", "io/resource_lifecycle.rs", "path_keys.rs", "fast_hash_core.rs"]]
    identities = {str(p.relative_to(ROOT)): fast_hash128_file(p) for p in source_paths}
    tooling = [p for directory in [ROOT / "benchmarks/hit_index", ROOT / "benchmarks/native/hit_index"]
               for p in directory.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    tooling.append(Path(__file__).resolve())
    tooling_identities = {str(p.relative_to(ROOT)): fast_hash128_file(p) for p in tooling}
    toolchain = {"rustc": command(["rustc", "--version"]).strip(),
                 "clang": command(["clang-cl", "--version"], env=env).splitlines()[0],
                 "platform": platform.platform(), "python": sys.version, "machine": platform.machine(),
                 "rustflags": env.get("RUSTFLAGS", ""), "cpu": command(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress)"], env=env).strip()}
    toolchain["capabilities"] = invoke_json([executable, "--mode", "capabilities"])
    toolchain["power_plan"] = command(["powercfg", "/getactivescheme"]).strip()
    configs = configurations(args.suite, args.algorithms)
    if args.candidate_bridge:
        configs.append({"name": "sunpack-candidate", "algorithm": "sunpack", "block": 128})
    status = 0
    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root, keep_workdir=args.keep_workdir) as ws:
        # Measure immutable per-run binaries, even if another development build
        # refreshes the shared cache while this campaign is running.
        native_dir = ws.result_dir / "native"
        native_dir.mkdir()
        for source in [executable, validator]:
            shutil.copy2(source, native_dir / source.name)
        executable = native_dir / executable.name
        validator = native_dir / validator.name
        shutil.copy2(dll, ws.result_dir / "reference-probe.dll")
        dll = ws.result_dir / "reference-probe.dll"
        if args.candidate_bridge:
            shutil.copy2(args.candidate_bridge, ws.result_dir / "candidate-probe.dll")
            args.candidate_bridge = ws.result_dir / "candidate-probe.dll"
        cases = synthetic(args.suite)
        public_inventory = {}
        if args.public and args.suite != "conformance":
            public, public_inventory = public_cases(executable, args.suite, fetch=args.fetch)
            cases += public
        manifest = []
        if args.corpus_manifest:
            saved = json.loads(args.corpus_manifest.read_text(encoding="utf-8"))
            manifest = saved["real_inputs"]
            for item in manifest:
                for path_key, hash_key in [("input", "input_xxh128"), ("trace", "trace_xxh128")]:
                    if fast_hash128_file(Path(item[path_key])) != item[hash_key]:
                        raise ValueError(f"Frozen {path_key} changed: {item['name']}")
            for row in saved["cases"]:
                if row["family"] == "real-matcher-trace":
                    cases.append(Case(**row))
        elif args.real:
            real, manifest = real_cases(ws)
            cases += real
        if args.case:
            cases = [case for case in cases if any(text in case.name for text in args.case)]
        if not cases:
            raise ValueError("case selection is empty")
        complete_cases = list(cases)
        cases = [case for i, case in enumerate(cases) if i % args.shard_count == args.shard_index]
        corpus = {"protocol_revision": PROTOCOL["revision"], "cases": [case.to_dict() for case in complete_cases],
                  "public_inventory": public_inventory, "real_inputs": manifest,
                  "selection": {"case_filter": args.case, "shard_count": args.shard_count, "shard_index": args.shard_index}}
        ws.write_result_json("corpus.json", corpus)
        ws.write_result_json("protocol.json", PROTOCOL)
        ws.write_result_json("sources.lock.json", pins)
        ws.write_result_json("source-identities.json", identities)
        ws.write_result_json("tooling-identities.json", tooling_identities)
        for source in tooling:
            target = ws.result_dir / "tooling" / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        ws.write_result_json("configurations.json", configs)
        ws.write_result_text("CMakeCache.txt", (CACHE / "cpp/CMakeCache.txt").read_text(encoding="utf-8"))
        ws.write_result_text("candidate.diff", command(["git", "diff", "--", *source_paths]))
        if args.reference_bridge:
            # An external frozen binary need not match the working build cache.
            # Do not attach unrelated cached source as its implementation.
            ws.write_result_json("reference-probe.json", {
                "origin": str(args.reference_bridge.resolve()),
                "binary_xxh128": fast_hash128_file(dll),
                "source": "external snapshot; source provenance supplied by the experiment",
            })
        else:
            for filename in ["Cargo.toml", "Cargo.lock", "src/lib.rs", "src/scan/hit_storage.rs"]:
                target = ws.result_dir / "bridge" / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(CACHE / "bridge" / filename, target)
        ws.write_result_text("faw-repair.json", (CACHE / "cpp/generated/faw-repair.json").read_text(encoding="utf-8"))
        validation = []
        valid = {}
        rows = []
        journal = ws.result_dir / "raw.jsonl"
        started = time.perf_counter()
        # Validation executable records exact emitted masked/seek tuples; timing
        # executable has all audit branches compiled out. No benchmark unit tests.
        def validate(job):
            case, config = job
            chosen_dll = args.candidate_bridge if config["name"] == "sunpack-candidate" else dll
            return native_call(validator, case, config, chosen_dll, mode="verify", params=params, block=0)

        for result in run_jobs(validate, ((case, config) for case in cases for config in configs),
                               parallel_jobs=args.parallel_jobs):
            validation.append(result)
            valid[(result["case"], result["configuration"])] = result
            if len(validation) % max(16, len(configs)) == 0 or len(validation) == len(cases) * len(configs):
                print(f"validated {len(validation)}/{len(cases)*len(configs)} cells", flush=True)
        ws.write_result_json("validation.json", validation)
        def measure_cell(job):
            dispatch_index, (block, order, case, config) = job
            checked = valid[(case.name, config["name"])]
            if checked["status"] != "ok":
                row = dict(checked, block=block, pair_order=order)
            elif args.suite == "conformance":
                row = dict(checked, block=block, pair_order=order)
            else:
                chosen_dll = args.candidate_bridge if config["name"] == "sunpack-candidate" else dll
                row = native_call(executable, case, config, chosen_dll, mode="index", params=params, block=block)
                row["pair_order"] = order
            row.update(dispatch_index=dispatch_index, parallel_jobs=args.parallel_jobs,
                       timing_context=params["timing_context"])
            return row

        with journal.open("w", encoding="utf-8") as stream:
            jobs = enumerate(schedule(cases, configs, params["process_blocks"]))
            for row in run_jobs(measure_cell, jobs, parallel_jobs=args.parallel_jobs):
                rows.append(row)
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
                stream.flush()
                if len(rows) % max(16, len(configs)) == 0 or len(rows) == len(cases) * len(configs) * params["process_blocks"]:
                    print(f"completed {len(rows)}/{len(cases)*len(configs)*params['process_blocks']} cells ({time.perf_counter()-started:.1f}s)", flush=True)
        lifecycle = []
        lifetimes = []
        if args.suite != "conformance":
            replay = builder_cases() + [case for case in cases if case.family == "real-matcher-trace"]
            versions = [("sunpack", dll)] + ([("sunpack-candidate", args.candidate_bridge)] if args.candidate_bridge else [])

            def replay_job(job):
                block, case, order, name, chosen_dll = job
                result = invoke_json([executable, *case.argv(), "--mode", "builder", "--bridge", chosen_dll,
                                      "--window", "6", "--workers", "4", "--order", order])
                result.update(case=case.name, order=order, configuration=name, block=block,
                              parallel_jobs=args.parallel_jobs, timing_context=params["timing_context"])
                return result

            jobs = ((block, case, order, name, chosen_dll) for block in range(params["process_blocks"])
                    for case in replay for order in ([0, 2, 3] if case.family == "real-matcher-trace" else [0, 1, 2])
                    for name, chosen_dll in (versions if block % 2 == 0 else list(reversed(versions))))
            for result in run_jobs(replay_job, jobs, parallel_jobs=args.parallel_jobs):
                lifecycle.append(result)
            print(f"replayed {len(lifecycle)} Builder cells", flush=True)

            def lifetime_job(job):
                case, name, chosen_dll = job
                result = invoke_json([executable, *case.argv(), "--mode", "lifetime", "--cycles", 12,
                                      "--bridge", chosen_dll, "--window", 6, "--workers", 4, "--order", 2])
                result.update(case=case.name, configuration=name, parallel_jobs=args.parallel_jobs,
                              timing_context=params["timing_context"])
                return result

            lifetimes = list(run_jobs(lifetime_job, ((case, name, chosen_dll) for case in builder_cases()
                                                   for name, chosen_dll in versions), parallel_jobs=args.parallel_jobs))
        full_scan = full_scan_cases(manifest, params["process_blocks"], candidate_module_root=args.candidate_module_root,
                                    reference_module_root=args.reference_module_root, parallel_jobs=args.parallel_jobs) if args.full_scan else []
        changed = {str(p.relative_to(ROOT)): fast_hash128_file(p) for p in source_paths} != identities
        binary_versions = {}
        for result in full_scan:
            binary_versions.setdefault(result["version"], set()).add(result.get("native_binary_xxh128"))
        if any(len(versions) != 1 or None in versions for versions in binary_versions.values()):
            changed = True
        summary = analysis.summarize(rows)
        candidate_errors = [r for r in validation if r["configuration"].startswith("sunpack") and r["status"] != "ok"]
        candidate_errors += [r for r in rows if r["configuration"].startswith("sunpack") and r["status"] != "ok"]
        candidate_errors += [r for r in lifecycle + lifetimes + full_scan if r["status"] != "ok"]
        conformance = None
        if args.conformance_report:
            conformance = json.loads(args.conformance_report.read_text(encoding="utf-8"))
            same_source = json.loads((args.conformance_report.parent / "source-identities.json").read_text(encoding="utf-8")) == identities
            conformance = {"report": str(args.conformance_report.resolve()), "same_source": same_source,
                           "candidate_bridge_xxh128": conformance["environment"].get("candidate_bridge_xxh128"),
                           "reference_bridge_xxh128": conformance["environment"].get("bridge_xxh128"),
                           "native_executable_xxh128": conformance["environment"].get("native_executable_xxh128"),
                           "gates": conformance["summary"]["gates"], "parameters": conformance["parameters"]}
        required_configs = {c["name"] for c in configurations(args.suite)}
        complete_synthetic = {c.name for c in synthetic(args.suite)} <= {c.name for c in complete_cases}
        summary["gates"] = {"source_changed": changed, "candidate_errors": len(candidate_errors),
                            "campaign_finished": True, "complete_synthetic_selection": complete_synthetic,
                            "complete_baseline_selection": required_configs <= {c["name"] for c in configs},
                            "scheduled_cells_complete": len(rows) == len(cases) * len(configs) * params["process_blocks"],
                            "mandatory_public_data": bool(public_inventory), "real_traces": bool(manifest),
                            "builder": bool(lifecycle), "lifetime": bool(lifetimes), "full_scan": bool(full_scan), "conformance": conformance,
                            "external_ir": "not included in the default corpus; disclose/import separately",
                            "scope": "Mechanical coverage only; publication additionally requires resolved uncertainty and claim-specific external/system workloads."}
        payload = {"parameters": {"suite": args.suite, **params, "protocol_revision": PROTOCOL["revision"], "shard_count": args.shard_count, "shard_index": args.shard_index},
                   "environment": {**toolchain, "revision": command(["git", "rev-parse", "HEAD"]).strip(),
                                   "native_executable_xxh128": fast_hash128_file(executable), "bridge_xxh128": fast_hash128_file(dll),
                                   "candidate_bridge_xxh128": fast_hash128_file(args.candidate_bridge) if args.candidate_bridge else None},
                   "samples": rows, "summary": summary}
        ws.write_result_json("lifecycle.json", lifecycle)
        ws.write_result_json("lifetime.json", lifetimes)
        ws.write_result_json("full-scan.json", full_scan)
        ws.write_result_text("report.json", render_report(report_from_payload(SCENARIO, payload)))
        ws.write_result_text("report.md", analysis.markdown(summary))
        if changed or (args.strict and candidate_errors):
            status = 1
        print(f"report: {ws.result_dir / 'report.json'}", flush=True)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
