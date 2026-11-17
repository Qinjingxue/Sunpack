"""Measure per-format CLI or continuous Watch extraction of a 300 MiB corpus."""
from __future__ import annotations

import argparse
import platform
import shutil
import statistics
import time
from pathlib import Path

from benchmarks.harness.corpus import DEFAULT_CACHE_ROOT, _cached_corpus
from benchmarks.harness.corpus_300m import FORMATS_300M, special_cases
from benchmarks.harness.launcher import NativePackage
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.scenarios.native_boundary import _configure_watch, _copy_case, _directory_changes, output_summary
from benchmarks.watch_broker import SERVICE_ENV, isolated_broker_environment


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("cli", "watch"), required=True)
    parser.add_argument("--launcher", type=Path)
    parser.add_argument("--profile", choices=("release", "ci"), default="release")
    parser.add_argument("--arch", choices=("x64", "arm64"), default="x64")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--sample-ms", type=float, default=50)
    parser.add_argument("--formats", default=",".join(FORMATS_300M))
    parser.add_argument("--large-file-mib", type=int, default=150, help="Each of the two payload files (default 150 MiB; lower for smoke runs).")
    parser.add_argument("--sample", action="append", default=[], metavar="FORMAT=PATH", help="Additional archive, e.g. zipx, lz4 or enc; provide sibling volumes and -p as needed.")
    parser.add_argument("-p", action="append", default=[])
    parser.add_argument("--shape", choices=("ordinary", "disguised", "carrier"), default="ordinary",
                        help="Use normal discovery for ordinary or renamed archives and force deep scans for carriers.")
    parser.add_argument("-R", default="*")
    parser.add_argument("--cache-root", type=Path, default=DEFAULT_CACHE_ROOT)
    parser.add_argument("--rebuild-corpus", action="store_true")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args(argv)
    if args.runs < 1 or args.sample_ms <= 0 or args.large_file_mib < 1:
        parser.error("--runs, --sample-ms and --large-file-mib must be positive")
    if args.mode == "watch" and not isolated_broker_environment():
        parser.error("Run Watch through `python -m benchmarks watch` for an isolated broker")
    selected = set(filter(None, args.formats.split(",")))
    if not selected or selected.difference(FORMATS_300M):
        parser.error("--formats must select supported 300 MiB cases")
    extras = {}
    for value in args.sample:
        name, separator, path = value.partition("=")
        if not separator or not name or not Path(path).is_file():
            parser.error(f"invalid --sample: {value}")
        extras[name] = Path(path).resolve()

    with BenchmarkWorkspace(f"e2e-300m-{args.mode}", results_root=args.results_root,
                            keep_workdir=args.keep_workdir) as workspace:
        corpus, skipped, cache = _cached_corpus(
            workspace.corpus, cache_root=args.cache_root, small_files=0, large_files=2,
            large_file_mib=args.large_file_mib, rebuild=args.rebuild_corpus,
        )
        cases = {key: {**item, "split": item["format"].endswith("-split")}
                 for key, item in corpus.items() if item["workload"] == "few_large" and item["format"] in selected - extras.keys()}
        generation = selected - extras.keys()
        cases.update(special_cases(workspace.corpus, corpus, generation, skipped,
                                   large_files=2, large_file_mib=args.large_file_mib))
        for item in cases.values():
            password = item.get("password")
            if password and password not in args.password:
                args.password.append(password)
        for name, path in extras.items():
            cases[f"external:{name}"] = {"path": path, "format": name, "split": name.endswith("-split"), "expected_payload_bytes": None}
        missing = selected - {item["format"] for item in cases.values()}
        skipped = {name: reason for name, reason in skipped.items() if name in selected or name.startswith("few_large:")}
        for name in missing:
            skipped.setdefault(name, "corpus generator unavailable or did not produce this format; supply --sample")
        if args.shape == "carrier":
            for key in list(cases):
                if cases[key]["split"]:
                    skipped[key] = "carrier shape excludes multi-file volume sets"
                    del cases[key]
        if not cases:
            selected_skips = {name: reason for name, reason in skipped.items()
                              if name in selected or name in extras}
            raise ValueError(f"No requested archive formats available for {args.shape}: {selected_skips}")

        deep = args.shape == "carrier"
        rows = []
        with NativePackage(workspace.work, launcher=args.launcher, profile=args.profile,
                           arch=args.arch, sample_ms=args.sample_ms, watch=args.mode == "watch") as app:
            if args.mode == "watch":
                inputs = workspace.work / "arrivals"
                inputs.mkdir()
                _configure_watch(app, args, inputs, workspace.outputs, live=True, deep=deep)
                staging = workspace.work / "staging"
                staging.mkdir()
                app.run("daemon", "start", "-nt", require_broker=True)
            try:
                for key, item in cases.items():
                    for run in range(args.runs):
                        name = f"{key.replace(':', '-')}-{run}"
                        if args.mode == "cli":
                            entry = _copy_case(item, workspace.work / "inputs" / name, args.shape)
                            output = workspace.outputs / name
                            passwords = [part for password in args.password for part in ("-p", password)]
                            scan_flags = ("-d",) if deep else ()
                            result = app.run("extract", *scan_flags, "-r", args.recursive,
                                             "-c", "k", "-nf", "-npa", "-o", output, entry, *passwords)
                            if not result["response"]["summary"]["processed_count"]:
                                raise RuntimeError(f"No archive processed for {key}")
                            output_info = output_summary(output)
                            shutil.rmtree(output, ignore_errors=True)
                        else:
                            folder = staging / name
                            entry = _copy_case(item, folder, args.shape)
                            members = list(folder.iterdir())
                            before = output_summary(workspace.outputs)
                            sampler = app.sampler()
                            with _directory_changes(inputs) as wait, sampler:
                                started = time.perf_counter()
                                if len(members) > 1:
                                    target = inputs / name
                                    folder.replace(target)
                                    targets = [target / member.name for member in members]
                                else:
                                    target = inputs / f"{name}{entry.suffix}"
                                    entry.replace(target)
                                    targets = [target]
                                while any(path.exists() for path in targets):
                                    wait()
                                seconds = time.perf_counter() - started
                            after = output_summary(workspace.outputs)
                            output_info = {field: after[field] - before[field] for field in before}
                            result = {"seconds": seconds, **app.memory_result(sampler.samples, require_broker=True),
                                      "samples": [sample.to_dict() for sample in sampler.samples]}
                        expected = item.get("expected_payload_bytes")
                        if expected is not None and output_info["bytes"] != expected:
                            raise RuntimeError(f"{key}: output has {output_info['bytes']} bytes, expected {expected}")
                        rows.append({"case": key, "format": item["format"], "run": run + 1,
                                     "expected_payload_bytes": expected, "output": output_info, **result})
                        print(f"{args.mode} {key} {run + 1}/{args.runs}: {result['seconds']:.3f}s", flush=True)
            finally:
                if args.mode == "watch":
                    app.run("daemon", "stop")
            report = {
                "schema_version": 2, "mode": args.mode, "platform": platform.platform(),
                "forced_deep_scan": deep,
                "parameters": {**vars(args), "password": None, "password_candidate_count": len(args.password)},
                "corpus_cache": cache, "skipped": skipped, "rows": rows,
                "broker_service": app.env[SERVICE_ENV] if args.mode == "watch" else None,
                "memory_scope": "native launcher, resident runtime and descendants" + (" and isolated Broker and descendants" if args.mode == "watch" else ""),
                "sampling_note": "Sampled peaks are lower bounds; short-lived allocations may be missed.",
                "timing_boundary": "publication to input cleanup" if args.mode == "watch" else "launcher start to command completion",
                "cases": {key: {"median_seconds": statistics.median(row["seconds"] for row in rows if row["case"] == key),
                                "max_sampled_rss_mib": max(row["peak_rss_mib"] for row in rows if row["case"] == key),
                                "max_sampled_private_mib": max(row["peak_private_mib"] for row in rows if row["case"] == key)}
                          for key in cases},
            }
            target = workspace.write_result_json("result.json", report)
            print(f"Result: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
