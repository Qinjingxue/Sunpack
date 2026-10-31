"""Compare frozen native builds on identical encrypted 7z file tables.

Each version/cell runs in a fresh interpreter. Version order alternates, and
entry-count order rotates between blocks. The parent retains the small input
archives and their producer commands. This measures password-header probing,
not payload extraction or whole-application memory.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import psutil

from benchmarks.harness import BenchmarkWorkspace, measure, render_report, report_from_payload
from tests.helpers.tool_config import get_test_tools

PASSWORD = "spe-header-scaling-known-password"
SCENARIO = "reader.header-scaling"
ROOT = Path(__file__).resolve().parents[2]


def memory(process):
    info = process.memory_info()
    return {key: int(getattr(info, key, 0)) for key in
            ("rss", "private", "peak_wset", "pagefile", "peak_pagefile")} | {
                "handles": process.num_handles(), "threads": process.num_threads()}


def probe(archive: Path, rounds: int):
    import sunpack_native
    from sunpack_native import NativeArchiveSession, clear_reader_resources, fast_hash128_file
    process = psutil.Process()
    module = next(Path(sunpack_native.__file__).parent.glob("*.pyd"))
    before = memory(process)
    session = NativeArchiveSession(str(archive))

    def invoke():
        outcome = dict(session.seven_zip_fast_verify_passwords([PASSWORD]))
        if outcome["status"] != "match" or int(outcome["matched_index"]) != 0:
            raise RuntimeError(f"header proof failed: {outcome}")
        return outcome

    measured = measure(invoke, runs=rounds)
    after_probe = memory(process)
    session.close()
    clear_reader_resources()
    after_clear = memory(process)
    return {"native_module": str(module), "native_xxh128": fast_hash128_file(module),
            "input_xxh128": fast_hash128_file(archive),
            "samples": [row.to_dict(include_value=True) for row in measured],
            "before": before, "after_probe": after_probe, "after_clear": after_clear}


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--baseline-module-root", type=Path)
    parser.add_argument("--entries", type=int, nargs="+", default=[1, 1000, 10000])
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--results-root", type=Path)
    args = parser.parse_args()
    if args.probe:
        print(json.dumps(probe(args.probe, args.rounds)))
        return
    if not args.baseline_module_root or not (args.baseline_module_root / "sunpack_native").is_dir():
        parser.error("--baseline-module-root must contain the frozen v1.3.1 wheel package")
    if min([*args.entries, args.rounds, args.repetitions]) < 1:
        parser.error("all dimensions must be positive")
    from sunpack_native import fast_hash128_file
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip:
        parser.error("7z.exe fixture producer is required")
    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root) as workspace:
        cases = []
        for count in args.entries:
            source = workspace.corpus / f"source-{count}"
            source.mkdir()
            for index in range(count):
                (source / f"entry-{index:06d}.txt").write_text("known header scaling payload\n", encoding="utf-8")
            archive = workspace.corpus / f"entries-{count}.7z"
            command = [str(seven_zip), "a", "-t7z", "-mx=0", "-mhe=on",
                       f"-p{PASSWORD}", "-y", str(archive), "*.txt"]
            result = subprocess.run(command, cwd=source, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            workspace.preserve(archive, "corpus/" + archive.name)
            cases.append({"entries": count, "path": archive, "bytes": archive.stat().st_size,
                          "xxh128": fast_hash128_file(archive), "producer_command": command,
                          "source_recipe": "entry-NNNNNN.txt, UTF-8 text: known header scaling payload\\n"})
        rows = []
        for block in range(args.repetitions):
            rotated = cases[block % len(cases):] + cases[:block % len(cases)]
            for case in rotated:
                versions = ["v1.3.1", "v1.3.2"]
                if block % 2:
                    versions.reverse()
                for order, version in enumerate(versions):
                    environment = os.environ.copy()
                    # Do not inherit a module override from a previous invocation.
                    roots = [str(ROOT)]
                    if version == "v1.3.1":
                        roots.insert(0, str(args.baseline_module_root.resolve()))
                    environment["PYTHONPATH"] = os.pathsep.join(roots)
                    command = [sys.executable, "-X", "utf8", "-m",
                               "benchmarks.scenarios.reader_header_scaling", "--probe",
                               str(case["path"]), "--rounds", str(args.rounds)]
                    completed = subprocess.run(command, cwd=ROOT, env=environment,
                                               capture_output=True, text=True, encoding="utf-8")
                    if completed.returncode:
                        raise RuntimeError(completed.stdout + completed.stderr)
                    row = json.loads(completed.stdout)
                    if row["input_xxh128"] != case["xxh128"]:
                        raise RuntimeError("paired input identity changed")
                    row.update(version=version, block=block, pair_order=order, entries=case["entries"],
                               command=command, module_search_roots=roots)
                    rows.append(row)
                    print(f"completed {version} entries={case['entries']} block={block}", flush=True)
        rendered = render_report(report_from_payload(SCENARIO, {
            "parameters": {"rounds": args.rounds, "repetitions": args.repetitions,
                           "entries": args.entries, "candidates": 1,
                           "scope": "Native password-header probe; no extraction. Warm samples exclude each child first call. Windows peak_wset includes Python and module startup; after_clear is a resident snapshot, not proof of deallocation."},
            "samples": rows, "corpus": cases,
        }))
        workspace.write_result_text("report.json", rendered)
        print(f"report: {workspace.result_dir / 'report.json'}", flush=True)


if __name__ == "__main__":
    main()
