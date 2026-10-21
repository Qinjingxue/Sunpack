from __future__ import annotations

import argparse
import copy
import gc
import json
import time
import tracemalloc
from pathlib import Path

from benchmarks.harness import BenchmarkReport, BenchmarkWorkspace, write_report
from sunpack.core.passwords.internal.builtin import read_builtin_password_file
from sunpack.core.passwords.internal.store import PasswordStore


def main():
    parser = argparse.ArgumentParser(description="Password snapshot memory and unrelated-scope query scaling.")
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 100000])
    parser.add_argument("--queries", type=int, default=10000)
    parser.add_argument("--results-root", type=Path)
    args = parser.parse_args()
    report = BenchmarkReport(scenario="memory.password-store", parameters=vars(args))
    with BenchmarkWorkspace(report.scenario, results_root=args.results_root) as workspace:
        path = workspace.paths.work / "passwords.json"
        for count in args.sizes:
            with path.open("w", encoding="utf-8") as handle:
                handle.write('{"passwords":[{"value":"global"},{"value":"hit","scopes":["D:/Focus"]}')
                for index in range(count):
                    handle.write(',')
                    json.dump({"value": f"password-{index}", "scopes": [f"D:/Unrelated/{index}"]}, handle)
                handle.write('],"clipboard_history":[]}')
            gc.collect()
            tracemalloc.start()
            snapshot = read_builtin_password_file(path)
            retained, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            started = time.perf_counter()
            refreshed = read_builtin_password_file(path, snapshot)
            reload_ms = (time.perf_counter() - started) * 1000
            assert refreshed is snapshot
            store = PasswordStore.from_sources(password_snapshot=snapshot, cli_passwords=["cli"])
            store.remember_success("hit")
            started = time.perf_counter()
            for _ in range(args.queries):
                values = store.candidates("D:/Focus/Child/Deep")
            query_us = (time.perf_counter() - started) * 1e6 / args.queries
            assert values == ["hit", "cli", "global"]
            started = time.perf_counter()
            for _ in range(args.queries):
                assert copy.deepcopy(snapshot) is snapshot
            share_us = (time.perf_counter() - started) * 1e6 / args.queries
            row = {"unrelated_passwords": count, "query_us": query_us,
                   "snapshot_deepcopy_us": share_us, "reload_ms": reload_ms,
                   "retained_mib": retained / 1048576, "load_peak_mib": peak / 1048576}
            report.samples.append(row)
            print(json.dumps(row), flush=True)
            del store, snapshot, refreshed
        write_report(report, workspace.result_dir / "report.json")
        print(f"report: {workspace.result_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
