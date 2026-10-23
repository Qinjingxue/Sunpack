"""Compare per-directory USN requests with one native batch on the same interval."""
from __future__ import annotations

import argparse
from pathlib import Path

import sunpack_native as native
from benchmarks.harness import BenchmarkReport, BenchmarkWorkspace, measure, write_report
from benchmarks.harness.timing import timing_summary
from sunpack.runtime.watch.scanner import watch_root_changes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directories", type=int, default=500)
    parser.add_argument("--changes", type=int, default=3000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    if min(args.directories, args.changes, args.rounds) < 1:
        parser.error("directories, changes and rounds must be positive")
    report = BenchmarkReport("watch.catalog-recovery", parameters=vars(args) | {
        "json_out": str(args.json_out) if args.json_out else None,
        "method": "Real NTFS USN; both APIs resolve identities and read the same fixed journal interval. No directory enumeration in either timed operation. Broker lease and corpus creation excluded.",
    })
    with BenchmarkWorkspace(report.scenario) as workspace:
        directories = [workspace.corpus / str(i) for i in range(args.directories)]
        for directory in directories:
            directory.mkdir()
        native.watch_broker_acquire()
        try:
            volume, journal, start = native.watch_volume_cursor(str(workspace.corpus))
            for i in range(args.changes):
                (directories[i % len(directories)] / f"{i}.opaque").touch()
            _, _, end = native.watch_volume_cursor(str(workspace.corpus))
            paths = [str(path) for path in directories]
            def shallow():
                return {path for directory in paths for path in watch_root_changes(directory, start, end)}
            def batched():
                return set(native.watch_directories_changes(paths, volume, journal, start, end))
            before = measure(shallow, runs=args.rounds)
            after = measure(batched, runs=args.rounds)
            expected = before[0].value
            if len(expected) != args.changes or any(row.value != expected for row in before + after):
                raise RuntimeError("USN queries returned different changes")
            report.summary.update({"journal_interval_bytes": end - start,
                "per_directory": timing_summary(before), "batched": timing_summary(after)})
        finally:
            native.watch_broker_release()
            write_report(report, workspace.result_dir / "report.json")
            if args.json_out:
                write_report(report, args.json_out)
            print(f"report: {workspace.result_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
