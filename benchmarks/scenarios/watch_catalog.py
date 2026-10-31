"""Measure native Watch catalog updates, bucket lookup and state lifetime."""
from __future__ import annotations

import argparse
import gc
from dataclasses import replace
from pathlib import Path

from benchmarks.harness import BenchmarkReport, BenchmarkWorkspace, ProcessSampler, measure, write_report
from benchmarks.harness.timing import timing_summary
from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.core.support.path_keys import path_key
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.runtime.watch.state import WatchStateStore
from sunpack_native import NativeWatchCatalog
from sunpack.runtime.watch.output_roots import WatchOutputRoots


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=30000)
    parser.add_argument("--protected-files", type=int, default=100000)
    parser.add_argument("--bucket-size", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--event-batch-size", type=int, default=64)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    if min(args.files, args.bucket_size, args.rounds, args.event_batch_size) < 1 or args.protected_files < 0:
        parser.error("files, bucket-size and rounds must be positive; protected-files nonnegative")
    report = BenchmarkReport("scan.watch-catalog", parameters={
        "files": args.files, "protected_files": args.protected_files,
        "bucket_size": args.bucket_size, "rounds": args.rounds, "event_batch_size": args.event_batch_size,
        "method": "Real empty disguised files across 100 directories. Compare the current native bucket path with scope re-enumeration on identical authorized inputs; this is not a comparison with a previous release. File updates use an independent index WAL and checkpoint; reload is measured without re-enumeration. No archive extraction or Broker is needed.",
    })
    sampler = ProcessSampler()
    with BenchmarkWorkspace(report.scenario, results_root=args.results_root) as workspace:
        root = workspace.corpus
        directories = [root / str(index) for index in range(100)]
        for directory in directories:
            directory.mkdir()
        for index in range(args.files):
            (directories[index % len(directories)] / f"item{index}.disguised").touch()
        members = []
        for index in range(args.bucket_size):
            path = directories[index % len(directories)] / f"shared.part{index + 1}.opaque"
            path.touch()
            members.append(path)
        generated = root / "generated"
        options = DirectoryScanner.compile_scan_options({"filesystem": {"scan_filters_enabled": False}})
        scope = DiscoveryScope(str(root), recursive=True)
        reference_scope = DiscoveryScope(str(root), recursive=True, excluded_subtrees=[str(generated)])
        baseline_memory = sampler.take().to_dict()
        state_path = workspace.work / "state.snapshot"
        state = WatchStateStore(str(state_path))
        try:
            outputs = WatchOutputRoots(state, (scope,))
            outputs.register(str(generated))
            for index in range(args.protected_files):
                (generated / f"output{index}.txt").touch()
            catalog = NativeWatchCatalog(state._native, str(workspace.work))
            def update(path=None):
                errors = options.catalog_update(catalog, scope.native, path)
                if errors:
                    raise OSError(errors)
            cold = measure(update, runs=1)[0]
            report.samples.append({"phase": "initial_catalog", **cold.to_dict()})
            del cold
            gc.collect()
            resident_memory = sampler.take().to_dict()
            def bucket():
                filtered, raw = options.catalog_snapshot(catalog, scope.native, str(members[0]))
                return len(raw.file_columns()[0])
            def enumerate_scope():
                filtered, raw = options.scan_scope(reference_scope.native)
                return len(raw.relation_bucket(str(members[0])))
            # Warm both paths, then alternate paired order to avoid assigning
            # all early/late cache and background conditions to one operation.
            bucket()
            enumerate_scope()
            lookup, enumeration = [], []
            for iteration in range(args.rounds):
                pair = [("bucket", bucket, lookup),
                        ("scope_reenumeration", enumerate_scope, enumeration)]
                if iteration % 2:
                    pair.reverse()
                for order, (phase, operation, rows) in enumerate(pair):
                    row = replace(measure(operation, runs=1)[0], iteration=iteration)
                    rows.append(row)
                    report.samples.append({"phase": phase, "pair_order": order,
                                           **row.to_dict(include_value=True)})
            for row in [*lookup, *enumeration]:
                if row.value != args.bucket_size:
                    raise RuntimeError(f"Different authorized bucket: {row.value}")
            sequence = iter(range(args.rounds * args.event_batch_size + 1))
            def event():
                for _ in range(args.event_batch_size):
                    members[-1].write_bytes(b"x" * (next(sequence) % 128 + 1))
                    update(str(members[-1]))
                # Include Written completion in both implementations' timings.
                commit = getattr(catalog, "commit", None)
                if commit is not None:
                    commit()
                return bucket()
            updates = measure(event, runs=args.rounds)
            report.samples.extend({"phase": "file_update_wal_and_bucket",
                                   **row.to_dict(include_value=True)} for row in updates)
            report.summary.update({
                "bucket": timing_summary(lookup), "scope_reenumeration": timing_summary(enumeration),
                "file_update_wal_and_bucket": timing_summary(updates),
                "index_wal_bytes": (workspace.work / "catalog.wal.bin").stat().st_size,
                "initial_memory": baseline_memory, "catalog_memory": resident_memory,
            })
            checkpoint = measure(catalog.close, runs=1)[0]
            report.summary["index_checkpoint_ms"] = checkpoint.wall_ms
            report.summary["index_checkpoint_bytes"] = (workspace.work / "catalog.snapshot.bin").stat().st_size
            catalog = None
            def restore():
                nonlocal catalog
                catalog = NativeWatchCatalog(state._native, str(workspace.work))
                return bucket()
            restored = measure(restore, runs=1)[0]
            if restored.value != args.bucket_size:
                raise RuntimeError("Incomplete restored index")
            report.summary["index_restore_ms"] = restored.wall_ms
            catalog.close()
            catalog = None
            gc.collect()
            report.summary["after_removal_memory"] = sampler.take().to_dict()
        finally:
            state.close()
            write_report(report, workspace.result_dir / "report.json")
            if args.json_out:
                write_report(report, args.json_out)
            print(f"report: {workspace.result_dir / 'report.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
