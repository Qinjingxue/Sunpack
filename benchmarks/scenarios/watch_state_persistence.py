from __future__ import annotations

"""Measure incremental watch-state update latency against large snapshots."""

import argparse
import math
import statistics
import time
from pathlib import Path
from types import SimpleNamespace

from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from sunpack.filesystem.watcher.group_models import WatchGroupState
from sunpack.filesystem.watcher.state import (
    WatchPendingWork,
    WatchStateEntry,
    WatchStateStore,
)


DEFAULT_TOTAL_RECORDS = (300, 3000, 30000)


def _percentile(samples: list[float], percentile: float) -> float:
    ordered = sorted(samples)
    index = max(
        0,
        min(len(ordered) - 1, math.ceil(len(ordered) * percentile) - 1),
    )
    return ordered[index]


def _summary(samples: list[float]) -> dict[str, float]:
    return {
        "median_ms": round(statistics.median(samples), 4),
        "p95_ms": round(_percentile(samples, 0.95), 4),
        "max_ms": round(max(samples), 4),
    }


def _seed_state(state: WatchStateStore, total_records: int) -> None:
    pending_count = total_records // 3
    entry_count = total_records // 3
    group_count = total_records - pending_count - entry_count
    state.pending_work = {
        f"pending-{index}": WatchPendingWork(
            path=f"C:\\downloads\\pending-{index}.7z",
            size=1048576 + index,
            mtime=1720000000.0 + index,
            file_id=f"pending-{index}",
            change_usn=index,
        )
        for index in range(pending_count)
    }
    state.entries = {
        f"entry-{index}": WatchStateEntry(
            path=f"C:\\downloads\\failed-{index}.7z",
            size=2097152 + index,
            mtime=1720000000.0 + index,
            file_id=f"failed-{index}",
            change_usn=index,
            status="failed_password",
            last_error="wrong password",
            attempt_count=3,
            failure_kind="password",
            failure_stage="extract",
            failure_payload={
                "kind": "password",
                "stage": "extract",
                "blockers": ["password"],
            },
            last_attempt_at=1720000100.0 + index,
            password_generation=2,
        )
        for index in range(entry_count)
    }
    state.groups = {
        f"group-{index}": WatchGroupState(
            group_id=f"group-{index}",
            directory="C:\\downloads",
            logical_name=f"archive-{index}",
            split_family="7z",
            head_path=f"C:\\downloads\\archive-{index}.7z.001",
            input_paths=[f"C:\\downloads\\archive-{index}.7z.001"],
            owned_paths=[f"C:\\downloads\\archive-{index}.7z.001"],
            status="suspended",
            blockers=["missing_volume"],
            input_fingerprint=f"input-{index}",
            ownership_fingerprint=f"owner-{index}",
            last_attempted_input_fingerprint=f"input-{index}",
            password_generation=2,
            failure_payload={
                "kind": "missing_volume",
                "stage": "relation",
                "missing_reason": "middle_gap",
                "missing_indices": [2],
            },
            attempt_count=1,
            updated_at=1720000200.0 + index,
        )
        for index in range(group_count)
    }
    state.save()


def _candidate(path: Path, index: int):
    return SimpleNamespace(
        path=str(path),
        size=4194304 + index,
        mtime=1721000000.0 + index,
        file_id=f"benchmark-{index}",
        change_usn=index,
    )


def benchmark_case(root: Path, total_records: int, rounds: int) -> dict:
    case_root = root / str(total_records)
    case_root.mkdir()
    state = WatchStateStore(
        str(case_root / "state.json"),
        compact_records=1_000_000,
        compact_bytes=1024 * 1024 * 1024,
        hard_compact_bytes=1024 * 1024 * 1024,
    )
    _seed_state(state, total_records)
    snapshot_bytes = state.path.stat().st_size
    append_samples = []
    delete_samples = []
    for index in range(rounds):
        candidate = _candidate(case_root / f"new-{index}.7z", index)
        started = time.perf_counter()
        state.queue_active(candidate)
        append_samples.append((time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        state.complete_work([candidate.path])
        delete_samples.append((time.perf_counter() - started) * 1000)

    started = time.perf_counter()
    state.save()
    compact_ms = (time.perf_counter() - started) * 1000
    return {
        "total_records": total_records,
        "snapshot_bytes": snapshot_bytes,
        "journal_put": _summary(append_samples),
        "journal_delete": _summary(delete_samples),
        "compact_ms": round(compact_ms, 4),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure watch-state journal latency as retained state grows."
    )
    parser.add_argument(
        "--records",
        type=int,
        nargs="+",
        default=list(DEFAULT_TOTAL_RECORDS),
        help="Total retained records per case (default: 300 3000 30000).",
    )
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sizes = sorted(set(args.records))
    if args.rounds < 1 or not sizes or sizes[0] < 0:
        raise SystemExit("rounds must be positive and record counts nonnegative")
    with BenchmarkWorkspace(
        "watch.state-persistence",
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        samples = [
            benchmark_case(workspace.work, total_records, args.rounds)
            for total_records in sizes
        ]
        payload = {
            "parameters": {"records": sizes, "rounds": args.rounds},
            "samples": samples,
            "summary": {
                "latency_should_be_independent_of_retained_records": True,
                "compaction_reported_separately": True,
            },
        }
        rendered = render_report(report_from_payload("watch.state-persistence", payload))
        workspace.write_result_text("report.json", rendered)
        print(rendered)


if __name__ == "__main__":
    main()
