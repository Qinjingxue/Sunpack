"""Stream one trace at a time to the Rust test executable and score its admissions."""
from __future__ import annotations

import json
import os
import subprocess
from contextlib import contextmanager
from dataclasses import asdict, replace

from benchmarks.harness.workspace import REPO_ROOT
from .replay import FileResult, add_valid_proposal_latency, input_results, proposal_boundaries, record_proposal


@contextmanager
def scheduler_replay(work):
    command = [
        "cargo", "test", "--quiet", "--locked", "--manifest-path", str(REPO_ROOT / "sunpack/Cargo.toml"),
        "-p", "sunpack-runtime", "--profile", "ci", "--bin", "sunpack-runtime", "--",
        "--ignored", "--exact", "--nocapture", "runtime::watch::quiet_replay::replay_corpus",
    ]
    with subprocess.Popen(
        command, cwd=REPO_ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        encoding="utf-8", env={**os.environ, "SUNPACK_QUIET_REPLAY_WORK": str(work)},
    ) as process:
        try:
            yield lambda trace, order: replay(trace, order, process)
        finally:
            process.stdin.close()
            output = process.stdout.read()
            if process.wait():
                raise RuntimeError(f"Rust scheduler replay exited with {process.returncode}: {output}")


def replay(trace, tie_order, process):
    indices = {file.key: index for index, file in enumerate(trace.files)}
    request = {
        "horizon": trace.horizon,
        "files": [
            {"visible_at": file.visible_at, "blocked": file.blocked,
             "mutations": [
                 {"at": item.at, "size": item.size, "mtime": item.mtime, "usn": item.usn,
                  "operation": item.operation, "change_reasons": item.change_reasons}
                 for item in file.mutations
             ]}
            for file in trace.files
        ],
        "observations": [(item.at, indices[item.key], item.source == "directory") for item in trace.observations],
        "observation_first": tie_order == "observation_first",
    }
    process.stdin.write(json.dumps(request, separators=(",", ":"), allow_nan=False) + "\n")
    process.stdin.flush()
    for line in process.stdout:
        _, marker, output = line.partition("QUIET_REPLAY ")
        if marker:
            response = json.loads(output)
            break
    else:
        raise RuntimeError("Rust scheduler test exited without returning a replay")

    # Canonicalize both sides of the comparison to Instant's nanosecond ticks.
    # Rust's as_secs_f64 and Python's division can round the same tick differently.
    ns = lambda at: round(at * 1_000_000_000) / 1_000_000_000
    trace = replace(trace, horizon=ns(trace.horizon), files=tuple(
        replace(file, visible_at=ns(file.visible_at),
                complete_at=None if file.complete_at is None else ns(file.complete_at),
                blocked=tuple((ns(start), ns(end)) for start, end in file.blocked),
                mutations=tuple(replace(item, at=ns(item.at)) for item in file.mutations))
        for file in trace.files
    ))
    group_ready, boundaries = proposal_boundaries(trace)
    files = []
    for source, proposals in zip(trace.files, response["proposals"], strict=True):
        result = FileResult(source.key, source.shape, source.complete_at is not None)
        for at in proposals:
            record_proposal(result, source, ns(at), group_ready, trace.horizon)
        files.append(asdict(result))
    add_valid_proposal_latency(files, boundaries)
    inputs = input_results(trace, files)
    for item in inputs:
        if item["processing_ready_at"] is None:
            item["missing_reason"] = "no_processing_ready_input"
        elif item["first_valid_proposal_at"] is not None:
            item["missing_reason"] = None
        else:
            deadlines = [response["pending_deadlines"][indices[member]] for member in item["members"]]
            pending = [ns(deadline) for deadline in deadlines if deadline is not None]
            item["pending_deadlines"] = pending
            if not pending:
                item["missing_reason"] = "no_pending_after_earlier_admission"
            elif min(pending) > trace.horizon:
                item["missing_reason"] = "deadline_beyond_horizon"
            else:
                item["missing_reason"] = "pending_at_horizon"
    return {"files": files, "inputs": inputs, "delivered_observations": len(trace.observations),
            "replay_cpu_ns": response["replay_cpu_ns"],
            "replay_elapsed_ns": response["replay_elapsed_ns"], **response["metrics"]}
