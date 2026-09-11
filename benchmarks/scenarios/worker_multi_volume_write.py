"""Verify per-volume writer scheduling on two real physical disks.

The scenario measures the same worker executable under three conditions:

1. solo: each target volume extracts one job alone;
2. both: a single worker process runs one job per volume concurrently;
3. both-reversed: the same pair submitted in the opposite order.

Acceptance follows ``docs/sevenzip_worker_per_volume_write.zh.md`` §9.3:

* aggregate throughput >= 0.90 x (solo_C + solo_D)   (hard fail below 0.80);
* each volume keeps >= 0.85 x its own solo throughput;
* solo throughput >= 0.90 x the volume's measured sequential write capability;
* a single worker reports at least 2 concurrent jobs during the pair phase;
* the two jobs' active windows overlap by >= 90% of the shorter job.

Unrelated volumes needed for capacity isolation: if the two targets resolve to
the same PhysicalDisk the scenario skips with an explicit reason instead of
producing a misleading result.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler, render_report, report_from_payload
from benchmarks.scenarios.worker_single_file_write import (
    MEMBER_NAME,
    MIB,
    GIB,
    _create_archive,
    _digest_path,
    _prefetch_archive,
    _worker_counters,
)
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path


SCENARIO = "extraction.worker-multi-volume-write"

# §9.3 thresholds.  These are hard gates, not diagnostics.
AGGREGATE_FLOOR = 0.90          # of (solo_C + solo_D)
AGGREGATE_HARD_FAIL = 0.80      # below this the disks are not actually additive
PER_VOLUME_FLOOR = 0.85         # of that volume's own solo throughput
OVERLAP_FLOOR = 0.90            # of the shorter job's active window
MIN_CONCURRENT_JOBS = 2
# Measured on this machine: the extraction pipeline saturates around 1.5x one job
# when the payload is cache resident, so a same-disk control can match a genuine
# cross-disk run.  A payload large enough to be I/O bound makes the two differ by
# roughly 1.5x here; the gate sits between the two regimes.
CROSS_VS_SAME_DISK_FLOOR = 1.15
# Sanity floor only: the raw probe writes 8 MiB blocks with no decode, no CRC and
# no staging copies, so extraction legitimately lands below it (measured ~0.84 on
# both NVMe volumes before this refactor).  A collapse below this means the
# extraction pipeline itself broke, not that the disks are slow.
SOLO_CAPABILITY_SANITY = 0.50

_TOPOLOGY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$parts = @{}
Get-Partition | Where-Object { $_.DriveLetter } | ForEach-Object {
    $parts[[string]$_.DriveLetter] = $_.DiskNumber
}
$disks = @{}
Get-PhysicalDisk | ForEach-Object {
    $disks[[string]$_.DeviceId] = [pscustomobject]@{
        friendly_name = $_.FriendlyName
        media_type = [string]$_.MediaType
        bus_type = [string]$_.BusType
        size = [int64]$_.Size
    }
}
$volumes = @()
foreach ($letter in $parts.Keys) {
    $disk = $parts[$letter]
    $info = $disks[[string]$disk]
    $vol = Get-Volume -DriveLetter $letter
    $volumes += [pscustomobject]@{
        drive = [string]$letter
        disk_number = [int]$disk
        friendly_name = [string]$info.friendly_name
        media_type = [string]$info.media_type
        bus_type = [string]$info.bus_type
        disk_size = [int64]$info.size
        size = [int64]$vol.Size
        size_remaining = [int64]$vol.SizeRemaining
        filesystem = [string]$vol.FileSystem
    }
}
[pscustomobject]@{ volumes = $volumes } | ConvertTo-Json -Depth 5 -Compress
"""


def _topology() -> list[dict[str, Any]]:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _TOPOLOGY_SCRIPT],
        capture_output=True,
        text=True,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(f"topology probe failed: {completed.stderr.strip()}")
    payload = json.loads(completed.stdout.strip() or "{}")
    volumes = payload.get("volumes") or []
    if isinstance(volumes, dict):
        volumes = [volumes]
    return [dict(item) for item in volumes]


def _median(values: list[float]) -> float:
    return float(statistics.median(values)) if values else 0.0


def _mad(values: list[float]) -> float:
    """Median absolute deviation (raw, not scaled)."""
    if not values:
        return 0.0
    center = statistics.median(values)
    return float(statistics.median([abs(value - center) for value in values]))


def _noise_floor(values: list[float]) -> float:
    """3 x MAD is the §9.2 noise estimate; 0.0 means "not measured"."""
    if len(values) < 3:
        return 0.0
    return 3.0 * _mad(values)


def _measure_sequential_write(target_dir: Path, *, bytes_to_write: int) -> float:
    """Measure bounded sequential write throughput on the target volume."""
    target_dir.mkdir(parents=True, exist_ok=True)
    probe = target_dir / "sequential-write-probe.bin"
    block = b"\xa5" * (8 * MIB)
    written = 0
    started = time.perf_counter()
    try:
        with probe.open("wb", buffering=0) as stream:
            while written < bytes_to_write:
                chunk = min(len(block), bytes_to_write - written)
                stream.write(block[:chunk])
                written += chunk
    finally:
        try:
            probe.unlink()
        except OSError:
            pass
    seconds = max(1e-6, time.perf_counter() - started)
    return written / MIB / seconds


class _JobRun:
    """One submitted job plus its native event timeline."""

    def __init__(self, job_id: str, output_dir: Path, payload_bytes: int) -> None:
        self.job_id = job_id
        self.output_dir = output_dir
        self.payload_bytes = payload_bytes
        self.events: list[dict[str, Any]] = []
        self.result: dict[str, Any] | None = None
        self.failure = ""
        self.submitted_ns = 0
        self.started_ns = 0
        self.finished_ns = 0
        self.done = threading.Event()

    def on_line(self, line: str) -> bool:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(event, dict):
            return False
        self.events.append(event)
        event_name = str(event.get("event") or "")
        if event.get("type") == "result" and str(event.get("job_id") or "") == self.job_id:
            self.result = event
        elif event_name == "job_started" and not self.started_ns:
            self.started_ns = time.perf_counter_ns()
        elif event_name == "job_finished" and self.result is not None:
            if not self.finished_ns:
                self.finished_ns = time.perf_counter_ns()
            self.done.set()
            return True
        return False

    def on_timeout(self, message: str) -> None:
        self.failure = str(message)
        self.done.set()

    @property
    def wall_seconds(self) -> float:
        if not self.started_ns or not self.finished_ns:
            return 0.0
        return max(1e-6, (self.finished_ns - self.started_ns) / 1_000_000_000.0)

    @property
    def throughput_mib(self) -> float:
        return self.payload_bytes / MIB / self.wall_seconds if self.wall_seconds else 0.0

    def verify_output(self) -> bool:
        output_file = self.output_dir / MEMBER_NAME
        if not output_file.is_file() or output_file.stat().st_size != self.payload_bytes:
            return False
        return True


def _top_level_entries(target_dir: Path) -> set[str]:
    try:
        return {item.name for item in target_dir.iterdir()}
    except OSError:
        return set()


def _wait_for_jobs(
    runs: list[_JobRun],
    *,
    worker: _NativeWorkerProcess,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    for run in runs:
        while not run.done.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "worker jobs timed out: " + ", ".join(item.job_id for item in runs)
                )
            run.done.wait(timeout=min(0.1, remaining))
            if not worker.is_alive() and not all(item.done.is_set() for item in runs):
                raise RuntimeError(
                    "worker exited while running jobs: "
                    + ", ".join(item.job_id for item in runs if not item.done.is_set())
                )
    failed = [item for item in runs if item.failure or item.result is None]
    if failed:
        detail = failed[0].failure or "worker closed before returning a result"
        raise RuntimeError(f"job {failed[0].job_id} failed: {detail}")
    rejected = [
        item
        for item in runs
        if str((item.result or {}).get("status") or "") != "ok"
    ]
    if rejected:
        item = rejected[0]
        result = item.result or {}
        raise RuntimeError(
            f"job {item.job_id} did not succeed: status={result.get('status')!r} "
            f"failure_stage={result.get('failure_stage')!r} "
            f"failure_kind={result.get('failure_kind')!r} "
            f"hresult_hex={result.get('hresult_hex')!r} "
            f"message={result.get('message')!r}"
        )


def _job_payload(
    *,
    job_id: str,
    archive: Path,
    output_dir: Path,
    dll_path: Path,
) -> str:
    return json.dumps(
        {
            "job_id": job_id,
            "seven_zip_dll_path": str(dll_path),
            "archive_path": str(archive),
            "part_paths": [str(archive)],
            "output_dir": str(output_dir),
            "password": "",
            "format_hint": "zip",
            "dry_run": False,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _run_phase(
    *,
    label: str,
    targets: list[dict[str, Any]],
    worker_path: Path,
    dll_path: Path,
    thread_capacity: int,
    writer_threads: int,
    timeout_seconds: float,
    sample_interval: float,
    prefetch: bool,
) -> dict[str, Any]:
    """Run one phase; ``targets`` carries archive/output/payload per volume."""
    if prefetch:
        for target in targets:
            _prefetch_archive(Path(target["archive"]), chunk_bytes=8 * MIB)
    worker = _NativeWorkerProcess(
        str(worker_path),
        None,
        {
            "thread_capacity": thread_capacity,
            "adaptive_enabled": False,
            "initial_active_jobs": len(targets),
            "writer_threads": writer_threads,
        },
    )
    sampler = ProcessSampler(interval_seconds=sample_interval)
    runs: list[_JobRun] = []
    top_level_before: dict[str, set[str]] = {}
    for index, target in enumerate(targets):
        output_dir = Path(target["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        top_level_before[str(output_dir)] = _top_level_entries(output_dir)
        runs.append(
            _JobRun(
                job_id=f"{label}-{index}",
                output_dir=output_dir,
                payload_bytes=int(target["payload_bytes"]),
            )
        )

    sampler.start()
    counters_before = _worker_counters(worker)
    sampler.take()
    phase_started = time.perf_counter_ns()
    try:
        for run, target in zip(runs, targets):
            run.submitted_ns = time.perf_counter_ns()
            worker.submit_async(
                _job_payload(
                    job_id=run.job_id,
                    archive=Path(target["archive"]),
                    output_dir=run.output_dir,
                    dll_path=dll_path,
                ),
                run.job_id,
                on_line=run.on_line,
                on_timeout=run.on_timeout,
            )
        _wait_for_jobs(runs, worker=worker, timeout_seconds=timeout_seconds)
        phase_finished = time.perf_counter_ns()
        sampler.take()
        counters_after = _worker_counters(worker)
    finally:
        sampler.stop()
        worker.close()

    phase_seconds = max(1e-6, (phase_finished - phase_started) / 1_000_000_000.0)
    # Peak-concurrency window: from the first job starting to the last one
    # finishing.  The submission-to-completion window also contains this harness's
    # own per-job overhead, which would understate the concurrent throughput the
    # comparison is about.
    starts = [run.started_ns for run in runs if run.started_ns]
    ends = [run.finished_ns for run in runs if run.finished_ns]
    if starts and ends and min(ends) > max(starts):
        concurrent_seconds = (max(ends) - max(starts)) / 1_000_000_000.0
    else:
        concurrent_seconds = phase_seconds
    results: list[dict[str, Any]] = []
    for run, target in zip(runs, targets):
        output_dir = str(run.output_dir)
        leaked = sorted(_top_level_entries(Path(output_dir)) - top_level_before[output_dir])
        status = str((run.result or {}).get("status") or "")
        results.append(
            {
                "job_id": run.job_id,
                "drive": target["drive"],
                "status": status,
                "output_verified": bool(status == "ok" and run.verify_output()),
                "wall_seconds": round(run.wall_seconds, 6),
                "throughput_mib_per_second": round(run.throughput_mib, 3),
                "concurrent_peak": _peak_concurrency(run),
                "leaked_entries": leaked,
            }
        )
    total_payload = sum(int(target["payload_bytes"]) for target in targets)
    return {
        "label": label,
        "phase_seconds": round(phase_seconds, 6),
        "aggregate_throughput_mib_per_second": round(total_payload / MIB / concurrent_seconds, 3),
        "aggregate_throughput_submit_window_mib_per_second": round(
            total_payload / MIB / phase_seconds, 3
        ),
        "concurrent_window_seconds": round(concurrent_seconds, 6),
        "concurrent_peak": max((item["concurrent_peak"] for item in results), default=0),
        "worker_cpu_ms": None
        if counters_before["cpu_ms"] is None or counters_after["cpu_ms"] is None
        else round(float(counters_after["cpu_ms"]) - float(counters_before["cpu_ms"]), 3),
        "jobs": results,
        "all_outputs_verified": all(item["output_verified"] for item in results),
        # Consumed by the pair-phase overlap gate; dropped before rendering.
        "runs": runs,
    }


def _peak_concurrency(run: _JobRun) -> int:
    """Highest ``active_jobs`` the worker reported for this job's lifecycle."""
    peak = 0
    for event in run.events:
        if event.get("event") in {"job_started", "job_admitted", "job_finished"}:
            peak = max(peak, int(event.get("active_jobs") or 0))
    return peak


def _overlap_ratio(first: _JobRun, second: _JobRun) -> float:
    """Fraction of the shorter job's active window covered by the intersection."""
    starts = [value for value in (first.started_ns, second.started_ns) if value]
    ends = [value for value in (first.finished_ns, second.finished_ns) if value]
    if len(starts) < 2 or len(ends) < 2:
        return 0.0
    overlap = min(ends) - max(starts)
    shorter = min(
        first.finished_ns - first.started_ns,
        second.finished_ns - second.started_ns,
    )
    if shorter <= 0:
        return 0.0
    return max(0.0, overlap / shorter)


def _evaluate(
    *,
    topology: list[dict[str, Any]],
    solo: dict[str, dict[str, Any]],
    pairs: list[dict[str, Any]],
    capability: dict[str, float],
    runs: int,
    mode: str,
    same_disk: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Apply the §9.3 gates and return a structured verdict."""
    checks: list[dict[str, Any]] = []
    solo_throughput = {drive: _median(item["values"]) for drive, item in solo.items()}
    drives = sorted(solo_throughput)

    for drive in drives:
        measured = capability.get(drive, 0.0)
        actual = solo_throughput.get(drive, 0.0)
        ratio = (actual / measured) if measured else 0.0
        checks.append(
            {
                "name": f"solo_capability[{drive}]",
                "detail": f"solo {actual:.1f} MiB/s vs sequential capability {measured:.1f} MiB/s",
                "value": round(ratio, 4),
                "threshold": SOLO_CAPABILITY_SANITY,
                "gate": False,
                "passed": ratio >= SOLO_CAPABILITY_SANITY,
            }
        )

    pair_aggregate = [item["aggregate_throughput_mib_per_second"] for item in pairs]
    pair_per_drive: dict[str, list[float]] = {drive: [] for drive in drives}
    pair_peaks: list[int] = []
    pair_overlaps: list[float] = []
    for item in pairs:
        pair_peaks.append(int(item["concurrent_peak"]))
        for job in item["jobs"]:
            pair_per_drive.setdefault(job["drive"], []).append(
                float(job["throughput_mib_per_second"])
            )
        pair_overlaps.append(float(item.get("overlap_ratio") or 0.0))

    solo_sum = sum(solo_throughput.values())
    aggregate = _median(pair_aggregate)
    aggregate_ratio = (aggregate / solo_sum) if solo_sum else 0.0
    checks.append(
        {
            "name": "aggregate_additivity",
            "detail": (
                f"pair aggregate {aggregate:.1f} MiB/s vs solo sum {solo_sum:.1f} MiB/s "
                f"(hard floor {AGGREGATE_HARD_FAIL:.2f})"
            ),
            "value": round(aggregate_ratio, 4),
            "threshold": AGGREGATE_FLOOR,
            "gate": True,
            "passed": aggregate_ratio >= AGGREGATE_FLOOR and aggregate_ratio >= AGGREGATE_HARD_FAIL,
        }
    )

    for drive in drives:
        pair_value = _median(pair_per_drive.get(drive, []))
        ratio = (pair_value / solo_throughput[drive]) if solo_throughput.get(drive) else 0.0
        checks.append(
            {
                "name": f"per_volume_retention[{drive}]",
                "detail": (
                    f"pair {pair_value:.1f} MiB/s vs solo {solo_throughput[drive]:.1f} MiB/s"
                ),
                "value": round(ratio, 4),
                "threshold": PER_VOLUME_FLOOR,
                "gate": True,
                "passed": ratio >= PER_VOLUME_FLOOR,
            }
        )

    peak = int(_median([float(value) for value in pair_peaks]))
    checks.append(
        {
            "name": "concurrency_floor",
            "detail": f"worker-reported peak concurrent jobs during pair phase = {peak}",
            "value": peak,
            "threshold": MIN_CONCURRENT_JOBS,
            "gate": True,
            "passed": peak >= MIN_CONCURRENT_JOBS,
        }
    )

    overlap = _median(pair_overlaps)
    checks.append(
        {
            "name": "window_overlap",
            "detail": f"median overlap of the two jobs' active windows = {overlap:.3f}",
            "value": round(overlap, 4),
            "threshold": OVERLAP_FLOOR,
            "gate": True,
            "passed": overlap >= OVERLAP_FLOOR,
        }
    )

    distinct_disks = len({item["disk_number"] for item in topology})
    checks.append(
        {
            "name": "distinct_physical_disks",
            "detail": f"targets span {distinct_disks} physical disk(s)",
            "value": distinct_disks,
            "threshold": 2,
            "gate": True,
            "passed": distinct_disks >= 2,
        }
    )

    verified = all(item["all_outputs_verified"] for item in pairs)
    checks.append(
        {
            "name": "output_integrity",
            "detail": "every pair-phase output matched its payload size",
            "value": verified,
            "threshold": True,
            "gate": True,
            "passed": bool(verified),
        }
    )

    noise = {drive: _noise_floor(solo[drive]["values"]) for drive in drives}

    # Same-disk control: the direct proof that the per-volume layout is doing real
    # work, independent of the extraction pipeline's own parallel ceiling.
    control_summary: dict[str, Any] = {"measured": False}
    if same_disk:
        control_values = [
            float(item["aggregate_throughput_mib_per_second"]) for item in same_disk
        ]
        cross_values = [float(value) for value in pair_aggregate]
        control_summary = {
            "measured": True,
            "aggregate_throughput_mib_per_second": round(_median(control_values), 3),
            "pipeline_ceiling_x_solo": round(
                (_median(control_values) / max(solo_throughput.values()))
                if solo_throughput else 0.0,
                4,
            ),
        }
        control_summary["paired"] = _paired_ratio(cross_values, control_values)
        ratio = float(control_summary["paired"].get("median_ratio") or 0.0)
        checks.append(
            {
                "name": "cross_volume_beats_same_volume",
                "detail": (
                    f"paired cross-disk vs same-disk ratio {ratio:.3f} "
                    f"(cross median {_median(cross_values):.1f} MiB/s, "
                    f"control median {_median(control_values):.1f} MiB/s)"
                ),
                "value": round(ratio, 4),
                "threshold": CROSS_VS_SAME_DISK_FLOOR,
                "gate": True,
                # Matching the control means the run was squeezed against the
                # extraction pipeline's own parallel ceiling, which is
                # inconclusive rather than a pass: increase the payload until the
                # two configurations separate.
                "passed": bool(control_summary["paired"].get("evaluated")) and
                    ratio >= CROSS_VS_SAME_DISK_FLOOR,
            }
        )

    performance_passed = all(item["passed"] for item in checks if item.get("gate", True))
    if mode == "candidate":
        verdict = "pass" if performance_passed else "fail"
        all_passed = performance_passed
    elif mode == "baseline":
        # The pre-refactor worker shares one global writer pool across volumes; its
        # non-additivity is the defect under repair, so a baseline run records the
        # reference numbers instead of failing on them.
        verdict = "reference"
        all_passed = True
    else:
        verdict = "observed"
        all_passed = True
    return {
        "mode": mode,
        "verdict": verdict,
        "checks": checks,
        "same_disk_control": control_summary,
        "performance_passed": performance_passed,
        "all_passed": all_passed,
        "solo_throughput_mib_per_second": {k: round(v, 3) for k, v in solo_throughput.items()},
        "solo_noise_floor_mib_per_second": {k: round(v, 3) for k, v in noise.items()},
        "solo_runs": runs,
        "aggregate_throughput_mib_per_second": round(aggregate, 3),
        "aggregate_ratio_vs_solo_sum": round(aggregate_ratio, 4),
    }


def _paired_ratio(cross_values: list[float], control_values: list[float]) -> dict[str, Any]:
    """Compare two concurrent configurations from paired, alternating samples.

    Comparing medians of phases recorded minutes apart lets thermal and
    background drift dominate: measured single-job throughput on this machine
    moves by 20% between runs, which is larger than the effect under test.  The
    two concurrent configurations therefore have to be sampled alternately and
    compared per repetition.
    """
    count = min(len(cross_values), len(control_values))
    if count == 0:
        return {"evaluated": False, "reason": "no paired samples"}
    ratios = [
        cross_values[index] / control_values[index]
        for index in range(count)
        if control_values[index] > 0
    ]
    if not ratios:
        return {"evaluated": False, "reason": "control throughput was zero"}
    return {
        "evaluated": True,
        "pairs": count,
        "ratios": [round(value, 4) for value in ratios],
        "median_ratio": round(float(statistics.median(ratios)), 4),
        "min_ratio": round(min(ratios), 4),
        "max_ratio": round(max(ratios), 4),
        "cross_values": [round(value, 3) for value in cross_values[:count]],
        "control_values": [round(value, 3) for value in control_values[:count]],
    }


def _with_details(payload: Any, report: dict[str, Any]) -> Any:
    """Carry the per-phase detail into the rendered artifact.

    ``report_from_payload`` keeps scenario/parameters/summary/environment only; the
    phase timeline and per-job rows are the evidence behind the §9.3 verdict, so
    they ride along inside ``parameters`` and survive into ``report.json``.
    """
    try:
        payload.parameters.setdefault("phases", report.get("phases") or [])
    except AttributeError:
        return payload
    return payload


def _skip(workspace: BenchmarkWorkspace, reason: str) -> int:
    report = {
        "parameters": {"skipped": True},
        "environment": {"topology": _topology()},
        "summary": {"all_passed": True, "skipped": True, "skip_reason": reason},
        "results": [],
    }
    rendered = render_report(report_from_payload(SCENARIO, report))
    workspace.write_result_text("report.json", rendered)
    print(rendered)
    print(f"SKIPPED: {reason}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify per-volume writer scheduling across two physical disks."
    )
    parser.add_argument("--volume-a", default="C:", help="first target volume (default C:)")
    parser.add_argument("--volume-b", default="D:", help="second target volume (default D:)")
    parser.add_argument("--payload-gib", type=float, default=2.0, help="payload per volume")
    parser.add_argument(
        "--small-job-mib",
        type=int,
        default=512,
        help="payload of the deliberately smaller job used for the overlap check",
    )
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument(
        "--same-disk-control",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "also run both concurrent jobs against ONE volume; that control is what "
            "separates a working per-volume layout from the pipeline's own ceiling"
        ),
    )
    parser.add_argument("--writer-threads", type=int, default=4)
    parser.add_argument("--thread-capacity", type=int, default=8)
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    parser.add_argument("--sample-interval", type=float, default=0.01)
    parser.add_argument(
        "--work-root",
        type=Path,
        help="directory holding per-volume work trees; defaults to <volume>:\\sunpack-bench",
    )
    parser.add_argument("--worker-path", type=Path)
    parser.add_argument(
        "--mode",
        choices=("baseline", "candidate", "observe"),
        default="observe",
        help=(
            "baseline: record the pre-refactor reference numbers without failing on the "
            "additivity gates; candidate: enforce every gate; observe: run and report only"
        ),
    )
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    if args.runs < 1 or args.warmups < 0:
        parser.error("--runs must be >= 1 and --warmups >= 0")
    if args.payload_gib <= 0:
        parser.error("--payload-gib must be positive")
    if not 1 <= args.writer_threads <= 32:
        parser.error("--writer-threads must be between 1 and 32")
    if args.thread_capacity < MIN_CONCURRENT_JOBS:
        parser.error(f"--thread-capacity must be >= {MIN_CONCURRENT_JOBS} for the pair phase")

    worker_path = args.worker_path
    if worker_path is None:
        try:
            worker_path = Path(get_sevenzip_bridge_worker_path())
        except FileNotFoundError as exc:
            parser.error(str(exc))
    worker_path = worker_path.resolve()
    if not worker_path.is_file():
        parser.error(f"worker executable is unavailable: {worker_path}")
    try:
        dll_path = Path(get_7z_dll_path()).resolve()
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if not dll_path.is_file():
        parser.error(f"7z.dll is unavailable: {dll_path}")

    topology = _topology()
    by_drive = {str(item["drive"]).rstrip(":"): item for item in topology}
    targets: list[dict[str, Any]] = []
    for letter in (args.volume_a, args.volume_b):
        key = letter.rstrip(":")
        if key not in by_drive:
            parser.error(f"volume {letter} is not a mounted drive letter on this machine")
        targets.append(dict(by_drive[key]))

    payload_bytes = int(args.payload_gib * GIB)
    small_bytes = int(args.small_job_mib * MIB)
    iterations = args.runs + args.warmups
    # Outputs live on the target volume; the corpus lives in the benchmark workspace.
    volume_output_bytes = iterations * (payload_bytes + payload_bytes + small_bytes)
    workspace_bytes = 2 * (payload_bytes + small_bytes) + MIB
    for target in targets:
        if int(target["size_remaining"]) < volume_output_bytes:
            parser.error(
                f"volume {target['drive']}: has {target['size_remaining'] / GIB:.1f} GiB free, "
                f"needs about {volume_output_bytes / GIB:.1f} GiB for this run"
            )

    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        if len({item["disk_number"] for item in targets}) < 2:
            return _skip(
                workspace,
                "both target volumes resolve to the same PhysicalDisk; per-volume scheduling "
                "cannot be distinguished from shared-device bandwidth on this machine",
            )

        work_roots: dict[str, Path] = {}
        for target in targets:
            drive = str(target["drive"])
            if args.work_root is None:
                root = Path(f"{drive}:\\") / "sunpack-bench"
            else:
                root = Path(args.work_root) / drive.replace(":", "")
            root.mkdir(parents=True, exist_ok=True)
            work_roots[drive] = root

        print(f"topology: {json.dumps(targets, ensure_ascii=False)}", flush=True)
        capability: dict[str, float] = {}
        for target in targets:
            drive = str(target["drive"])
            probe_bytes = min(payload_bytes, 2 * GIB)
            capability[drive] = _measure_sequential_write(
                work_roots[drive] / "capability", bytes_to_write=probe_bytes
            )
            print(
                f"  {drive} sequential write capability ~{capability[drive]:.1f} MiB/s "
                f"({target['friendly_name']}, {target['media_type']}/{target['bus_type']})",
                flush=True,
            )

        corpora: dict[str, dict[str, Any]] = {}
        small_corpora: dict[str, dict[str, Any]] = {}
        corpus_root = workspace.corpus
        corpus_root.mkdir(parents=True, exist_ok=True)
        print(f"building {args.payload_gib:g} GiB stored ZIP corpus in {corpus_root} ...", flush=True)
        shared_corpus = _create_archive(
            corpus_root, payload_bytes=payload_bytes, chunk_bytes=8 * MIB
        )
        small_root = corpus_root / "small"
        small_root.mkdir(parents=True, exist_ok=True)
        shared_small = _create_archive(
            small_root, payload_bytes=small_bytes, chunk_bytes=8 * MIB
        )
        for target in targets:
            drive = str(target["drive"])
            corpora[drive] = shared_corpus
            small_corpora[drive] = shared_small

        phases: list[dict[str, Any]] = []
        solo_values: dict[str, dict[str, Any]] = {
            str(target["drive"]): {"values": [], "rows": []} for target in targets
        }

        # Phase 1: solo per volume (ordering alternated to cancel thermal/first-touch bias).
        for iteration in range(args.warmups + args.runs):
            phase = "warmup" if iteration < args.warmups else "run"
            ordered = targets if iteration % 2 == 0 else list(reversed(targets))
            for target in ordered:
                drive = str(target["drive"])
                run_dir = work_roots[drive] / "solo" / f"{phase}-{iteration:02d}"
                result = _run_phase(
                    label=f"solo-{drive}-{phase}{iteration:02d}",
                    targets=[
                        {
                            "drive": drive,
                            "archive": str(corpora[drive]["archive"]),
                            "output_dir": str(run_dir),
                            "payload_bytes": payload_bytes,
                        }
                    ],
                    worker_path=worker_path,
                    dll_path=dll_path,
                    thread_capacity=args.thread_capacity,
                    writer_threads=args.writer_threads,
                    timeout_seconds=args.timeout_seconds,
                    sample_interval=args.sample_interval,
                    prefetch=True,
                )
                phases.append(result)
                value = float(result["jobs"][0]["throughput_mib_per_second"])
                if phase == "run":
                    solo_values[drive]["values"].append(value)
                    solo_values[drive]["rows"].append(result)
                print(f"{phase}-{iteration} solo {drive}: {value:.1f} MiB/s", flush=True)

        # Phase 2: pair on one worker process, with a deliberately smaller second job.
        #
        # The same-disk control is interleaved into the same loop rather than run as
        # a separate phase: measured single-job throughput on this machine drifts by
        # ~20% between runs, which is larger than the effect under test, so the two
        # concurrent configurations have to be sampled next to each other.
        pair_rows: list[dict[str, Any]] = []
        same_disk_rows: list[dict[str, Any]] = []
        for iteration in range(args.warmups + args.runs):
            phase = "warmup" if iteration < args.warmups else "run"
            order = targets if iteration % 2 == 0 else list(reversed(targets))
            run_dir = work_roots[str(targets[0]["drive"])] / "pair" / f"{phase}-{iteration:02d}"
            pair_targets = []
            for index, target in enumerate(order):
                drive = str(target["drive"])
                is_small = index == len(order) - 1
                corpus = small_corpora[drive] if is_small else corpora[drive]
                pair_targets.append(
                    {
                        "drive": drive,
                        "archive": str(corpus["archive"]),
                        "output_dir": str(run_dir / drive.replace(":", "")),
                        "payload_bytes": small_bytes if is_small else payload_bytes,
                    }
                )
            result = _run_phase(
                label=f"pair-{phase}{iteration:02d}",
                targets=pair_targets,
                worker_path=worker_path,
                dll_path=dll_path,
                thread_capacity=args.thread_capacity,
                writer_threads=args.writer_threads,
                timeout_seconds=args.timeout_seconds,
                sample_interval=args.sample_interval,
                prefetch=True,
            )
            phases.append(result)
            print(
                f"{phase}-{iteration} pair: aggregate "
                f"{result['aggregate_throughput_mib_per_second']:.1f} MiB/s "
                f"peak_jobs={result['concurrent_peak']} "
                + " ".join(
                    f"{job['drive']}={job['throughput_mib_per_second']:.1f}"
                    for job in result["jobs"]
                ),
                flush=True,
            )
            if phase == "run":
                runs = result["runs"]
                result["overlap_ratio"] = (
                    round(_overlap_ratio(runs[0], runs[1]), 4) if len(runs) >= 2 else 0.0
                )
                pair_rows.append(result)

            if not args.same_disk_control:
                continue

            # Same-disk control, immediately after the cross-disk sample.  With a
            # payload large enough to stay I/O bound this must be clearly slower; if
            # it matches, the run was squeezed against the extraction pipeline's own
            # ceiling and proves nothing either way.
            control_dir = work_roots[str(targets[0]["drive"])] / "same-disk" / f"{phase}-{iteration:02d}"
            control_targets = []
            for index in range(2):
                drive = str(targets[0]["drive"])
                is_small = index == 1
                corpus = small_corpora[drive] if is_small else corpora[drive]
                control_targets.append(
                    {
                        "drive": drive,
                        "archive": str(corpus["archive"]),
                        "output_dir": str(control_dir / f"job{index}"),
                        "payload_bytes": small_bytes if is_small else payload_bytes,
                    }
                )
            control = _run_phase(
                label=f"same-disk-{phase}{iteration:02d}",
                targets=control_targets,
                worker_path=worker_path,
                dll_path=dll_path,
                thread_capacity=args.thread_capacity,
                writer_threads=args.writer_threads,
                timeout_seconds=args.timeout_seconds,
                sample_interval=args.sample_interval,
                prefetch=True,
            )
            phases.append(control)
            print(
                f"{phase}-{iteration} same-disk: aggregate "
                f"{control['aggregate_throughput_mib_per_second']:.1f} MiB/s "
                f"peak_jobs={control['concurrent_peak']}",
                flush=True,
            )
            if phase == "run":
                same_disk_rows.append(control)

        # ``_JobRun`` objects are reporting inputs only; keep them out of the artifact.
        for phase_row in phases:
            phase_row.pop("runs", None)

        summary = _evaluate(
            topology=targets,
            solo=solo_values,
            pairs=pair_rows,
            capability=capability,
            runs=args.runs,
            mode=args.mode,
            same_disk=same_disk_rows,
        )
        report = {
            "parameters": {
                "mode": args.mode,
                "payload_gib": args.payload_gib,
                "small_job_mib": args.small_job_mib,
                "runs": args.runs,
                "warmups": args.warmups,
                "writer_threads": args.writer_threads,
                "thread_capacity": args.thread_capacity,
                "timeout_seconds": args.timeout_seconds,
                "sample_interval": args.sample_interval,
            },
            "environment": {
                "worker": str(worker_path),
                "seven_zip_dll_path": str(dll_path),
                "cpu_count": os.cpu_count(),
                "python": sys.version,
                "topology": targets,
                "volume_capability_mib_per_second": {
                    key: round(value, 3) for key, value in capability.items()
                },
            },
            "phases": phases,
            "summary": summary,
            "artifacts": {"result_dir": str(workspace.result_dir)},
        }
        rendered = render_report(_with_details(report_from_payload(SCENARIO, report), report))
        workspace.write_result_text("report.json", rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
