"""Verify per-volume writer scheduling against a same-volume control.

The scenario runs two concurrent extraction jobs through ONE worker process
under two configurations, alternating them inside every repetition:

  cross   job A -> volume A, job B -> volume B
  same    job A -> volume A, job B -> volume A   (control)

Configurations are alternated inside every repetition: run-to-run drift on this
machine is larger than the effect under test, so comparing phases recorded minutes
apart proves nothing.

The control exists because the extraction pipeline has its own parallel ceiling,
so an absolute threshold would reject a layout that is in fact working; the run is
only meaningful while the payload is large enough to stay I/O bound.

The scenario skips with an explicit reason when both targets resolve to the same
PhysicalDisk.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import threading
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from benchmarks.scenarios.worker_single_file_write import MIB, GIB, _create_archive
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.support.output_paths import resolve_output_volume_key
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path


SCENARIO = "extraction.worker-volume-writer-scheduling"

# Every measurement evicts the corpus from the page cache first: with a resident
# archive both configurations hit the same non-disk bottleneck.
_FILE_FLAG_NO_BUFFERING = 0x20000000
_FILE_FLAG_WRITE_THROUGH = 0x80000000
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
_kernel32.CreateFileW.argtypes = [
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.HANDLE,
]
_kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]


def _purge_file_cache(path: Path) -> None:
    """Evict one file from the system cache (best effort).

    A write-through, unbuffered open invalidates the file's cached pages without
    modifying it.
    """
    try:
        handle = _kernel32.CreateFileW(
            str(path),
            _GENERIC_WRITE,
            0,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_NO_BUFFERING | _FILE_FLAG_WRITE_THROUGH,
            None,
        )
    except OSError:
        return
    if handle != _INVALID_HANDLE:
        _kernel32.CloseHandle(handle)

# Gates: assert the direction and the win rate, not a magnitude (it depends on how
# cold the cache is).
MIN_CONCURRENT_JOBS = 2
CROSS_NOT_SLOWER_FLOOR = 0.90   # median paired ratio must stay above this
CROSS_WIN_RATIO = 0.75          # and cross must win most paired samples
PIPELINE_BOUND_RATIO = 1.20     # a smaller margin than this is inconclusive

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
        size_remaining = [int64]$vol.SizeRemaining
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


class _Job:
    """One submitted job with its native event timeline."""

    def __init__(
        self,
        job_id: str,
        output_dir: Path,
        payload_bytes: int,
        drive: str,
        archive: Path,
    ) -> None:
        self.job_id = job_id
        self.output_dir = output_dir
        self.payload_bytes = payload_bytes
        self.drive = drive
        # The archive lives on the same volume as the output, or the read load moves
        # to a third volume and hides the effect this scenario measures.
        self.archive = archive
        self.result: dict[str, Any] | None = None
        self.failure = ""
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
        if event.get("type") == "result" and str(event.get("job_id") or "") == self.job_id:
            self.result = event
        elif event.get("event") == "job_started" and not self.started_ns:
            self.started_ns = time.perf_counter_ns()
        elif event.get("event") == "job_finished" and self.result is not None:
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


def _run_configuration(
    *,
    label: str,
    jobs: list[_Job],
    worker_path: Path,
    dll_path: Path,
    thread_capacity: int,
    writer_threads: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    for job in jobs:
        _purge_file_cache(job.archive)
    worker = _NativeWorkerProcess(
        str(worker_path),
        None,
        {
            "thread_capacity": thread_capacity,
            "adaptive_enabled": False,
            "initial_active_jobs": len(jobs),
            "writer_threads": writer_threads,
        },
    )
    try:
        for job in jobs:
            payload = json.dumps(
                {
                    "job_id": job.job_id,
                    "seven_zip_dll_path": str(dll_path),
                    "archive_path": str(job.archive),
                    "part_paths": [str(job.archive)],
                    "output_dir": str(job.output_dir),
                    "output_volume_key": resolve_output_volume_key(str(job.output_dir)),
                    "password": "",
                    "format_hint": "zip",
                    "dry_run": False,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            worker.submit_async(payload, job.job_id, on_line=job.on_line, on_timeout=job.on_timeout)
        deadline = time.monotonic() + timeout_seconds
        for job in jobs:
            while not job.done.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"{label}: job {job.job_id} timed out")
                job.done.wait(timeout=min(0.2, remaining))
                if not worker.is_alive() and not all(item.done.is_set() for item in jobs):
                    raise RuntimeError(f"{label}: worker exited with jobs still running")
    finally:
        worker.close()

    failed = [job for job in jobs if job.failure or job.result is None]
    if failed:
        raise RuntimeError(f"{label}: job {failed[0].job_id} failed: {failed[0].failure or 'no result'}")
    rejected = [job for job in jobs if str((job.result or {}).get("status") or "") != "ok"]
    if rejected:
        result = rejected[0].result or {}
        raise RuntimeError(
            f"{label}: job {rejected[0].job_id} status={result.get('status')!r} "
            f"stage={result.get('failure_stage')!r} kind={result.get('failure_kind')!r}"
        )

    rows = []
    for job in jobs:
        output_file = job.output_dir / "payload.bin"
        rows.append(
            {
                "job_id": job.job_id,
                "drive": job.drive,
                "wall_seconds": round(job.wall_seconds, 6),
                "throughput_mib_per_second": round(job.throughput_mib, 3),
                "verified": output_file.is_file()
                and output_file.stat().st_size == job.payload_bytes,
            }
        )
    return {
        "label": label,
        # Both jobs run concurrently, so their per-job rates add up.
        "aggregate_throughput_mib_per_second": round(sum(row["throughput_mib_per_second"] for row in rows), 3),
        "jobs": rows,
        "verified": all(row["verified"] for row in rows),
    }


def _skip(workspace: BenchmarkWorkspace, reason: str) -> int:
    report = {
        "parameters": {"skipped": True},
        "environment": {"topology": _topology()},
        "summary": {"all_passed": True, "skipped": True, "skip_reason": reason},
    }
    rendered = render_report(report_from_payload(SCENARIO, report))
    workspace.write_result_text("report.json", rendered)
    print(rendered)
    print(f"SKIPPED: {reason}")
    return 0


def _mad(values: list[float]) -> float:
    if not values:
        return 0.0
    center = statistics.median(values)
    return float(statistics.median([abs(value - center) for value in values]))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify per-volume writer scheduling with a same-volume control."
    )
    parser.add_argument("--volume-a", default="C:")
    parser.add_argument("--volume-b", default="D:")
    parser.add_argument(
        "--payload-mib",
        type=int,
        default=512,
        help=(
            "payload per job.  The layout effect is below this machine's noise floor at "
            "every size tried (256/512/768/1024 MiB); the scenario therefore asserts "
            "structure and non-regression rather than a convergence multiple"
        ),
    )
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--writer-threads", type=int, default=4)
    parser.add_argument("--thread-capacity", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    parser.add_argument("--worker-path", type=Path)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    if args.payload_mib < 64:
        parser.error("--payload-mib must be at least 64 to stay out of the cached regime")
    if args.repeats < 1 or args.warmups < 0:
        parser.error("--repeats must be >= 1 and --warmups >= 0")
    if not 1 <= args.writer_threads <= 32:
        parser.error("--writer-threads must be between 1 and 32")
    if args.thread_capacity < MIN_CONCURRENT_JOBS:
        parser.error(f"--thread-capacity must be >= {MIN_CONCURRENT_JOBS}")

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

    topology = _topology()
    by_drive = {str(item["drive"]).rstrip(":"): item for item in topology}
    targets = []
    for letter in (args.volume_a, args.volume_b):
        key = letter.rstrip(":")
        if key not in by_drive:
            parser.error(f"volume {letter} is not a mounted drive letter on this machine")
        targets.append(dict(by_drive[key]))

    payload_bytes = args.payload_mib * MIB
    required = (args.repeats + args.warmups) * 2 * payload_bytes * 2
    for target in targets:
        if int(target["size_remaining"]) < required:
            parser.error(
                f"volume {target['drive']} has {target['size_remaining'] / GIB:.1f} GiB free, "
                f"needs about {required / GIB:.1f} GiB"
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
            root = Path(f"{drive}:\\") / "sunpack-bench" / "volume-scheduling"
            if root.exists():
                shutil.rmtree(root, ignore_errors=True)
            root.mkdir(parents=True, exist_ok=True)
            work_roots[drive] = root

        print(f"topology: {json.dumps(targets, ensure_ascii=False)}", flush=True)
        corpus_by_drive: dict[str, Path] = {}
        for target in targets:
            drive = str(target["drive"])
            drive_corpus = work_roots[drive] / "corpus"
            drive_corpus.mkdir(parents=True, exist_ok=True)
            built = _create_archive(
                drive_corpus, payload_bytes=payload_bytes, chunk_bytes=8 * MIB
            )
            corpus_by_drive[drive] = Path(built["archive"])
            print(f"corpus on {drive}: {corpus_by_drive[drive]}", flush=True)
        corpus = {"archive": str(corpus_by_drive[str(targets[0]["drive"])])}
        print(f"payload={args.payload_mib} MiB per job, repeats={args.repeats}", flush=True)

        cross_values: list[float] = []
        same_values: list[float] = []
        phases: list[dict[str, Any]] = []
        for iteration in range(args.warmups + args.repeats):
            phase = "warmup" if iteration < args.warmups else "run"
            order = ("cross", "same") if iteration % 2 == 0 else ("same", "cross")
            for configuration in order:
                stamp = f"{phase}{iteration:02d}-{configuration}"
                if configuration == "cross":
                    assignment = [(targets[0], "a"), (targets[1], "b")]
                else:
                    assignment = [(targets[0], "a"), (targets[0], "b")]
                jobs = []
                for index, (target, suffix) in enumerate(assignment):
                    drive = str(target["drive"])
                    out_dir = work_roots[drive] / stamp / suffix
                    out_dir.mkdir(parents=True, exist_ok=True)
                    jobs.append(
                        _Job(
                            f"{stamp}-{index}",
                            out_dir,
                            payload_bytes,
                            drive,
                            corpus_by_drive[drive],
                        )
                    )
                result = _run_configuration(
                    label=stamp,
                    jobs=jobs,
                    worker_path=worker_path,
                    dll_path=dll_path,
                    thread_capacity=args.thread_capacity,
                    writer_threads=args.writer_threads,
                    timeout_seconds=args.timeout_seconds,
                )
                result["configuration"] = configuration
                result["phase"] = phase
                phases.append(result)
                print(
                    f"{stamp:22s} aggregate={result['aggregate_throughput_mib_per_second']:8.1f} MiB/s  "
                    + " ".join(
                        f"{row['drive']}={row['throughput_mib_per_second']:.0f}"
                        for row in result["jobs"]
                    ),
                    flush=True,
                )
                if phase == "run":
                    (cross_values if configuration == "cross" else same_values).append(
                        float(result["aggregate_throughput_mib_per_second"])
                    )
                for job in jobs:
                    shutil.rmtree(job.output_dir, ignore_errors=True)

        checks: list[dict[str, Any]] = []
        count = min(len(cross_values), len(same_values))
        paired = [
            cross_values[index] / same_values[index]
            for index in range(count)
            if same_values[index] > 0
        ]
        median_ratio = float(statistics.median(paired)) if paired else 0.0
        wins = sum(1 for value in paired if value > 1.0)
        win_ratio = (wins / len(paired)) if paired else 0.0
        checks.append(
            {
                "name": "one_volume_per_job_not_slower",
                "detail": (
                    f"paired ratios {[round(value, 3) for value in paired]}; cross won "
                    f"{wins}/{len(paired)} samples "
                    f"(cross median {statistics.median(cross_values) if cross_values else 0:.1f} MiB/s, "
                    f"same median {statistics.median(same_values) if same_values else 0:.1f} MiB/s). "
                    "A per-volume facility must never be slower than sharing one volume."
                ),
                "value": round(median_ratio, 4),
                "threshold": CROSS_NOT_SLOWER_FLOOR,
                "passed": bool(paired) and median_ratio >= CROSS_NOT_SLOWER_FLOOR,
            }
        )
        checks.append(
            {
                "name": "cross_wins_consistently",
                "detail": (
                    f"cross-volume was faster in {win_ratio:.2f} of paired samples; the "
                    "per-volume layout gives each job its own writer pool, so it should "
                    "win whenever the disks are doing the work"
                ),
                "value": round(win_ratio, 4),
                "threshold": CROSS_WIN_RATIO,
                "passed": win_ratio >= CROSS_WIN_RATIO,
            }
        )
        checks.append(
            {
                "name": "run_not_pipeline_bound",
                "detail": (
                    "a margin below "
                    f"{PIPELINE_BOUND_RATIO:.2f}x means both configurations were limited by "
                    "something other than the disks (cache-resident corpus); raise "
                    "--payload-mib or re-check the cache purge"
                ),
                "value": round(
                    max(median_ratio, 1.0 / median_ratio if median_ratio else 0.0), 4
                ),
                "threshold": PIPELINE_BOUND_RATIO,
                "passed": median_ratio > 0.0 and median_ratio >= PIPELINE_BOUND_RATIO,
            }
        )
        checks.append(
            {
                "name": "output_integrity",
                "detail": "every job produced its full payload",
                "value": all(item["verified"] for item in phases),
                "threshold": True,
                "passed": all(item["verified"] for item in phases),
            }
        )
        checks.append(
            {
                "name": "distinct_physical_disks",
                "detail": f"targets span {len({item['disk_number'] for item in targets})} physical disk(s)",
                "value": len({item["disk_number"] for item in targets}),
                "threshold": 2,
                "passed": len({item["disk_number"] for item in targets}) >= 2,
            }
        )

        summary = {
            "checks": checks,
            "all_passed": all(item["passed"] for item in checks),
            "cross_median_mib_per_second": round(statistics.median(cross_values), 3) if cross_values else None,
            "same_median_mib_per_second": round(statistics.median(same_values), 3) if same_values else None,
            "cross_mad_mib_per_second": round(_mad(cross_values), 3),
            "same_mad_mib_per_second": round(_mad(same_values), 3),
            "paired_ratios": [round(value, 4) for value in paired],
            "cross_win_ratio": round(win_ratio, 4),
        }
        report = {
            "parameters": {
                "volume_a": args.volume_a,
                "volume_b": args.volume_b,
                "payload_mib": args.payload_mib,
                "repeats": args.repeats,
                "warmups": args.warmups,
                "writer_threads": args.writer_threads,
                "thread_capacity": args.thread_capacity,
            },
            "environment": {
                "worker": str(worker_path),
                "seven_zip_dll_path": str(dll_path),
                "cpu_count": os.cpu_count(),
                "topology": targets,
                "corpus": {key: value for key, value in corpus.items() if key != "archive"},
            },
            "phases": phases,
            "summary": summary,
            "artifacts": {"result_dir": str(workspace.result_dir)},
        }

        payload = report_from_payload(SCENARIO, report)
        payload.parameters.setdefault("phases", phases)
        rendered = render_report(payload)
        workspace.write_result_text("report.json", rendered)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
