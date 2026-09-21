"""Measure real 7z worker CPU and IO contention."""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import psutil

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler, render_report, report_from_payload
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.support.resources import get_7z_path, get_sevenzip_bridge_worker_path
from tests.helpers.tool_config import get_7z_cli_dll_path

SCENARIO = "extraction.worker-resource-pressure"
MODES = ("cpu", "io")
CONTROLLERS = ("adaptive", "fixed")


def _csv_values(value: str, allowed: tuple[str, ...], label: str) -> list[str]:
    selected: list[str] = []
    for item in value.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if item not in allowed:
            raise ValueError(f"{label} value {item!r} is not one of: {', '.join(allowed)}")
        if item not in selected:
            selected.append(item)
    if not selected:
        raise ValueError(f"at least one {label} is required")
    return selected


def _capacities(value: str) -> list[int]:
    result: list[int] = []
    for item in value.split(","):
        capacity = int(item.strip())
        if not 1 <= capacity <= 32:
            raise ValueError("capacities must be between 1 and 32")
        if capacity not in result:
            result.append(capacity)
    if not result:
        raise ValueError("at least one capacity is required")
    return result


def _write_payload(path: Path, size_mib: int, *, repetitive: bool) -> int:
    chunk_size = 1 << 20
    if repetitive:
        block = bytes((index * 73 + (index // 257) * 11) % 251 for index in range(256 << 10))
        chunk = (block * ((chunk_size // len(block)) + 1))[:chunk_size]
    else:
        chunk = os.urandom(chunk_size)
    with path.open("wb") as stream:
        for _ in range(size_mib):
            stream.write(chunk)
    return size_mib << 20


def _create_archive(root: Path, mode: str, *, source_mib: int, dictionary_mib: int, seven_zip: Path) -> dict[str, Any]:
    source = root / f"{mode}-payload.bin"
    payload_bytes = _write_payload(source, source_mib, repetitive=mode == "cpu")
    archive = root / f"{mode}-template.7z"
    command = [str(seven_zip), "a", "-y", "-bd", "-bso0", "-bse0", "-t7z", str(archive), str(source)]
    if mode == "io":
        command.append("-mx=0")
    else:
        command.extend(["-mx=9", f"-m0=lzma2:d={dictionary_mib}m:fb=273"])
    result = subprocess.run(command, cwd=ROOT, timeout=600, check=False)
    if result.returncode != 0 or not archive.is_file():
        raise RuntimeError(f"7z archive creation failed for {mode}: exit={result.returncode}")
    archive_bytes = archive.stat().st_size
    return {
        "mode": mode,
        "template": archive,
        "payload_bytes": payload_bytes,
        "archive_bytes": archive_bytes,
        "compression_ratio": round(payload_bytes / max(1, archive_bytes), 3),
        "dictionary_bytes": dictionary_mib << 20 if mode != "io" else 0,
        "repetitive_payload": mode == "cpu",
    }


def _copy_jobs(root: Path, case: dict[str, Any], jobs: int) -> list[Path]:
    root.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for index in range(jobs):
        target = root / f"{case['mode']}-{index:04d}.7z"
        shutil.copyfile(case["template"], target)
        paths.append(target)
    return paths


def _counters(process: psutil.Process | None) -> dict[str, float | int | None]:
    if process is None:
        return {"cpu_ms": None, "read_bytes": None, "write_bytes": None}
    try:
        cpu = process.cpu_times()
        io = process.io_counters()
        return {
            "cpu_ms": (float(cpu.user) + float(cpu.system)) * 1000.0,
            "read_bytes": int(io.read_bytes),
            "write_bytes": int(io.write_bytes),
        }
    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
        return {"cpu_ms": None, "read_bytes": None, "write_bytes": None}


def _job_payload(*, job_id: str, archive: Path, output: Path) -> str:
    item: dict[str, Any] = {
        "job_id": job_id,
        "request_id": job_id,
        "archive_path": str(archive),
        "part_paths": [str(archive)],
        "output_dir": str(output),
        "password": "",
        "format_hint": "7z",
    }
    return json.dumps(item, ensure_ascii=False, separators=(",", ":"))


def _run_case(*, workspace: BenchmarkWorkspace, worker_path: Path, archives: list[Path],
              case: dict[str, Any], capacity: int, controller: str, jobs: int,
              timeout_seconds: float, sample_interval: float) -> dict[str, Any]:
    label = f"{case['mode']}-{controller}-cap{capacity}"
    worker = _NativeWorkerProcess(str(worker_path), None, {
        "thread_capacity": capacity,
        "adaptive_enabled": controller == "adaptive",
        "initial_active_jobs": 0 if controller == "adaptive" else capacity,
        "sample_interval_ms": max(100, int(sample_interval * 1000)),
    })
    process = psutil.Process(worker.process.pid) if worker.process is not None else None
    sampler = ProcessSampler(interval_seconds=0.02)
    lock = threading.Lock()
    done = threading.Condition(lock)
    events: list[dict[str, Any]] = []
    results: dict[str, dict[str, Any]] = {}
    failures: dict[str, str] = {}
    completed: set[str] = set()
    started = time.perf_counter()
    finished = started
    before = _counters(process)

    def callback(job_id: str):
        def on_line(line: str) -> bool:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return False
            if not isinstance(event, dict):
                return False
            with done:
                if event.get("type") == "native_event":
                    events.append(event)
                elif event.get("type") == "result" and str(event.get("job_id") or "") == job_id:
                    results[job_id] = event
                if job_id in results and any(
                    item.get("job_id") == job_id and item.get("event") == "job_finished" for item in events
                ):
                    completed.add(job_id)
                    done.notify_all()
                    return True
            return False
        return on_line

    def timeout(job_id: str):
        def on_timeout(message: str) -> None:
            with done:
                failures[job_id] = str(message)
                completed.add(job_id)
                done.notify_all()
        return on_timeout

    try:
        sampler.start()
        for index in range(jobs):
            job_id = f"{label}-job{index:04d}"
            worker.submit_async(
                _job_payload(
                    job_id=job_id, archive=archives[index], output=workspace.outputs / label / job_id,
                ),
                job_id, on_line=callback(job_id), on_timeout=timeout(job_id),
            )
        deadline = time.monotonic() + timeout_seconds
        with done:
            while len(completed) < jobs:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failures["batch"] = f"timed out with {jobs - len(completed)} incomplete jobs"
                    break
                done.wait(timeout=min(0.2, remaining))
                if not worker.is_alive() and len(completed) < jobs:
                    failures["worker"] = f"worker exited with {jobs - len(completed)} incomplete jobs"
                    break
        finished = time.perf_counter()
    finally:
        after = _counters(process)
        sampler.stop()
        controller_events = worker.controller_events()
        worker.close()

    elapsed = max(1e-6, finished - started)
    cpu_ms = None if before["cpu_ms"] is None or after["cpu_ms"] is None else float(after["cpu_ms"]) - float(before["cpu_ms"])
    read_bytes = None if before["read_bytes"] is None or after["read_bytes"] is None else int(after["read_bytes"]) - int(before["read_bytes"])
    write_bytes = None if before["write_bytes"] is None or after["write_bytes"] is None else int(after["write_bytes"]) - int(before["write_bytes"])
    active_values = [int(event.get("active_jobs", 0) or 0) for event in events if event.get("event") in {"job_admitted", "job_started", "job_finished"}]
    successful = sum(result.get("status") == "ok" for result in results.values())
    return {
        "label": label, "mode": case["mode"], "controller": controller, "capacity": capacity, "jobs": jobs,
        "payload_mib_total": round(int(case["payload_bytes"]) * jobs / 1024 / 1024, 3),
        "archive_mib_total": round(sum(path.stat().st_size for path in archives) / 1024 / 1024, 3),
        "compression_ratio": case["compression_ratio"], "elapsed_seconds": round(elapsed, 3),
        "jobs_per_second": round(successful / elapsed, 6), "worker_cpu_ms": None if cpu_ms is None else round(cpu_ms, 3),
        "worker_cpu_core_utilization": None if cpu_ms is None else round(cpu_ms / 1000 / elapsed, 6),
        "host_cpu_utilization": None if cpu_ms is None else round(cpu_ms / 1000 / elapsed / max(1, os.cpu_count() or 1), 6),
        "read_bytes": read_bytes,
        "read_mib_per_second": None if read_bytes is None else round(read_bytes / 1024 / 1024 / elapsed, 3),
        "write_bytes": write_bytes,
        "worker_rss_peak_mib": round(max((sample.children_rss_mib for sample in sampler.samples), default=0.0), 3),
        "observed_peak_active_jobs": max(active_values, default=0),
        "controller_sample_count": len(controller_events),
        "controller_adjustment_count": sum(
            "decision" not in item or str(item.get("decision") or "none") != "none"
            for item in controller_events
        ),
        "successful_jobs": successful, "failed_jobs": jobs - successful, "failures": failures,
        "result_statuses": [result.get("status") for result in results.values()],
        "dictionary_mib": round(int(case["dictionary_bytes"]) / 1024 / 1024, 3),
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    columns = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Stress native 7z worker CPU and IO scheduling.")
    parser.add_argument("--modes", default=",".join(MODES))
    parser.add_argument("--controllers", default=",".join(CONTROLLERS))
    parser.add_argument("--capacities", default="1,2,4,8")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--cpu-source-mib", type=int, default=64)
    parser.add_argument("--io-source-mib", type=int, default=128)
    parser.add_argument("--dictionary-mib", type=int, default=64)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--sample-interval", type=float, default=0.02)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    try:
        modes = _csv_values(args.modes, MODES, "mode")
        controllers = _csv_values(args.controllers, CONTROLLERS, "controller")
        capacities = _capacities(args.capacities)
    except (ValueError, TypeError) as exc:
        parser.error(str(exc))
    sizes = (args.cpu_source_mib, args.io_source_mib, args.dictionary_mib)
    if args.jobs < 1 or args.timeout_seconds <= 0 or args.sample_interval <= 0 or min(sizes) < 1:
        parser.error("jobs, timeouts, intervals, and size parameters must be positive")
    try:
        worker_path = Path(get_sevenzip_bridge_worker_path()).resolve()
        dll = Path(get_7z_cli_dll_path()).resolve()
        seven_zip = Path(get_7z_path()).resolve()
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if not worker_path.is_file() or not dll.is_file() or not seven_zip.is_file():
        parser.error("native worker, 7z.dll, or 7z.exe is unavailable")

    with BenchmarkWorkspace(SCENARIO, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        cases: dict[str, dict[str, Any]] = {}
        settings = {"cpu": (args.cpu_source_mib, args.dictionary_mib), "io": (args.io_source_mib, 0)}
        for mode in modes:
            print(f"building {mode} archive ...", flush=True)
            cases[mode] = _create_archive(workspace.corpus, mode, source_mib=settings[mode][0], dictionary_mib=settings[mode][1], seven_zip=seven_zip)
            case = cases[mode]
            print(f"  payload={case['payload_bytes'] / 1024 / 1024:.1f} MiB archive={case['archive_bytes'] / 1024 / 1024:.1f} MiB ratio={case['compression_ratio']:.2f}", flush=True)

        rows: list[dict[str, Any]] = []
        for mode in modes:
            case = cases[mode]
            archives = _copy_jobs(workspace.corpus / "jobs", case, args.jobs)
            for controller in controllers:
                for capacity in capacities:
                    print(f"running {mode}/{controller}/capacity={capacity} ...", flush=True)
                    row = _run_case(
                        workspace=workspace, worker_path=worker_path, archives=archives, case=case,
                        capacity=capacity, controller=controller, jobs=args.jobs, timeout_seconds=args.timeout_seconds,
                        sample_interval=args.sample_interval,
                    )
                    rows.append(row)
                    print(f"  elapsed={row['elapsed_seconds']:.2f}s host_cpu={row['host_cpu_utilization']} read={row['read_mib_per_second']}MiB/s rss={row['worker_rss_peak_mib']}MiB active={row['observed_peak_active_jobs']} passed={row['successful_jobs']}/{args.jobs}", flush=True)
            if not workspace.keep_workdir:
                for path in archives:
                    path.unlink(missing_ok=True)

        report = {
            "parameters": vars(args) | {"modes": modes, "controllers": controllers, "capacities": capacities},
            "environment": {"worker_path": str(worker_path), "seven_zip_path": str(seven_zip), "cpu_count": os.cpu_count(), "python": sys.version},
            "corpus": {mode: {key: value for key, value in case.items() if key != "template"} for mode, case in cases.items()},
            "results": rows,
            "summary": {"rows": len(rows), "all_jobs_completed": all(row["successful_jobs"] == args.jobs for row in rows)},
        }
        rendered = render_report(report_from_payload(SCENARIO, report))
        workspace.write_result_text("report.json", rendered)
        _write_csv(workspace.result_dir / "results.csv", rows)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
