"""Measure end-to-end extraction time and peak process-tree RSS.

This benchmark intentionally runs each extractor in a fresh subprocess.  RSS is
sampled for the parent and all descendants, so persistent/native 7-Zip workers
are included instead of only measuring the Python coordinator process.
"""
from __future__ import annotations

import argparse
import os
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

import psutil

from benchmarks.harness import benchmark_temp_dir, render_report, report_from_payload


ROOT = Path(__file__).resolve().parents[2]


def output_summary(root: Path) -> dict:
    file_count = 0
    total_bytes = 0
    extensions: dict[str, int] = {}
    sample_paths: list[str] = []
    for directory, _dirs, files in os.walk(root):
        for name in files:
            path = Path(directory, name)
            try:
                total_bytes += path.stat().st_size
                file_count += 1
                extension = path.suffix.lower() or "<none>"
                extensions[extension] = extensions.get(extension, 0) + 1
                if len(sample_paths) < 20:
                    sample_paths.append(path.relative_to(root).as_posix())
            except OSError:
                pass
    return {
        "file_count": file_count,
        "total_bytes": total_bytes,
        "extensions": dict(sorted(extensions.items())),
        "sample_paths": sample_paths,
    }


def sunpack_service_processes() -> list[psutil.Process]:
    """Find the long-lived persistent server and the native 7z worker.

    ``sunpack extract`` now delegates to a persistent server process; the CLI
    client only waits for the streamed response.  The benchmark therefore has
    to include the server (and its seven-zip worker child) in RSS accounting
    explicitly, because the server may outlive the client process.
    """
    members = []
    for process in psutil.process_iter(("name", "cmdline")):
        try:
            name = (process.info["name"] or "").lower()
            command = " ".join(process.info["cmdline"] or []).lower()
            is_server = (
                "sunpack.py" in command and "--persistent-server" in command
            ) or ("-m sunpack" in command and "--persistent-server" in command)
            if name == "sunpack_sevenzip_worker.exe" or is_server:
                members.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return members


def rss_for(processes: list[psutil.Process]) -> tuple[int, int]:
    rss = 0
    live = 0
    seen: set[int] = set()
    for process in processes:
        if process.pid in seen:
            continue
        seen.add(process.pid)
        try:
            rss += process.memory_info().rss
            live += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return rss, live


def _shutdown_persistent_server() -> None:
    """Best-effort shutdown of the persistent server after a timed-out run."""
    try:
        subprocess.run(
            [sys.executable, "-m", "sunpack", "--persistent-shutdown"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10.0,
        )
    except Exception:
        pass


def _terminate_process_tree(process: subprocess.Popen) -> None:
    try:
        root = psutil.Process(process.pid)
        for child in root.children(recursive=True):
            try:
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        root.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        try:
            process.kill()
        except Exception:
            pass


def run_measured(command: list[str], output_dir: Path, sample_ms: int, timeout_seconds: float) -> dict:
    # The first psutil walk with per-process cmdline can take >1s on a busy
    # host (hundreds of processes), so it runs once here, before the client is
    # spawned and outside the measured window.  The sampling loop below then
    # only does cheap pid-liveness checks on the known service set.
    services_baseline = sunpack_service_processes()
    idle_service_rss, idle_service_count = rss_for(services_baseline)
    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    root_process = psutil.Process(process.pid)
    peak_tree_rss = 0
    peak_process_count = 0
    samples = 0
    timed_out = False

    while process.poll() is None:
        if time.perf_counter() - started > timeout_seconds:
            timed_out = True
            break
        try:
            members = [root_process, *root_process.children(recursive=True)]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            members = []
        for service in services_baseline:
            try:
                if not service.is_running():
                    continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            members.append(service)
            try:
                members.extend(service.children(recursive=True))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        tree_rss, live_count = rss_for(members)
        peak_tree_rss = max(peak_tree_rss, tree_rss)
        peak_process_count = max(peak_process_count, live_count)
        samples += 1
        time.sleep(sample_ms / 1000)

    elapsed = time.perf_counter() - started
    if timed_out:
        _terminate_process_tree(process)
        process.wait(timeout=5)
        # The extraction ran in the persistent server; shut it down so the
        # next run starts from a clean, measurable baseline.
        _shutdown_persistent_server()
    return {
        "exit_code": -124 if timed_out else process.returncode,
        "timed_out": timed_out,
        "timeout_seconds": timeout_seconds,
        "elapsed_seconds": elapsed,
        "peak_tree_rss_bytes": peak_tree_rss,
        "peak_tree_rss_mib": peak_tree_rss / 1024**2,
        "idle_service_rss_bytes": idle_service_rss,
        "idle_service_rss_mib": idle_service_rss / 1024**2,
        "incremental_peak_rss_mib": max(0, peak_tree_rss - idle_service_rss) / 1024**2,
        "idle_service_process_count": idle_service_count,
        "peak_process_count": peak_process_count,
        "rss_samples": samples,
        "output": output_summary(output_dir),
    }


def command_for(archive: Path, output: Path, password: str, recursive: str) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "sunpack",
        "extract",
        "--direct-file",
        "--recur",
        recursive,
        "--cleanup",
        "k",
        "--no-flatten",
        "--no-builtin-pw",
        "--no-dir-pw",
        "--quiet",
        "--no-pause",
        "-o",
        str(output),
    ]
    if password:
        command.extend(["--password", password])
    return [*command, str(archive)]


def median_success(rows: list[dict], field: str) -> float | None:
    values = [float(row[field]) for row in rows if row["exit_code"] == 0]
    return statistics.median(values) if values else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--password", default="")
    parser.add_argument("--recursive", default="*", help="SunPack recursive extraction mode (default: *)")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--sample-ms", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=600.0, help="Per-run wall-clock timeout in seconds.")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()

    archive = args.archive.resolve()
    if not archive.is_file():
        parser.error(f"archive does not exist: {archive}")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    owned_temp: Path | None = None
    if args.work_dir:
        work = args.work_dir.resolve()
        work.mkdir(parents=True, exist_ok=True)
    else:
        owned_temp = benchmark_temp_dir("sunpack-real-extract-")
        work = owned_temp

    rows: list[dict] = []
    try:
        for run in range(max(1, args.runs)):
            output = work / f"sunpack-{run}"
            shutil.rmtree(output, ignore_errors=True)
            output.mkdir(parents=True)
            row = run_measured(
                command_for(archive, output, args.password, args.recursive),
                output,
                max(1, args.sample_ms),
                args.timeout,
            )
            row["run"] = run + 1
            rows.append(row)
            shutil.rmtree(output, ignore_errors=True)
    finally:
        if owned_temp is not None:
            shutil.rmtree(owned_temp, ignore_errors=True)

    report = {
        "schema_version": 1,
        "archive": {"path": str(archive), "bytes": archive.stat().st_size},
        "sunpack_recursive_mode": args.recursive,
        "environment": {
            "python": sys.version,
            "platform": sys.platform,
            "cpu_count": os.cpu_count(),
            "rss_sample_interval_ms": max(1, args.sample_ms),
            "per_run_timeout_seconds": args.timeout,
        },
        "runs": {"sunpack": rows},
        "summary": {
            "sunpack": {
                "successful_runs": sum(row["exit_code"] == 0 for row in rows),
                "timed_out_runs": sum(bool(row.get("timed_out")) for row in rows),
                "median_elapsed_seconds": median_success(rows, "elapsed_seconds"),
                "median_peak_tree_rss_mib": median_success(rows, "peak_tree_rss_mib"),
                "median_incremental_peak_rss_mib": median_success(rows, "incremental_peak_rss_mib"),
                "outputs_consistent": len({
                    (row["output"]["file_count"], row["output"]["total_bytes"])
                    for row in rows if row["exit_code"] == 0
                }) <= 1,
            }
        },
    }
    rendered = render_report(report_from_payload("extraction.real-archive", report))
    print(rendered)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered, encoding="utf-8")
    return 0 if all(row["exit_code"] == 0 for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
