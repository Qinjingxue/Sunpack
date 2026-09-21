"""Reproduce the 300 MiB native-worker versus 7z.exe benchmark.

The benchmark intentionally measures two different user-facing execution models:
the persistent SunPack native worker and a fresh ``7z.exe x`` process.  It also
records the generated archive catalog (method, solid mode, volume layout, and
compression ratio) plus machine and binary fingerprints, so a result can be
compared without guessing what was actually tested.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler
from benchmarks.scenarios.extraction_format_matrix import GENERATED_FORMATS
from benchmarks.scenarios.sevenzip_worker_matrix import (
    _case_job,
    _output_summary,
    _run_job,
    _volume_paths,
)
from benchmarks.scenarios.worker_read_patterns import _build_cases
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.support.resources import get_sevenzip_bridge_worker_path
from tests.helpers.tool_config import get_7z_cli_dll_path, require_7z


MIB = 1024 * 1024
DEFAULT_FORMATS = (*GENERATED_FORMATS, "rar4")
DEFAULT_SMALL_FILES = 8
DEFAULT_LARGE_FILES = 2
DEFAULT_LARGE_FILE_MIB = 150
DEFAULT_RUNS = 5
DEFAULT_TIMEOUT_SECONDS = 900.0

METHODS = {
    "7z-split": ("LZMA2 (7-Zip default)", "solid default; -v16m", "16 MiB volumes"),
    "7z:solid": ("LZMA2", "solid (-ms=on)", "single volume"),
    "7z:non-solid": ("LZMA2", "non-solid (-ms=off)", "single volume"),
    "zip": ("Deflate (7-Zip default)", "standard ZIP", "single volume"),
    "rar": ("RAR5 default method", "standard RAR5", "single volume"),
    "rar:solid": ("RAR5 default method", "solid (-s)", "single volume"),
    "rar:non-solid": ("RAR5 default method", "non-solid (-s-)", "single volume"),
    "rar-split": ("RAR5 default method", "solid/default; -v16m", "16 MiB volumes"),
    "rar4:solid": ("RAR4 default method", "solid (-ma4 -s)", "single volume"),
    "rar4:non-solid": ("RAR4 default method", "non-solid (-ma4 -s-)", "single volume"),
    "tar": ("none", "uncompressed TAR", "single volume"),
    "gz": ("Deflate over TAR", "7-Zip gzip default", "single compressed TAR stream"),
    "tgz": ("Deflate over TAR", "same bytes as .tar.gz", "single compressed TAR stream"),
    "bz2": ("BZip2 over TAR", "7-Zip bzip2 default", "single compressed TAR stream"),
    "tbz2": ("BZip2 over TAR", "same bytes as .tar.bz2", "single compressed TAR stream"),
    "xz": ("LZMA2 over TAR", "7-Zip xz default", "single compressed TAR stream"),
    "txz": ("LZMA2 over TAR", "same bytes as .tar.xz", "single compressed TAR stream"),
    "zst": ("Zstandard over TAR", "zstd level 3", "single compressed TAR stream"),
    "tzst": ("Zstandard over TAR", "same bytes as .tar.zst", "single compressed TAR stream"),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None


def _tool_info(path: Path, *, query_version: bool = False) -> dict[str, Any]:
    info: dict[str, Any] = {
        "path": str(path),
        "file_size_bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }
    if query_version:
        try:
            result = subprocess.run(
                [str(path), "i"],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=30,
            )
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            info["version_line"] = next((line for line in lines if line.startswith("7-Zip ")), None)
            info["version_probe_returncode"] = result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            info["version_probe_error"] = repr(exc)
    return info


def _powershell_json(script: str) -> Any:
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _collect_environment(workspace_root: Path) -> dict[str, Any]:
    environment: dict[str, Any] = {
        "platform": platform.platform(),
        "python": sys.version,
        "machine": platform.machine(),
        "cpu_model_fallback": platform.processor(),
        "logical_processors": os.cpu_count(),
        "physical_cores": psutil.cpu_count(logical=False),
        "memory_total_bytes": psutil.virtual_memory().total,
        "workspace_drive": workspace_root.drive or None,
        "workspace_disk_usage": {
            key: value
            for key, value in zip(
                ("total_bytes", "used_bytes", "free_bytes"),
                shutil.disk_usage(workspace_root),
            )
        },
    }
    ps_script = r'''
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 Name,Manufacturer,MaxClockSpeed,NumberOfCores,NumberOfLogicalProcessors
$computer = Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,@{N='TotalMemoryBytes';E={$_.TotalPhysicalMemory}}
$os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture
$volumes = @(Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter,FileSystem,FileSystemLabel,Size,SizeRemaining)
$disks = @(Get-PhysicalDisk | Select-Object FriendlyName,MediaType,BusType,Size,HealthStatus)
[pscustomobject]@{cpu=$cpu; computer=$computer; os=$os; volumes=$volumes; physical_disks=$disks} | ConvertTo-Json -Depth 5 -Compress
'''
    native = _powershell_json(ps_script)
    if native is not None:
        environment["windows_system_inventory"] = native
    try:
        power = subprocess.run(
            ["powercfg.exe", "/getactivescheme"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=10,
        )
        environment["active_power_scheme"] = power.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return environment


def _seven_zip_listing(seven_zip: Path, archive: Path) -> dict[str, Any]:
    """Capture stable archive properties from the same 7z.exe fixture."""
    wanted = {"Type", "Method", "Solid", "Blocks", "Volumes", "Physical Size", "Headers Size", "Encrypted"}
    try:
        result = subprocess.run(
            [str(seven_zip), "l", "-slt", str(archive)],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": repr(exc)}
    values: dict[str, list[str]] = {}
    for line in result.stdout.splitlines():
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        if key in wanted:
            values.setdefault(key, [])
            if value not in values[key] and len(values[key]) < 8:
                values[key].append(value)
    return {"returncode": result.returncode, "properties": values, "stderr": result.stderr[-1000:]}


def _case_descriptor(case: dict[str, Any], seven_zip: Path) -> dict[str, Any]:
    fmt = str(case["format"])
    variant = str(case.get("variant") or "standard")
    method, mode, layout = METHODS.get(f"{fmt}:{variant}", METHODS.get(fmt, ("tool default", variant, "single volume")))
    volumes = _volume_paths(case["item"])
    archive_bytes = sum(path.stat().st_size for path in volumes if path.is_file())
    payload_bytes = int(case.get("payload_bytes") or 0)
    first_volume = volumes[0]
    return {
        "case_id": case["case_id"],
        "format": fmt,
        "variant": variant,
        "payload_files": 2,
        "payload_bytes": payload_bytes,
        "payload_shape": "1 x 150 MiB deterministic repeated text + 1 x 150 MiB deterministic random bytes",
        "archive_paths": [str(path) for path in volumes],
        "archive_bytes_total": archive_bytes,
        "archive_volume_bytes": [path.stat().st_size for path in volumes if path.is_file()],
        "volume_count": len(volumes),
        "compression_ratio_payload_over_archive": round(payload_bytes / archive_bytes, 6) if archive_bytes else None,
        "archive_fraction_of_payload_percent": round(archive_bytes * 100.0 / payload_bytes, 6) if payload_bytes else None,
        "compression_method": method,
        "compression_mode": mode,
        "layout": layout,
        "archive_listing": _seven_zip_listing(seven_zip, first_volume),
    }


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 3) if values else None


def _run_worker_case(
    case: dict[str, Any],
    *,
    workspace: BenchmarkWorkspace,
    worker_path: Path,
    dll_path: Path,
    runs: int,
    warmups: int,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    worker = _NativeWorkerProcess(str(worker_path), None)
    sampler = ProcessSampler(interval_seconds=0.02)
    rows: list[dict[str, Any]] = []
    case_slug = str(case["case_id"]).replace(":", "-")
    try:
        sampler.start()
        for run in range(warmups):
            output = workspace.outputs / case_slug / f"worker-warmup-{run}"
            try:
                _run_job(
                    worker,
                    _case_job(case["item"], job_id=f"{case_slug}-worker-warmup-{run}", output_dir=output, dll_path=dll_path),
                    timeout_seconds=timeout_seconds,
                    sampler=sampler,
                )
            finally:
                shutil.rmtree(output, ignore_errors=True)
        for run in range(runs):
            output = workspace.outputs / case_slug / f"worker-run-{run}"
            try:
                row = _run_job(
                    worker,
                    _case_job(case["item"], job_id=f"{case_slug}-worker-{run}", output_dir=output, dll_path=dll_path),
                    timeout_seconds=timeout_seconds,
                    sampler=sampler,
                )
                row["run"] = run
                rows.append(row)
            finally:
                shutil.rmtree(output, ignore_errors=True)
    finally:
        sampler.stop()
        worker.close()
    return rows


def _run_seven_zip_case(
    case: dict[str, Any],
    *,
    workspace: BenchmarkWorkspace,
    seven_zip: Path,
    runs: int,
    warmups: int,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    case_slug = str(case["case_id"]).replace(":", "-")
    archive = _volume_paths(case["item"])[0]
    for run in range(warmups + runs):
        output = workspace.outputs / case_slug / f"seven-zip-{run}"
        started = time.perf_counter_ns()
        try:
            completed = subprocess.run(
                [str(seven_zip), "x", "-y", "-bd", "-bso0", "-bse0", "-aoa", f"-o{output}", str(archive)],
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=timeout_seconds,
            )
            wall_ms = round((time.perf_counter_ns() - started) / 1_000_000.0, 3)
            if run >= warmups:
                stats = _output_summary(output)
                rows.append({
                    "run": run - warmups,
                    "wall_ms": wall_ms,
                    "returncode": completed.returncode,
                    "passed": completed.returncode == 0,
                    "files": stats["file_count"],
                    "bytes": stats["total_bytes"],
                    "stderr": completed.stderr[-2000:],
                })
        finally:
            shutil.rmtree(output, ignore_errors=True)
    return rows


def _table(results: list[dict[str, Any]]) -> str:
    lines = ["case | worker median ms | 7z.exe median ms | worker/7z", "---|---:|---:|---:"]
    for case in results:
        worker = _median([float(row["worker_wall_ms"]) for row in case.get("worker", [])])
        seven = _median([float(row["wall_ms"]) for row in case.get("seven_zip", [])])
        ratio = worker / seven if worker is not None and seven else None
        lines.append(f"{case['case_id']} | {worker or 0:.3f} | {seven or 0:.3f} | {ratio:.3f}" if ratio is not None else f"{case['case_id']} | - | - | -")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproduce the 300 MiB native-worker versus 7z.exe benchmark.")
    parser.add_argument("--format", action="append", choices=DEFAULT_FORMATS, dest="formats")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--warmups", type=int, default=0)
    parser.add_argument("--small-files", type=int, default=DEFAULT_SMALL_FILES)
    parser.add_argument("--large-files", type=int, default=DEFAULT_LARGE_FILES)
    parser.add_argument("--large-file-mib", type=int, default=DEFAULT_LARGE_FILE_MIB)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--worker", type=Path, help="Worker executable; defaults to the normal SunPack resource lookup.")
    parser.add_argument("--seven-zip", type=Path, help="7z.exe fixture; defaults to tests/test_tools.json/tools/7z.exe.")
    parser.add_argument("--worker-source-commit", default=None, help="Source commit used to build the worker binary.")
    parser.add_argument("--sunpack-version", default="v0.6.2")
    parser.add_argument("--metadata-only", action="store_true", help="Generate and catalog the corpus without running extraction.")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    if args.runs < 1 and not args.metadata_only:
        parser.error("--runs must be positive unless --metadata-only is used")
    if min(args.small_files, args.large_files, args.large_file_mib) < 1 or args.warmups < 0:
        parser.error("file counts, --large-file-mib, and --warmups must be non-negative/positive")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")

    formats = list(dict.fromkeys(args.formats or DEFAULT_FORMATS))
    worker_path = (args.worker or Path(get_sevenzip_bridge_worker_path())).resolve()
    seven_zip = (args.seven_zip or require_7z()).resolve()
    dll_path = Path(get_7z_cli_dll_path()).resolve()
    if not worker_path.is_file():
        parser.error(f"worker does not exist: {worker_path}")
    if not seven_zip.is_file() or not dll_path.is_file():
        parser.error("7z.exe and its companion 7z.dll must both exist")

    scenario = "extraction.worker-vs-7z-300m"
    with BenchmarkWorkspace(scenario, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        cases, corpus_info = _build_cases(
            workspace,
            formats,
            small_files=args.small_files,
            large_files=args.large_files,
            large_file_mib=args.large_file_mib,
            seven_zip_variants={"solid", "non-solid"},
            large_content="mixed",
        )
        descriptors = [_case_descriptor(case, seven_zip) for case in cases]
        results: list[dict[str, Any]] = []
        prior_env = {name: os.environ.get(name) for name in ("SUNPACK_SEVENZIP_PROFILE_READS", "SUNPACK_SEVENZIP_PROFILE_PIPELINE", "SUNPACK_SEVENZIP_PREFETCH")}
        os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "0"
        os.environ["SUNPACK_SEVENZIP_PROFILE_PIPELINE"] = "0"
        os.environ["SUNPACK_SEVENZIP_PREFETCH"] = "0"
        try:
            if not args.metadata_only:
                for index, case in enumerate(cases, start=1):
                    print(f"[{index}/{len(cases)}] {case['case_id']}", flush=True)
                    worker_rows = _run_worker_case(
                        case,
                        workspace=workspace,
                        worker_path=worker_path,
                        dll_path=dll_path,
                        runs=args.runs,
                        warmups=args.warmups,
                        timeout_seconds=args.timeout_seconds,
                    )
                    seven_rows = _run_seven_zip_case(
                        case,
                        workspace=workspace,
                    seven_zip=seven_zip,
                    runs=args.runs,
                    warmups=args.warmups,
                    timeout_seconds=args.timeout_seconds,
                )
                    results.append({
                        "case_id": case["case_id"],
                        "format": case["format"],
                        "variant": case.get("variant", "standard"),
                        "worker": worker_rows,
                        "seven_zip": seven_rows,
                    })
        finally:
            for name, value in prior_env.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        complete = [row for row in results if row.get("worker") and row.get("seven_zip")]
        worker_medians = [_median([float(sample["worker_wall_ms"]) for sample in row["worker"]]) for row in complete]
        seven_medians = [_median([float(sample["wall_ms"]) for sample in row["seven_zip"]]) for row in complete]
        worker_sum = round(sum(value or 0 for value in worker_medians), 3)
        seven_sum = round(sum(value or 0 for value in seven_medians), 3)
        report = {
            "schema_version": 1,
            "scenario": scenario,
            "sunpack_version": args.sunpack_version,
            "source_commit": _git_commit(),
            "worker_source_commit": args.worker_source_commit or _git_commit(),
            "runs": args.runs,
            "warmups": args.warmups,
            "payload_definition": {
                "small_files": args.small_files,
                "large_files": args.large_files,
                "large_file_mib": args.large_file_mib,
                "payload_bytes": args.large_files * args.large_file_mib * MIB,
                "shape": "two 150 MiB files: one deterministic repeated-text member and one deterministic random member",
                "random_seed": 20260729,
                "small_file_note": "few_large benchmark archives contain only the two large members; small_files is retained for corpus-builder compatibility.",
            },
            "execution_model": {
                "worker": "persistent native worker; worker process is created once per case and reused for warmups/measured runs",
                "seven_zip": "fresh 7z.exe x process per run; process startup is included",
                "order": "worker runs first, then 7z.exe runs on the same generated archive",
                "prefetch": "disabled",
                "diagnostics": "native read/pipeline diagnostics disabled",
                "timing": "wall-clock from submit/extraction start until the result/output process completes",
            },
            "environment": _collect_environment(workspace.root),
            "binaries": {
                "seven_zip": _tool_info(seven_zip, query_version=True),
                "worker": _tool_info(worker_path),
                "seven_zip_companion_dll": _tool_info(dll_path),
                "rar_builder": _tool_info(ROOT / "tools" / "Rar.exe") if (ROOT / "tools" / "Rar.exe").is_file() else None,
                "zstd_builder": _tool_info(ROOT / "tools" / "zstd.exe") if (ROOT / "tools" / "zstd.exe").is_file() else None,
            },
            "corpus": corpus_info,
            "archive_catalog": descriptors,
            "results": results,
            "summary": {
                "generated_case_count": len(cases),
                "measured_case_count": len(complete),
                "worker_successful_cases": sum(bool(row.get("worker")) and all(sample.get("passed") for sample in row["worker"]) for row in complete),
                "seven_zip_exit0_cases": sum(bool(row.get("seven_zip")) and all(sample.get("returncode") == 0 for sample in row["seven_zip"]) for row in complete),
                "sum_of_per_case_medians_worker_ms": worker_sum if complete else None,
                "sum_of_per_case_medians_seven_zip_ms": seven_sum if complete else None,
                "sum_of_medians_worker_over_seven_zip": round(worker_sum / seven_sum, 6) if seven_sum else None,
                "sum_of_medians_note": "A sum of independent per-case medians, not one serial combined workload measurement.",
            },
        }
        table = _table(results)
        result_path = workspace.write_result_json("report.json", report)
        workspace.write_result_text("summary.md", table)
        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(table)
        print(json.dumps({"result": str(result_path), "case_count": len(cases), "metadata_only": args.metadata_only}, ensure_ascii=False))
        return 0 if args.metadata_only or (len(complete) == len(cases) and all(sample.get("passed") for row in complete for sample in row["worker"]) and all(sample.get("returncode") == 0 for row in complete for sample in row["seven_zip"])) else 1


if __name__ == "__main__":
    raise SystemExit(main())
