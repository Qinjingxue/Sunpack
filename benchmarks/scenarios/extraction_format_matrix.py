"""Reproducible archive workload and detection regression benchmark.

The public mode creates many-small-file and few-large-file corpora, measures
SunPack and raw 7-Zip extraction, and measures detection without interpreter
startup.  ``--compare-root`` can point at a second Git worktree so that the
same archives are scanned by both revisions on the same machine.

Progress and phase timing: by default the run prints timestamped progress
lines to stderr (phase, case/run/label, per-operation wall time) and records
cumulative phase timings in ``phase_timing_seconds`` of the report.  Disable
with ``--no-progress``.  Progress always goes to stderr so the detection
worker's stdout JSON contract stays intact.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import AdaptivePressureGate, BenchmarkWorkspace, PhaseReporter, render_report, report_from_payload

PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
if not PYTHON.exists():
    PYTHON = Path(sys.executable)
SEVEN_ZIP = ROOT / "tools" / "7z.exe"
RAR = ROOT / "tools" / "Rar.exe"
ZSTD = ROOT / "tools" / "zstd.exe"
SUPPORTED = ("zip", "7z", "rar", "gz", "bz2", "xz", "zst", "tar", "tgz", "tbz2", "txz", "tzst")
GENERATED_FORMATS = (
    "zip", "7z", "7z-split", "rar", "rar-split", "tar", "gz", "bz2", "xz", "zst", "tgz", "tbz2", "txz", "tzst",
)
MIN_SCANNABLE_ARCHIVE_BYTES = 1024 * 1024
DEFAULT_CACHE_ROOT = ROOT / "benchmarks" / ".cache" / "extraction-format-matrix"
# Every subprocess below gets a hard timeout so a stale or hung command fails
# loudly instead of blocking the whole matrix forever.
DEFAULT_SUBPROCESS_TIMEOUT = float(os.environ.get("SUNPACK_BENCH_SUBPROCESS_TIMEOUT", "600"))


def timed(command: list[str], cwd: Path, timeout: float = DEFAULT_SUBPROCESS_TIMEOUT) -> tuple[float, int, str]:
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return time.perf_counter() - started, -124, f"command timed out after {timeout:g}s: {command[0]}"
    return time.perf_counter() - started, result.returncode, result.stderr[-2000:]


def _run_live_capture(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: float = DEFAULT_SUBPROCESS_TIMEOUT,
) -> tuple[int, str, str]:
    """Run a subprocess, forwarding its stderr lines to our stderr in real time.

    stdout and stderr are drained concurrently so the child never blocks on a
    full pipe; both streams are also returned as text (stderr doubles as the
    error report when the child fails).  A hard timeout kills the child so a
    stale worker cannot hang the matrix.
    """
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    def pump(stream: Any, chunks: list[str], echo: bool) -> None:
        for line in iter(stream.readline, ""):
            chunks.append(line)
            if echo:
                print(line, end="", file=sys.stderr, flush=True)

    threads = [
        threading.Thread(target=pump, args=(process.stdout, stdout_chunks, False), daemon=True),
        threading.Thread(target=pump, args=(process.stderr, stderr_chunks, True), daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=2)
        return -124, "".join(stdout_chunks), "".join(stderr_chunks) + f"\ncommand timed out after {timeout:g}s"
    for thread in threads:
        thread.join()
    return returncode, "".join(stdout_chunks), "".join(stderr_chunks)


def _run_7z(command: list[str]) -> bool:
    try:
        result = subprocess.run(
            [str(SEVEN_ZIP), *command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=DEFAULT_SUBPROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def _run_rar(command: list[str]) -> bool:
    try:
        result = subprocess.run(
            [str(RAR), *command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=DEFAULT_SUBPROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def _write_payloads(
    root: Path,
    small_files: int,
    large_files: int,
    large_file_mib: int,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Path]:
    small = root / "many-small"
    large = root / "few-large"
    small.mkdir(parents=True)
    large.mkdir(parents=True)
    chunk_size = 1024 * 1024
    rng = random.Random(20260729)
    if progress:
        progress(f"writing {small_files} x 1 KiB small files")
    for index in range(small_files):
        (small / f"file-{index:05d}.bin").write_bytes(rng.randbytes(1024))

    compressible_chunk = (b"sunpack-benchmark\n" * ((chunk_size // 18) + 1))[:chunk_size]
    if progress:
        progress(f"writing {large_files} x {large_file_mib} MiB large files")
    for index in range(large_files):
        with (large / f"large-{index:02d}.bin").open("wb") as stream:
            for _ in range(large_file_mib):
                stream.write(compressible_chunk if index % 2 == 0 else rng.randbytes(chunk_size))
    return {"many_small": small, "few_large": large}


def _create_archive(target: Path, archive_type: str, source: Path) -> bool:
    return _run_7z(["a", "-y", f"-t{archive_type}", str(target), str(source)]) and target.exists()


def _create_zstd_archive(target: Path, source: Path) -> bool:
    try:
        result = subprocess.run(
            [str(ZSTD), "-q", "-f", "-3", str(source), "-o", str(target)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=DEFAULT_SUBPROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0 and target.exists()


def _payload_total_bytes(root: Path) -> int:
    """Total uncompressed size of a payload tree (metadata only, no hashing).

    Payload-content correctness is covered by dedicated correctness tests, so
    the benchmark records only the expected size (used as informational
    metadata) instead of re-hashing every extracted file.
    """
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _isolate_corpus_inputs(root: Path, corpus: dict[str, dict[str, Any]]) -> None:
    """Keep scanner-visible siblings limited to the archive's own volume set."""
    inputs_root = root / "inputs"
    inputs_root.mkdir()
    for name, item in corpus.items():
        source = Path(item["path"])
        case_root = inputs_root / name.replace(":", "-")
        case_root.mkdir()
        if item["format"] == "7z-split":
            members = sorted(source.parent.glob(f"{source.name.rsplit('.', 1)[0]}.*"))
        elif item["format"] == "rar-split":
            prefix = source.name.split(".part", 1)[0]
            members = sorted(source.parent.glob(f"{prefix}.part*.rar"))
        else:
            members = [source]
        for member in members:
            destination = case_root / member.name
            if item["workload"] == "external":
                shutil.copy2(member, destination)
            else:
                shutil.move(str(member), destination)
            if member == source:
                item["path"] = destination


def _timed_seven_zip_extract(archive: Path, output: Path, archive_format: str) -> tuple[float, int]:
    started = time.perf_counter()
    stage = output / "_compressed_stream"
    composite = archive_format in {"gz", "bz2", "xz", "zst", "tgz", "tbz2", "txz", "tzst"}
    first_output = stage if composite else output
    first_output.mkdir(parents=True, exist_ok=True)
    command = [str(SEVEN_ZIP), "x", "-y", "-bd", "-bso0", f"-o{first_output}", str(archive)]
    try:
        first = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=DEFAULT_SUBPROCESS_TIMEOUT)
    except subprocess.TimeoutExpired:
        return time.perf_counter() - started, -124
    code = first.returncode
    if code == 0 and composite:
        tar_candidates = [path for path in stage.rglob("*") if path.is_file()]
        if len(tar_candidates) != 1:
            code = 2
        else:
            try:
                second = subprocess.run(
                    [str(SEVEN_ZIP), "x", "-y", "-bd", "-bso0", f"-o{output}", str(tar_candidates[0])],
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=DEFAULT_SUBPROCESS_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                code = -124
            else:
                code = second.returncode
        shutil.rmtree(stage, ignore_errors=True)
    return time.perf_counter() - started, code


def create_corpus(
    root: Path,
    extra: dict[str, Path],
    small_files: int,
    large_files: int,
    large_file_mib: int,
    progress: Callable[[str], None] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    root.mkdir(parents=True, exist_ok=True)
    payloads = _write_payloads(root / "payloads", small_files, large_files, large_file_mib, progress=progress)
    expected_payload_bytes = {name: _payload_total_bytes(path) for name, path in payloads.items()}
    corpus: dict[str, dict[str, Any]] = {}
    skipped: dict[str, str] = {}

    for workload, source in payloads.items():
        base_archives: dict[str, Path] = {}
        for archive_type in ("zip", "7z", "tar"):
            if progress:
                progress(f"creating {workload}:{archive_type}")
            target = root / f"{workload}.{archive_type}"
            if _create_archive(target, archive_type, source):
                base_archives[archive_type] = target
                corpus[f"{workload}:{archive_type}"] = {
                    "workload": workload,
                    "format": archive_type,
                    "path": target,
                }
            else:
                skipped[f"{workload}:{archive_type}"] = "bundled 7-Zip cannot create this format"

        # Keep the scanner entry volume above the project's default 1 MiB
        # recognition floor and avoid thousands of tiny volumes.
        split_size = "1m" if workload == "many_small" else "16m"
        split_target = root / f"{workload}.split.7z"
        split_first = root / f"{workload}.split.7z.001"
        if progress:
            progress(f"creating {workload}:7z-split (volume {split_size})")
        split_created = _run_7z(["a", "-y", "-t7z", f"-v{split_size}", str(split_target), str(source)])
        split_volumes = sorted(root.glob(f"{workload}.split.7z.*")) if split_created else []
        if len(split_volumes) > 1 and split_first.exists():
            corpus[f"{workload}:7z-split"] = {
                "workload": workload,
                "format": "7z-split",
                "path": split_first,
            }
        else:
            skipped[f"{workload}:7z-split"] = "workload did not produce multiple 7z volumes"

        rar_target = root / f"{workload}.rar"
        if progress:
            progress(f"creating {workload}:rar")
        if _run_rar(["a", "-idq", "-r", "-ep1", str(rar_target), str(source)]) and rar_target.exists():
            corpus[f"{workload}:rar"] = {"workload": workload, "format": "rar", "path": rar_target}
        else:
            skipped[f"{workload}:rar"] = "bundled RAR cannot create this format"

        rar_split_target = root / f"{workload}.split.rar"
        if progress:
            progress(f"creating {workload}:rar-split (volume {split_size})")
        if _run_rar(["a", "-idq", "-r", "-ep1", f"-v{split_size}", str(rar_split_target), str(source)]):
            rar_volumes = sorted(root.glob(f"{workload}.split.part*.rar"))
            if not rar_volumes and rar_split_target.exists():
                rar_volumes = [rar_split_target]
        else:
            rar_volumes = []
        if len(rar_volumes) > 1:
            corpus[f"{workload}:rar-split"] = {
                "workload": workload,
                "format": "rar-split",
                "path": rar_volumes[0],
            }
        else:
            skipped[f"{workload}:rar-split"] = "workload did not produce multiple RAR volumes"

        tar_source = base_archives.get("tar")
        for ext, archive_type in {"gz": "gzip", "bz2": "bzip2", "xz": "xz"}.items():
            if progress:
                alias = {"gz": "tgz", "bz2": "tbz2", "xz": "txz"}[ext]
                progress(f"creating {workload}:{ext} (+{alias})")
            target = root / f"{workload}.tar.{ext}"
            if tar_source is not None and _create_archive(target, archive_type, tar_source):
                corpus[f"{workload}:{ext}"] = {"workload": workload, "format": ext, "path": target}
                alias = {"gz": "tgz", "bz2": "tbz2", "xz": "txz"}[ext]
                alias_target = root / f"{workload}.{alias}"
                shutil.copy2(target, alias_target)
                corpus[f"{workload}:{alias}"] = {"workload": workload, "format": alias, "path": alias_target}
            else:
                skipped[f"{workload}:{ext}"] = "bundled 7-Zip cannot create this format"

        zstd_target = root / f"{workload}.tar.zst"
        if progress:
            progress(f"creating {workload}:zst (+tzst)")
        if tar_source is not None and _create_zstd_archive(zstd_target, tar_source):
            corpus[f"{workload}:zst"] = {"workload": workload, "format": "zst", "path": zstd_target}
            tzst_target = root / f"{workload}.tzst"
            shutil.copy2(zstd_target, tzst_target)
            corpus[f"{workload}:tzst"] = {"workload": workload, "format": "tzst", "path": tzst_target}
        else:
            skipped[f"{workload}:zst"] = "zstandard runtime cannot create this format"

    for name, source in extra.items():
        key = f"external:{name}"
        corpus[key] = {"workload": "external", "format": name, "path": source, "expected_payload_bytes": None}
    for item in corpus.values():
        if item["workload"] in expected_payload_bytes:
            item["expected_payload_bytes"] = expected_payload_bytes[item["workload"]]
    for ext in SUPPORTED:
        if not any(item["format"] == ext for item in corpus.values()):
            skipped.setdefault(ext, "provide a valid archive with --sample EXT=PATH")
    _isolate_corpus_inputs(root, corpus)
    return corpus, skipped


def _cache_key(small_files: int, large_files: int, large_file_mib: int) -> str:
    tool_fingerprints = []
    for tool in (SEVEN_ZIP, RAR, ZSTD):
        stat = tool.stat()
        tool_fingerprints.append((tool.name, stat.st_size, stat.st_mtime_ns))
    payload = {
        "schema": 1,
        "small_files": small_files,
        "large_files": large_files,
        "large_file_mib": large_file_mib,
        "tools": tool_fingerprints,
        "formats": GENERATED_FORMATS,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:20]


def _cached_corpus(
    destination: Path,
    *,
    cache_root: Path,
    small_files: int,
    large_files: int,
    large_file_mib: int,
    rebuild: bool,
) -> tuple[dict[str, dict[str, Any]], dict[str, str], dict[str, Any]]:
    key = _cache_key(small_files, large_files, large_file_mib)
    entry = cache_root.resolve() / key
    manifest_path = entry / "cache-manifest.json"
    hit = manifest_path.is_file() and not rebuild
    if not hit:
        staging = cache_root.resolve() / f".{key}-{os.getpid()}"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=False)
        corpus, skipped = create_corpus(staging / "corpus", {}, small_files, large_files, large_file_mib)
        manifest = {
            "schema_version": 1,
            "key": key,
            "cases": {
                name: {**item, "path": str(Path(item["path"]).relative_to(staging))}
                for name, item in corpus.items()
            },
            "skipped": skipped,
        }
        (staging / "cache-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        cache_root.mkdir(parents=True, exist_ok=True)
        if entry.exists():
            shutil.rmtree(entry)
        shutil.move(str(staging), str(entry))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    shutil.copytree(entry / "corpus", destination, dirs_exist_ok=True)
    corpus = {
        name: {**item, "path": destination / Path(item["path"]).relative_to("corpus")}
        for name, item in manifest["cases"].items()
    }
    return corpus, dict(manifest["skipped"]), {"enabled": True, "hit": hit, "key": key, "path": str(entry)}


def _add_external_corpus(root: Path, corpus: dict[str, dict[str, Any]], extra: dict[str, Path]) -> None:
    for name, source in extra.items():
        key = f"external:{name}"
        case_root = root / "inputs" / key.replace(":", "-")
        case_root.mkdir(parents=True, exist_ok=True)
        destination = case_root / source.name
        shutil.copy2(source, destination)
        corpus[key] = {"workload": "external", "format": name, "path": destination, "expected_payload_bytes": None}


def _median(values: list[float | None]) -> float | None:
    successful = [value for value in values if value is not None]
    return statistics.median(successful) if successful else None


def _worker_detection(
    archives: list[tuple[str, Path]],
    runs: int,
    warmups: int,
    reporter: PhaseReporter | None = None,
) -> int:
    """Run detection in-process; imports and CLI startup are outside samples."""
    from sunpack.core.config.loader import load_config
    from sunpack.pipeline.coordinator.scanner import ScanOrchestrator

    config = load_config()
    rows: dict[str, dict[str, Any]] = {}
    total = len(archives)
    for index, (name, archive) in enumerate(archives, 1):
        samples: list[float] = []
        result_count = 0
        if reporter is not None:
            reporter.note(f"detection-worker: scanning {index}/{total} {name} ({archive.stat().st_size} bytes)")
        try:
            for _ in range(warmups):
                ScanOrchestrator(config).scan_targets([str(archive)])
            for _ in range(runs):
                started = time.perf_counter()
                results = ScanOrchestrator(config).scan_targets([str(archive)])
                samples.append(time.perf_counter() - started)
                result_count = len(results)
        except Exception as exc:  # Keep a single unsupported/broken format from aborting the matrix.
            rows[name] = {
                "samples_seconds": [],
                "median_seconds": None,
                "result_count": None,
                "error": f"{type(exc).__name__}: {exc}",
            }
            continue
        rows[name] = {
            "samples_seconds": samples,
            "median_seconds": statistics.median(samples),
            "result_count": result_count,
            "error": None,
        }
        if reporter is not None:
            median = statistics.median(samples) if samples else None
            reporter.note(
                f"detection-worker:   {name} done in {sum(samples):.2f}s over {len(samples)} samples"
                + (f", median {median:.3f}s" if median is not None else "")
            )
    print(json.dumps(rows, ensure_ascii=False))
    return 0


def _detection_for_root(
    source_root: Path,
    archives: dict[str, dict[str, Any]],
    runs: int,
    warmups: int,
    *,
    label: str = "current",
    reporter: PhaseReporter | None = None,
) -> dict[str, dict[str, Any]]:
    command = [str(PYTHON), str(Path(__file__).resolve()), "--detection-worker", "--runs", str(runs), "--warmups", str(warmups)]
    if reporter is not None and not reporter.enabled:
        command.append("--no-progress")
    for name, item in archives.items():
        command.extend(["--worker-archive", f"{name}={item['path']}"])
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(source_root)
    phase_context = (
        reporter.phase("detection", f"pass {label}: {len(archives)} archives") if reporter is not None else contextlib.nullcontext()
    )
    with phase_context:
        returncode, stdout, stderr = _run_live_capture(command, cwd=source_root, env=environment)
    if returncode != 0:
        raise RuntimeError(f"detection worker failed for {source_root}: {stderr.strip()}")
    return json.loads(stdout)


def _merge_detection_passes(
    first: dict[str, dict[str, Any]],
    second: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for name, first_row in first.items():
        second_row = second[name]
        if first_row.get("error") or second_row.get("error"):
            merged[name] = first_row if first_row.get("error") else second_row
            continue
        if first_row["result_count"] != second_row["result_count"]:
            raise RuntimeError(f"detection result count changed between passes for {name}")
        samples = [*first_row["samples_seconds"], *second_row["samples_seconds"]]
        merged[name] = {
            "samples_seconds": samples,
            "median_seconds": statistics.median(samples),
            "result_count": first_row["result_count"],
            "error": None,
        }
    return merged


def benchmark(
    archives: dict[str, dict[str, Any]],
    work: Path,
    runs: int,
    warmups: int,
    compare_root: Path | None,
    case_cooldown_seconds: float,
    pressure_gate: AdaptivePressureGate,
    collect_phase_profile: bool,
    phase_profile_runs: int,
    phase_profile_warmups: int,
    reporter: PhaseReporter | None = None,
) -> list[dict[str, Any]]:
    current_detection = _detection_for_root(ROOT, archives, runs, warmups, label="current", reporter=reporter)
    comparison_detection: dict[str, dict[str, Any]] = {}
    if compare_root is not None:
        # ABBA order reduces revision bias from cache warmth, CPU frequency, and
        # other short-lived machine drift. Each reported median has 2 * runs.
        comparison_first = _detection_for_root(compare_root, archives, runs, warmups, label="comparison-1", reporter=reporter)
        comparison_second = _detection_for_root(compare_root, archives, runs, warmups, label="comparison-2", reporter=reporter)
        current_second = _detection_for_root(ROOT, archives, runs, warmups, label="current-2", reporter=reporter)
        current_detection = _merge_detection_passes(current_detection, current_second)
        comparison_detection = _merge_detection_passes(comparison_first, comparison_second)
    rows: list[dict[str, Any]] = []
    total_cases = len(archives)
    for case_index, (name, item) in enumerate(archives.items(), 1):
        archive = Path(item["path"])
        case_message = f"case {case_index}/{total_cases} {name} ({item['format']}, {archive.stat().st_size} bytes)"
        with reporter.phase("extraction_matrix", case_message) if reporter is not None else contextlib.nullcontext():
            raw: list[float | None] = []
            full: list[float | None] = []
            raw_exit_codes: list[int] = []
            full_exit_codes: list[int] = []
            raw_file_counts: list[int] = []
            full_file_counts: list[int] = []
            full_errors: list[str] = []
            pressure_waits: list[dict[str, Any]] = []
            for run in range(-warmups, runs):
                labels = ("raw", "sunpack") if run % 2 == 0 else ("sunpack", "raw")
                for label in labels:
                    pressure_started = time.perf_counter()
                    pressure_waits.append({"label": label, "run": run, **pressure_gate.wait().to_dict()})
                    if reporter is not None:
                        reporter.record("matrix_pressure_wait", time.perf_counter() - pressure_started)
                    output = work / f"out-{name.replace(':', '-')}-{label}-{run}"
                    shutil.rmtree(output, ignore_errors=True)
                    output.mkdir()
                    if label == "raw":
                        extract_started = time.perf_counter()
                        elapsed, code = _timed_seven_zip_extract(archive, output, item["format"])
                        if reporter is not None:
                            reporter.record("matrix_seven_zip_extract", time.perf_counter() - extract_started)
                        error = ""
                    else:
                        command = [
                            str(PYTHON), "-m", "sunpack", "extract", "--recur", "*",
                            "--cleanup", "k", "--no-flatten", "--no-builtin-pw", "--no-dir-pw", "--quiet",
                            "--no-pause", "-o", str(output), str(archive),
                        ]
                        extract_started = time.perf_counter()
                        elapsed, code, error = timed(command, ROOT)
                        if reporter is not None:
                            reporter.record("matrix_sunpack_extract", time.perf_counter() - extract_started)
                    count_started = time.perf_counter()
                    extracted_file_count = sum(1 for path in output.rglob("*") if path.is_file())
                    valid = code == 0  # Payload correctness is covered by dedicated correctness tests.
                    if reporter is not None:
                        reporter.record("matrix_output_count", time.perf_counter() - count_started)
                    if run >= 0:
                        (raw if label == "raw" else full).append(elapsed if valid else None)
                        (raw_exit_codes if label == "raw" else full_exit_codes).append(code)
                        (raw_file_counts if label == "raw" else full_file_counts).append(extracted_file_count)
                        if label == "sunpack":
                            full_errors.append(error)
                    cleanup_started = time.perf_counter()
                    shutil.rmtree(output, ignore_errors=True)
                    if reporter is not None:
                        reporter.record("matrix_cleanup", time.perf_counter() - cleanup_started)
                    if reporter is not None:
                        reporter.note(
                            f"  run {run + warmups + 1}/{runs + warmups} {label}: {elapsed:.2f}s "
                            f"(code {code}, files {extracted_file_count})"
                        )
                    if case_cooldown_seconds:
                        time.sleep(case_cooldown_seconds)

        phase_profile: dict[str, Any] | None = None
        if collect_phase_profile:
            with reporter.phase(
                "phase_profiles", f"case {case_index}/{total_cases} {name}"
            ) if reporter is not None else contextlib.nullcontext():
                pressure_waits.append({"label": "phase_profile", "run": 0, **pressure_gate.wait().to_dict()})
                profile_output = work / f"out-{name.replace(':', '-')}-phase-profile"
                shutil.rmtree(profile_output, ignore_errors=True)
                command = [
                    str(PYTHON), "-m", "benchmarks.scenarios.extraction_large_archive",
                    str(archive), str(profile_output), "--warmup", str(phase_profile_warmups),
                    "--repeat", str(phase_profile_runs),
                    "--recursive-rounds", "1", "--keep-output",
                ]
                profiled = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, encoding="utf-8", errors="replace")
                marker = "PROFILE_JSON="
                marker_at = profiled.stdout.find(marker)
                if profiled.returncode == 0 and marker_at >= 0:
                    phase_profile = json.loads(profiled.stdout[marker_at + len(marker):])["summary"]
                else:
                    phase_profile = {
                        "error": f"profile worker exited {profiled.returncode}",
                        "stderr": profiled.stderr[-2000:],
                    }
                shutil.rmtree(profile_output, ignore_errors=True)

        raw_m = _median(raw)
        full_m = _median(full)
        current = current_detection[name]
        comparison = comparison_detection.get(name)
        delta = None
        delta_percent = None
        if current["median_seconds"] is not None and comparison and comparison["median_seconds"]:
            delta = current["median_seconds"] - comparison["median_seconds"]
            delta_percent = delta / comparison["median_seconds"] * 100.0
        rows.append({
            "name": name,
            "workload": item["workload"],
            "format": item["format"],
            "bytes": archive.stat().st_size,
            "runs": runs,
            "seven_zip_seconds": raw_m,
            "sunpack_seconds": full_m,
            "seven_zip_samples_seconds": raw,
            "sunpack_samples_seconds": full,
            "seven_zip_exit_codes": raw_exit_codes,
            "sunpack_exit_codes": full_exit_codes,
            "seven_zip_file_counts": raw_file_counts,
            "sunpack_file_counts": full_file_counts,
            "sunpack_stderr": full_errors,
            "pressure_waits": pressure_waits,
            "phase_profile": phase_profile,
            "end_to_end_includes_detection": True,
            "detection": {
                "current": current,
                "comparison": comparison,
                "delta_seconds": delta,
                "delta_percent": delta_percent,
            },
            "overhead_seconds": full_m - raw_m if full_m is not None and raw_m is not None else None,
        })
    return rows


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    current = [
        row["detection"]["current"]["median_seconds"]
        for row in rows
        if row["detection"]["current"]["median_seconds"] is not None
    ]
    comparable = [
        row for row in rows
        if row["detection"]["current"]["median_seconds"] is not None
        and row["detection"]["comparison"] is not None
        and row["detection"]["comparison"]["median_seconds"] is not None
    ]
    summary: dict[str, Any] = {
        "case_count": len(rows),
        "detection_current_total_seconds": sum(current),
        "detection_current_median_seconds": statistics.median(current) if current else None,
        "successful_extraction_cases": sum(row["sunpack_seconds"] is not None for row in rows),
        "successful_seven_zip_cases": sum(row["seven_zip_seconds"] is not None for row in rows),
        "successful_detection_cases": len(current),
        "detection_error_cases": len(rows) - len(current),
    }
    # A case is comparable when both extractors exited successfully. Payload
    # content correctness is covered by dedicated correctness tests, so only
    # the exit codes gate the comparison here.
    valid_pairs = [
        row for row in rows
        if row["sunpack_seconds"] is not None
        and row["seven_zip_seconds"] is not None
    ]
    sunpack_total = sum(row["sunpack_seconds"] for row in valid_pairs)
    seven_zip_total = sum(row["seven_zip_seconds"] for row in valid_pairs)
    failed_cases = [
        {
            "name": row["name"],
            "sunpack_exit_codes": row["sunpack_exit_codes"],
            "sunpack_file_counts": row["sunpack_file_counts"],
            "seven_zip_file_counts": row["seven_zip_file_counts"],
            "sunpack_stderr": row["sunpack_stderr"],
        }
        for row in rows
        if row not in valid_pairs
    ]
    summary.update({
        "comparable_valid_cases": len(valid_pairs),
        "sunpack_end_to_end_total_seconds": sunpack_total,
        "seven_zip_total_seconds": seven_zip_total,
        "sunpack_vs_seven_zip_ratio": sunpack_total / seven_zip_total if seven_zip_total else None,
        "all_generated_cases_passed": len(valid_pairs) == len(rows),
        "failed_cases": failed_cases,
    })
    if comparable:
        current_total = sum(row["detection"]["current"]["median_seconds"] for row in comparable)
        comparison_total = sum(row["detection"]["comparison"]["median_seconds"] for row in comparable)
        summary.update({
            "detection_comparison_total_seconds": comparison_total,
            "detection_total_delta_seconds": current_total - comparison_total,
            "detection_total_delta_percent": (
                (current_total - comparison_total) / comparison_total * 100.0 if comparison_total else None
            ),
        })
    return summary


def _phase_aggregates(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_format: dict[str, dict[str, list[float]]] = {}
    for row in rows:
        profile = row.get("phase_profile") or {}
        medians = profile.get("timing_medians_seconds") or {}
        format_rows = by_format.setdefault(row["format"], {})
        for label, value in medians.items():
            format_rows.setdefault(label, []).append(float(value))
    rendered: dict[str, Any] = {}
    for archive_format, phases in sorted(by_format.items()):
        phase_medians = {label: statistics.median(values) for label, values in phases.items()}
        rendered[archive_format] = {
            "phase_medians_seconds": phase_medians,
            "top_phases": [
                {"phase": label, "median_seconds": value}
                for label, value in sorted(phase_medians.items(), key=lambda item: item[1], reverse=True)[:15]
            ],
        }
    return rendered


def _git_revision(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _parse_archive_args(values: list[str]) -> list[tuple[str, Path]]:
    archives = []
    for value in values:
        name, path = value.split("=", 1)
        archives.append((name, Path(path).resolve()))
    return archives


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--small-files", type=int, default=2000)
    parser.add_argument("--large-files", type=int, default=2)
    parser.add_argument("--large-file-mib", type=int, default=32)
    parser.add_argument("--sample", action="append", default=[], metavar="EXT=PATH")
    parser.add_argument("--format", action="append", choices=GENERATED_FORMATS, dest="formats")
    parser.add_argument("--compare-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--results-root", type=Path, help="Durable benchmark result root.")
    parser.add_argument("--keep-workdir", action="store_true", help="Keep generated archives and extraction outputs.")
    parser.add_argument(
        "--case-cooldown-seconds", type=float, default=0.0,
        help="Optional fixed pause after the adaptive pressure gate.",
    )
    parser.add_argument("--max-cpu-percent", type=float, default=85.0)
    parser.add_argument("--min-available-memory-percent", type=float, default=15.0)
    parser.add_argument("--pressure-sample-seconds", type=float, default=0.1)
    parser.add_argument("--pressure-max-wait-seconds", type=float, default=30.0)
    parser.add_argument("--no-phase-profile", action="store_true")
    parser.add_argument("--phase-profile-runs", type=int, default=1)
    parser.add_argument("--phase-profile-warmups", type=int, default=0)
    parser.add_argument("--cache-root", type=Path, default=DEFAULT_CACHE_ROOT)
    parser.add_argument("--no-corpus-cache", action="store_true")
    parser.add_argument("--rebuild-corpus-cache", action="store_true")
    parser.add_argument("--no-progress", action="store_true", help="Disable real-time progress lines and phase timing output.")
    parser.add_argument("--detection-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-archive", action="append", default=[], help=argparse.SUPPRESS)
    args = parser.parse_args()
    reporter = PhaseReporter(enabled=not args.no_progress)

    if args.detection_worker:
        return _worker_detection(
            _parse_archive_args(args.worker_archive), max(1, args.runs), max(0, args.warmups), reporter,
        )
    if not SEVEN_ZIP.is_file():
        parser.error(f"bundled 7-Zip does not exist: {SEVEN_ZIP}")
    if not RAR.is_file():
        parser.error(f"bundled RAR does not exist: {RAR}")
    if not ZSTD.is_file():
        parser.error(f"bundled zstd does not exist: {ZSTD}")
    compare_root = args.compare_root.resolve() if args.compare_root else None
    if compare_root is not None and not (compare_root / "sunpack").is_dir():
        parser.error(f"comparison root does not contain sunpack package: {compare_root}")

    extra = dict(_parse_archive_args(args.sample))
    with BenchmarkWorkspace(
        "extraction.format-matrix",
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        work = workspace.work
        if args.no_corpus_cache:
            with reporter.phase("corpus", "building corpus (cache disabled)"):
                corpus, skipped = create_corpus(
                    workspace.corpus,
                    extra,
                    max(1, args.small_files),
                    max(1, args.large_files),
                    max(1, args.large_file_mib),
                    progress=reporter.note,
                )
            cache_info = {"enabled": False, "hit": False}
        else:
            with reporter.phase("corpus", "loading or building content-addressed corpus"):
                corpus, skipped, cache_info = _cached_corpus(
                    workspace.corpus,
                    cache_root=args.cache_root,
                    small_files=max(1, args.small_files),
                    large_files=max(1, args.large_files),
                    large_file_mib=max(1, args.large_file_mib),
                    rebuild=args.rebuild_corpus_cache,
                )
                _add_external_corpus(workspace.corpus, corpus, extra)
                for name in extra:
                    skipped.pop(name, None)
        reporter.note(f"corpus: {len(corpus)} archives ready (cache enabled={cache_info.get('enabled')}, hit={cache_info.get('hit')})")
        if args.formats:
            selected_formats = set(args.formats)
            corpus = {name: item for name, item in corpus.items() if item["format"] in selected_formats}
        undersized = {
            name: Path(item["path"]).stat().st_size
            for name, item in corpus.items()
            if item["workload"] != "external"
            and Path(item["path"]).stat().st_size < MIN_SCANNABLE_ARCHIVE_BYTES
        }
        if undersized:
            details = ", ".join(f"{name}={size}B" for name, size in sorted(undersized.items()))
            raise RuntimeError(f"generated scanner inputs are below the 1 MiB floor: {details}")
        pressure_gate = AdaptivePressureGate(
            max_cpu_percent=args.max_cpu_percent,
            min_available_memory_percent=args.min_available_memory_percent,
            sample_seconds=args.pressure_sample_seconds,
            max_wait_seconds=args.pressure_max_wait_seconds,
        )
        rows = benchmark(
            corpus,
            work,
            max(1, args.runs),
            max(0, args.warmups),
            compare_root,
            max(0.0, args.case_cooldown_seconds),
            pressure_gate,
            not args.no_phase_profile,
            max(1, args.phase_profile_runs),
            max(0, args.phase_profile_warmups),
            reporter,
        )
        with reporter.phase("report", "building report payload and rendering"):
            report = {
                "schema_version": 2,
                "supported_formats": list(SUPPORTED),
                "generated_formats": list(GENERATED_FORMATS),
                "workloads": {
                    "many_small": {"file_count": max(1, args.small_files)},
                    "few_large": {"file_count": max(1, args.large_files), "file_size_mib": max(1, args.large_file_mib)},
                },
                "environment": {
                    "python": sys.version,
                    "platform": sys.platform,
                    "cpu_count": os.cpu_count(),
                    "current_root": str(ROOT),
                    "current_revision": _git_revision(ROOT),
                    "compare_root": str(compare_root) if compare_root else None,
                    "compare_revision": _git_revision(compare_root) if compare_root else None,
                },
                "results": rows,
                "summary": _summary(rows),
                "phase_aggregates": _phase_aggregates(rows),
                "pressure_gate": pressure_gate.summary(),
                "corpus_cache": cache_info,
                "skipped": skipped,
                "artifacts": {"result_dir": str(workspace.result_dir)},
                "phase_timing_seconds": reporter.totals(),
            }
            rendered = render_report(report_from_payload("extraction.format-matrix", report))
            workspace.write_result_text("report.json", rendered)
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(rendered, encoding="utf-8")
        print(rendered)
        all_passed = report["summary"]["all_generated_cases_passed"]
        reporter.note(f"benchmark complete in {reporter.elapsed:.1f}s, phase breakdown:")
        for line in reporter.render_summary().splitlines():
            reporter.note(f"  {line}")
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
