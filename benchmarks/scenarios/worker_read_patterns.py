"""Profile 7z.dll IInStream access patterns across generated archive formats."""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import random
import re
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.harness import BenchmarkWorkspace, ProcessSampler, render_report, report_from_payload
from benchmarks.scenarios.extraction_format_matrix import (
    GENERATED_FORMATS,
    _cached_corpus,
    _create_archive,
    _parse_archive_args,
    _run_7z,
    _run_rar,
    _write_payloads,
    create_corpus,
)
from benchmarks.scenarios.sevenzip_worker_matrix import _case_job, _median, _run_job
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _NativeWorkerProcess
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path


MIB = 1024 * 1024
DEFAULT_SMALL_FILES = 8
DEFAULT_LARGE_FILES = 2
DEFAULT_LARGE_FILE_MIB = 32


def _solid_variants(
    root: Path,
    payload_bytes: int,
    *,
    only_variants: set[str] | None = None,
    reuse_existing: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    source = root / "payloads" / "few-large"
    variants_root = root / "solid-variants"
    variants_root.mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, Any]] = []
    skipped: dict[str, str] = {}
    commands = (
        ("7z", "solid", ["a", "-y", "-t7z", "-ms=on"]),
        ("7z", "non-solid", ["a", "-y", "-t7z", "-ms=off"]),
        ("rar", "solid", ["a", "-idq", "-r", "-ep1", "-s"]),
        ("rar", "non-solid", ["a", "-idq", "-r", "-ep1", "-s-"]),
    )
    for archive_format, variant, command in commands:
        if only_variants is not None and variant not in only_variants:
            continue
        archive = variants_root / f"few-large-{archive_format}-{variant}.{archive_format}"
        if reuse_existing and archive.is_file() and archive.stat().st_size > 0:
            created = True
        else:
            created = _run_7z([*command, str(archive), str(source)]) if archive_format == "7z" else _run_rar([*command, str(archive), str(source)])
        if not created or not archive.is_file():
            skipped[f"few_large:{archive_format}:{variant}"] = "bundled archiver could not create explicit solid-mode archive"
            continue
        cases.append({
            "case_id": f"few_large:{archive_format}:{variant}",
            "format": archive_format,
            "variant": variant,
            "workload": "few_large",
            "archive_path": archive,
            "archive_bytes": archive.stat().st_size,
            "payload_bytes": payload_bytes,
            "item": {"path": archive, "format": archive_format, "expected_payload_bytes": payload_bytes},
        })
    return cases, skipped


def _focused_corpus(
    root: Path,
    formats: set[str],
    *,
    small_files: int,
    large_files: int,
    large_file_mib: int,
    large_content: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Create only the large archives needed by the targeted regression probe."""
    payload_root = root / "payloads"
    if large_content == "mixed":
        payloads = _write_payloads(payload_root, small_files, large_files, large_file_mib)
        source = payloads["few_large"]
    else:
        source = payload_root / "few-large"
        source.mkdir(parents=True)
        rng = random.Random(20260817)
        chunk_size = MIB
        for index in range(large_files):
            with (source / f"large-{index:02d}.bin").open("wb") as stream:
                for _ in range(large_file_mib):
                    stream.write(rng.randbytes(chunk_size))
    payload_bytes = large_files * large_file_mib * MIB
    corpus: dict[str, dict[str, Any]] = {}
    skipped: dict[str, str] = {}
    if "tar" in formats:
        archive = root / "few-large.tar"
        if _create_archive(archive, "tar", source):
            corpus["few_large:tar"] = {
                "workload": "few_large",
                "format": "tar",
                "path": archive,
                "expected_payload_bytes": payload_bytes,
            }
        else:
            skipped["few_large:tar"] = "bundled 7-Zip cannot create this format"
    if "rar-split" in formats:
        archive = root / "few-large.split.rar"
        if _run_rar(["a", "-idq", "-r", "-ep1", "-v16m", str(archive), str(source)]):
            volumes = sorted(root.glob("few-large.split.part*.rar"))
        else:
            volumes = []
        if len(volumes) > 1:
            corpus["few_large:rar-split"] = {
                "workload": "few_large",
                "format": "rar-split",
                "path": volumes[0],
                "expected_payload_bytes": payload_bytes,
            }
        else:
            skipped["few_large:rar-split"] = "workload did not produce multiple RAR volumes"
    return corpus, skipped


def _build_cases(
    workspace: BenchmarkWorkspace,
    formats: list[str],
    *,
    small_files: int,
    large_files: int,
    large_file_mib: int,
    seven_zip_variants: set[str],
    large_content: str,
    cached_corpus: dict[str, dict[str, Any]] | None = None,
    cache_info: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    targeted_formats = {"7z", "rar-split", "tar"}
    requested = set(formats)
    if cached_corpus is not None:
        # The cache already holds the payload tree; rebuild only missing solid variants.
        corpus = cached_corpus
        skipped: dict[str, str] = {}
        variants, variant_skipped = _solid_variants(
            workspace.corpus, large_files * large_file_mib * MIB, reuse_existing=True
        )
    else:
        if requested <= targeted_formats:
            corpus, skipped = _focused_corpus(
                workspace.corpus,
                requested,
                small_files=small_files,
                large_files=large_files,
                large_file_mib=large_file_mib,
                large_content=large_content,
            )
        else:
            corpus, skipped = create_corpus(
                workspace.corpus,
                {},
                small_files,
                large_files,
                large_file_mib,
            )
        variants, variant_skipped = _solid_variants(workspace.corpus, large_files * large_file_mib * MIB)
    cases: list[dict[str, Any]] = []
    for name, item in sorted(corpus.items()):
        archive_format = str(item["format"])
        if item.get("workload") != "few_large" or archive_format not in requested or archive_format in {"7z", "rar"}:
            continue
        archive = Path(item["path"])
        cases.append({
            "case_id": name,
            "format": archive_format,
            "variant": "split" if archive_format.endswith("-split") else "standard",
            "workload": "few_large",
            "archive_path": archive,
            "archive_bytes": archive.stat().st_size,
            "payload_bytes": int(item.get("expected_payload_bytes") or 0),
            "item": item,
        })
    cases.extend(
        case
        for case in variants
        if case["format"] in requested and case["variant"] in seven_zip_variants
    )
    cases.sort(key=lambda case: (str(case["format"]), str(case["variant"])))
    return cases, {
        "payload": {
            "small_files": small_files,
            "large_files": large_files,
            "large_file_mib": large_file_mib,
            "large_content": large_content,
        },
        "generated_formats": list(GENERATED_FORMATS),
        "requested_formats": formats,
        "case_count": len(cases),
        "skipped": {**skipped, **variant_skipped},
        "corpus_cache": cache_info,
    }


def _archive_format(path: Path) -> str:
    """Map an archive path to the native worker's format hint.

    Split 7z volumes end in `.7z.001`, split RAR volumes in `.partN.rar`.
    """
    name = path.name.lower()
    if re.search(r"\.7z\.\d{3}$", name):
        return "7z-split"
    if re.search(r"\.part\d+\.rar$", name):
        return "rar-split"
    for suffix, archive_format in (
        (".zip", "zip"),
        (".7z", "7z"),
        (".rar", "rar"),
        (".tar", "tar"),
        (".tgz", "tgz"),
        (".gz", "gz"),
        (".tbz2", "tbz2"),
        (".bz2", "bz2"),
        (".txz", "txz"),
        (".xz", "xz"),
        (".tzst", "tzst"),
        (".zst", "zst"),
    ):
        if name.endswith(suffix):
            return archive_format
    raise ValueError(f"cannot derive an archive format from {path.name!r}")


def _explicit_archives(values: list[str], *, payload_bytes: int) -> list[dict[str, Any]]:
    """Build cases from archives supplied on the command line."""
    cases: list[dict[str, Any]] = []
    for name, path in _parse_archive_args(values):
        if not path.is_file():
            raise FileNotFoundError(f"archive does not exist: {path}")
        archive_format = _archive_format(path)
        variant = "split" if archive_format.endswith("-split") else "standard"
        cases.append({
            "case_id": name,
            "format": archive_format,
            "variant": variant,
            "workload": "explicit",
            "archive_path": path,
            "archive_bytes": path.stat().st_size,
            "payload_bytes": payload_bytes,
            "item": {
                "path": path,
                "format": archive_format,
                "workload": "explicit",
                "expected_payload_bytes": payload_bytes,
            },
        })
    return cases


def _prefetch_recommendation(row: dict[str, Any]) -> str:
    """Classify from measured virtual-stream access, without assuming a cache exists."""
    ratio = row.get("input_sequential_read_ratio")
    if ratio is None:
        return "no logical reads"
    seeks = int(row.get("input_seek_count") or 0)
    max_run = int(row.get("input_max_sequential_run_bytes") or 0)
    if seeks <= 1 and ratio >= 0.90:
        return "sequential prefetch candidate"
    if seeks <= 12 and max_run >= 4 * MIB:
        return "seek-epoch prefetch candidate"
    return "avoid global prefetch"


def _starvation_verdict(row: dict[str, Any]) -> str:
    """Report whether the decoder ever had to fall back to a synchronous read.

    A miss means the consumer read the file itself and discarded the prefetch
    epoch; misses are compared against the logical read count rather than
    demanding zero.
    """
    hits = row.get("input_prefetch_hit_count")
    misses = row.get("input_prefetch_miss_count")
    if hits is None or misses is None:
        return "no prefetch trace"
    if not row.get("input_prefetch_enabled"):
        return "prefetch disabled"
    hits = int(hits)
    misses = int(misses)
    total = hits + misses
    if total == 0:
        return "no prefetch traffic"
    ratio = misses / total
    if ratio <= 0.01:
        return "decoder fed (miss<=1%)"
    if ratio <= 0.05:
        return "rare starvation (miss<=5%)"
    return "starving (miss>5%)"


def _mib(value: int | float | None) -> str:
    return "-" if value is None else f"{float(value) / MIB:.2f}"


def _pattern_table(rows: list[dict[str, Any]]) -> str:
    columns = [
        "format", "archive MiB", "stream", "seeks", "forward MiB", "backward MiB", "logical reads",
        "sequential %", "runs", "max run MiB", "hits", "misses", "invalidations", "miss %",
        "prefetch wait ms", "ReadFile ms", "ReadFile wall %", "decoder verdict",
    ]
    lines = ["| " + " | ".join(columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    for row in rows:
        name = str(row["format"])
        if row.get("variant") not in {None, "standard"}:
            name = f"{name} ({row['variant']})"
        ratio = row.get("input_sequential_read_ratio")
        read_ratio = row.get("input_read_file_wall_ratio")
        hits = row.get("input_prefetch_hit_count")
        misses = row.get("input_prefetch_miss_count")
        miss_ratio = "-"
        if hits is not None and misses is not None and (int(hits) + int(misses)) > 0:
            miss_ratio = f"{int(misses) / (int(hits) + int(misses)) * 100:.2f}%"
        lines.append("| " + " | ".join((
            name,
            _mib(row.get("archive_bytes")),
            str(row.get("input_stream_mode") or "-"),
            str(row.get("input_seek_count") or 0),
            _mib(row.get("input_seek_forward_bytes")),
            _mib(row.get("input_seek_backward_bytes")),
            str(row.get("input_logical_read_call_count") or 0),
            "-" if ratio is None else f"{float(ratio) * 100:.1f}%",
            str(row.get("input_sequential_run_count") or 0),
            _mib(row.get("input_max_sequential_run_bytes")),
            "-" if hits is None else str(int(hits)),
            "-" if misses is None else str(int(misses)),
            str(row.get("input_prefetch_invalidation_count") or 0),
            miss_ratio,
            f"{float(row.get('input_prefetch_consumer_wait_ms') or 0):.1f}",
            f"{float(row.get('input_read_file_wall_ms') or 0):.3f}",
            "-" if read_ratio is None else f"{float(read_ratio) * 100:.1f}%",
            str(row.get("decoder_verdict") or "-"),
        )) + " |")
    return "\n".join(lines) + "\n"


def _cold_copy_case(case: dict[str, Any], slot: Path) -> dict[str, Any]:
    """Point a case at a freshly written copy of its archive.

    Cached pages are keyed by file, so a freshly written path has none — the only
    reliable cold-cache measurement without a cache-clearing tool.
    """
    source = Path(case["archive_path"])
    slot = slot.with_suffix(source.suffix)
    slot.unlink(missing_ok=True)
    shutil.copy2(source, slot)
    copied = dict(case)
    copied["archive_path"] = slot
    copied["archive_bytes"] = slot.stat().st_size
    item = dict(case["item"])
    item["path"] = slot
    copied["item"] = item
    return copied


def _run_case(
    case: dict[str, Any],
    *,
    workspace: BenchmarkWorkspace,
    worker_path: Path,
    dll_path: Path,
    runs: int,
    timeout_seconds: float,
    sample_interval: float,
    prefetch_enabled: bool,
    prefetch_window_kib: int,
    prefetch_depth: int,
    run_start: int = 0,
    copy_slots: list[Path] | None = None,
) -> list[dict[str, Any]]:
    prior_environment = {
        name: os.environ.get(name)
        for name in (
            "SUNPACK_SEVENZIP_PROFILE_READS",
            "SUNPACK_SEVENZIP_PREFETCH",
            "SUNPACK_SEVENZIP_PREFETCH_WINDOW_KIB",
            "SUNPACK_SEVENZIP_PREFETCH_DEPTH",
        )
    }
    worker: _NativeWorkerProcess | None = None
    sampler = ProcessSampler(interval_seconds=sample_interval)
    sampling = False
    rows: list[dict[str, Any]] = []
    try:
        os.environ["SUNPACK_SEVENZIP_PROFILE_READS"] = "1"
        os.environ["SUNPACK_SEVENZIP_PREFETCH"] = "1" if prefetch_enabled else "0"
        os.environ["SUNPACK_SEVENZIP_PREFETCH_WINDOW_KIB"] = str(prefetch_window_kib)
        os.environ["SUNPACK_SEVENZIP_PREFETCH_DEPTH"] = str(prefetch_depth)
        worker = _NativeWorkerProcess(str(worker_path), None)
        sampler.start()
        sampling = True
        for run in range(run_start, run_start + runs):
            mode = "on" if prefetch_enabled else "off"
            if copy_slots:
                case = _cold_copy_case(case, copy_slots[run % len(copy_slots)])
            output = workspace.outputs / str(case["case_id"]).replace(":", "-") / mode / f"run-{run}"
            job = _case_job(case["item"], job_id=f"read-pattern-{case['case_id']}-{run}", output_dir=output, dll_path=dll_path)
            try:
                row = _run_job(worker, job, timeout_seconds=timeout_seconds, sampler=sampler)
            finally:
                if not workspace.keep_workdir:
                    shutil.rmtree(output, ignore_errors=True)
            row.update({key: case[key] for key in ("case_id", "format", "variant", "workload", "archive_bytes", "payload_bytes")})
            row["run"] = run
            row["prefetch_recommendation"] = _prefetch_recommendation(row)
            row["decoder_verdict"] = _starvation_verdict(row)
            rows.append(row)
    finally:
        if sampling:
            sampler.stop()
        if worker is not None:
            worker.close()
        for name, previous in prior_environment.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
    return rows


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    columns = [
        "case_id", "format", "variant", "run", "archive_bytes", "payload_bytes", "status", "passed", "worker_wall_ms",
        "input_stream_mode", "input_logical_read_call_count", "input_seek_count", "input_seek_forward_bytes",
        "input_seek_backward_bytes", "input_sequential_read_bytes", "input_nonsequential_read_bytes",
        "input_sequential_read_ratio", "input_sequential_run_count", "input_max_sequential_run_bytes",
        "input_read_file_call_count", "input_read_file_wall_ms", "input_read_file_max_wall_ms",
        "input_read_file_wall_ratio", "input_prefetch_enabled", "input_prefetch_hit_count",
        "input_prefetch_miss_count", "input_prefetch_invalidation_count", "input_prefetch_consumer_wait_ms",
        "input_prefetch_issued_count", "input_prefetch_published_count", "input_prefetch_orphaned_count",
        "input_consumer_read_blocking_ms", "prefetch_recommendation", "decoder_verdict",
    ]
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Profile native worker input read/seek patterns for generated archives.")
    parser.add_argument("--format", action="append", choices=GENERATED_FORMATS, dest="formats")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--small-files", type=int, default=DEFAULT_SMALL_FILES)
    parser.add_argument("--large-files", type=int, default=DEFAULT_LARGE_FILES)
    parser.add_argument("--large-file-mib", type=int, default=DEFAULT_LARGE_FILE_MIB)
    parser.add_argument("--large-content", choices=("mixed", "random"), default="mixed")
    parser.add_argument(
        "--archive",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help=(
            "Benchmark a pre-built archive instead of the generated corpus.  Repeatable. "
            "Lets one matrix cover several compression methods and sizes without rebuilding."
        ),
    )
    parser.add_argument(
        "--corpus-cache-root",
        type=Path,
        default=ROOT / "benchmarks" / ".cache" / "worker-read-patterns",
        help="Persistent corpus cache shared by repeated rounds of the same parameters.",
    )
    parser.add_argument(
        "--rebuild-corpus",
        action="store_true",
        help="Ignore the persistent corpus cache and rebuild the generated archives.",
    )
    parser.add_argument("--7z-variant", action="append", choices=("solid", "non-solid"), dest="seven_zip_variants")
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--sample-interval", type=float, default=0.02)
    parser.add_argument(
        "--prefetch",
        choices=("on", "off", "compare"),
        default="on",
        help="Enable prefetch subject to the production format policy, disable it, or compare both.",
    )
    parser.add_argument("--prefetch-window-kib", type=int, default=512)
    parser.add_argument("--prefetch-depth", type=int, default=2)
    parser.add_argument(
        "--copy-to",
        type=Path,
        help=(
            "Copy each archive to this directory before every run and benchmark the copy. "
            "A freshly written path has no cached pages, which is the only reliable way to "
            "measure cold-cache behaviour without a cache-clearing utility."
        ),
    )
    parser.add_argument(
        "--copy-slots",
        type=int,
        default=2,
        help="How many rotating copy slots to keep when --copy-to is set.",
    )
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    if min(args.runs, args.small_files, args.large_files, args.large_file_mib) < 1:
        parser.error("--runs, --small-files, --large-files, and --large-file-mib must be positive")
    if args.timeout_seconds <= 0 or args.sample_interval <= 0:
        parser.error("--timeout-seconds and --sample-interval must be positive")
    if not 64 <= args.prefetch_window_kib <= 16 * 1024 or not 1 <= args.prefetch_depth <= 8:
        parser.error("--prefetch-window-kib must be 64..16384 and --prefetch-depth must be 1..8")
    formats = list(dict.fromkeys(args.formats)) if args.formats else list(GENERATED_FORMATS)
    seven_zip_variants = set(args.seven_zip_variants or ("solid", "non-solid"))
    if args.large_content != "mixed" and not args.archive and not set(formats) <= {"7z", "rar-split", "tar"}:
        parser.error("--large-content random is currently supported only with --format 7z, --format rar-split, and --format tar")
    worker_path = Path(get_sevenzip_bridge_worker_path()).resolve()
    dll_path = Path(get_7z_dll_path()).resolve()
    if not worker_path.is_file() or not dll_path.is_file():
        parser.error("the native worker and 7z.dll must both exist")

    scenario = "extraction.worker-read-patterns"
    with BenchmarkWorkspace(scenario, results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
            explicit_bytes = args.large_files * args.large_file_mib * MIB
            if args.archive:
                cases = _explicit_archives(args.archive, payload_bytes=explicit_bytes)
                corpus_info = {
                    "source": "explicit-archives",
                    "payload_bytes_per_case": explicit_bytes,
                    "cases": [
                        {
                            "case_id": case["case_id"],
                            "format": case["format"],
                            "variant": case["variant"],
                            "path": str(case["archive_path"]),
                            "archive_bytes": case["archive_bytes"],
                        }
                        for case in cases
                    ],
                }
            else:
                corpus, cached = _cached_corpus(
                    workspace.corpus,
                    cache_root=args.corpus_cache_root,
                    small_files=args.small_files,
                    large_files=args.large_files,
                    large_file_mib=args.large_file_mib,
                    rebuild=args.rebuild_corpus,
                )
                cases, corpus_info = _build_cases(
                    workspace,
                    formats,
                    small_files=args.small_files,
                    large_files=args.large_files,
                    large_file_mib=args.large_file_mib,
                    seven_zip_variants=seven_zip_variants,
                    large_content=args.large_content,
                    cached_corpus=corpus,
                    cache_info={**cached, "content": args.large_content},
                )
            if not cases:
                raise RuntimeError("no archive cases are available")
            copy_slots: list[Path] = []
            if args.copy_to:
                if args.copy_slots < 1:
                    parser.error("--copy-slots must be positive")
                args.copy_to.mkdir(parents=True, exist_ok=True)
                copy_slots = [args.copy_to / f"cold-{index}" for index in range(args.copy_slots)]
            rows: list[dict[str, Any]] = []
            failures: list[dict[str, str]] = []
            for index, case in enumerate(cases, start=1):
                print(f"[{index}/{len(cases)}] {case['case_id']} archive={case['archive_bytes']}B", flush=True)
                try:
                    if args.prefetch == "compare":
                        for run in range(args.runs):
                            modes = ("off", "on") if run % 2 == 0 else ("on", "off")
                            for mode in modes:
                                rows.extend(_run_case(
                                    case,
                                    workspace=workspace,
                                    worker_path=worker_path,
                                    dll_path=dll_path,
                                    runs=1,
                                    timeout_seconds=args.timeout_seconds,
                                    sample_interval=args.sample_interval,
                                    prefetch_enabled=mode == "on",
                                    prefetch_window_kib=args.prefetch_window_kib,
                                    prefetch_depth=args.prefetch_depth,
                                    run_start=run,
                                    copy_slots=copy_slots,
                                ))
                    else:
                        rows.extend(_run_case(
                            case,
                            workspace=workspace,
                            worker_path=worker_path,
                            dll_path=dll_path,
                            runs=args.runs,
                            timeout_seconds=args.timeout_seconds,
                            sample_interval=args.sample_interval,
                            prefetch_enabled=args.prefetch == "on",
                            prefetch_window_kib=args.prefetch_window_kib,
                            prefetch_depth=args.prefetch_depth,
                            copy_slots=copy_slots,
                        ))
                except Exception as exc:
                    failures.append({"case_id": str(case["case_id"]), "error": repr(exc)})
                    print(f"  ERROR {exc}", flush=True)
            table = _pattern_table(rows)
            starvation = [row for row in rows if row.get("decoder_verdict")]
            starved_rows = [row for row in rows if str(row.get("decoder_verdict", "")).startswith("starving")]
            summary = {
                "sample_count": len(rows),
                "passed_samples": sum(bool(row.get("passed")) for row in rows),
                "all_passed": bool(rows) and all(bool(row.get("passed")) for row in rows) and not failures,
                "median_worker_wall_ms": _median([row.get("worker_wall_ms") for row in rows]),
                "median_read_file_wall_ratio": _median([row.get("input_read_file_wall_ratio") for row in rows]),
                "median_prefetch_miss_ratio": _median([
                    int(row["input_prefetch_miss_count"]) / (int(row["input_prefetch_hit_count"]) + int(row["input_prefetch_miss_count"]))
                    for row in rows
                    if row.get("input_prefetch_hit_count") is not None
                    and (int(row["input_prefetch_hit_count"]) + int(row["input_prefetch_miss_count"])) > 0
                ]),
                "starved_sample_count": len(starved_rows),
                "decoder_verdicts": {
                    verdict: sum(1 for row in rows if row.get("decoder_verdict") == verdict)
                    for verdict in sorted({str(row.get("decoder_verdict")) for row in starvation})
                },
                "case_failures": failures,
            }
            report = {
                "parameters": {
                "runs": args.runs,
                "formats": formats,
                "seven_zip_variants": sorted(seven_zip_variants),
                "payload": corpus_info.get("payload"),
                "explicit_archives": [case["case_id"] for case in cases] if args.archive else [],
                "prefetch": {"mode": args.prefetch, "window_kib": args.prefetch_window_kib, "depth": args.prefetch_depth},
                },
                "method": {
                    "timed_region": "synchronous ReadFile calls within native IInStream implementations",
                    "logical_trace": "successful IInStream reads and seeks requested by 7z.dll",
                    "prefetch_caveat": "The on mode enables prefetch where the production format policy permits it. Consumer blocking is synchronous ReadFile time plus any wait for the current prefetch epoch; background ReadFile time is intentionally not added because it can overlap decompression.",
                    "decoder_verdict": "A prefetch miss means the consumer had to read the file itself and the prefetch epoch was discarded; misses beyond the few non-window-aligned reads (archive tails, header probes) indicate decoder starvation.",
                },
                "environment": {
                    "worker_path": str(worker_path),
                    "worker_size_bytes": worker_path.stat().st_size,
                    "worker_sha256": hashlib.sha256(worker_path.read_bytes()).hexdigest()[:16],
                    "seven_zip_dll_path": str(dll_path),
                    "python": sys.version,
                },
                "corpus": corpus_info,
                "results": rows,
                "summary": summary,
                "artifacts": {"result_dir": str(workspace.result_dir), "read_pattern_table": str(workspace.result_dir / "read-patterns.md")},
            }
            rendered = render_report(report_from_payload(scenario, report))
            workspace.write_result_text("report.json", rendered)
            workspace.write_result_text("read-patterns.md", table)
            _write_csv(workspace.result_dir / "results.csv", rows)
            if args.json_out:
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(rendered, encoding="utf-8")
            print(table)
            print(rendered)
            return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
