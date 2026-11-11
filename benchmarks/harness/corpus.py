"""Generated archive fixtures shared by native boundary benchmarks."""
from __future__ import annotations
import json
import os
import random
import shutil
import subprocess
import time
import zlib
from pathlib import Path
from typing import Any, Callable
ROOT = Path(__file__).resolve().parents[2]
SEVEN_ZIP = ROOT / "tools/7z.exe"
RAR = ROOT / "tools/Rar.exe"
ZSTD = ROOT / "tools/zstd.exe"
SUPPORTED = ("zip", "7z", "rar", "gz", "bz2", "xz", "zst", "tar", "tgz", "tbz2", "txz", "tzst")
GENERATED_FORMATS = (*SUPPORTED, "7z-split", "rar-split")
DEFAULT_CACHE_ROOT = ROOT / "benchmarks/.cache/extraction-native"
DEFAULT_SUBPROCESS_TIMEOUT = None

def _remove_cache_path(path: Path, root: Path) -> None:
    resolved = path.resolve()
    if resolved == root.resolve() or root.resolve() not in resolved.parents:
        raise ValueError(f"cache cleanup escaped root: {resolved}")
    if path.exists():
        shutil.rmtree(path)

def _run_7z(command: list[str]) -> bool:
    try:
        result = subprocess.run(
            [str(SEVEN_ZIP), *command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=DEFAULT_SUBPROCESS_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
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
    except (OSError, subprocess.TimeoutExpired):
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
    except (OSError, subprocess.TimeoutExpired):
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
    except (OSError, subprocess.TimeoutExpired):
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
            except (OSError, subprocess.TimeoutExpired):
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
    *,
    payloads: dict[str, Path] | None = None,
    copy_file: Callable[[Path, Path], Any] = shutil.copy2,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    root.mkdir(parents=True, exist_ok=True)
    if payloads is None:
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

        # Avoid thousands of tiny volumes in routine throughput runs.
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
                copy_file(target, alias_target)
                corpus[f"{workload}:{alias}"] = {"workload": workload, "format": alias, "path": alias_target}
            else:
                skipped[f"{workload}:{ext}"] = "bundled 7-Zip cannot create this format"

        zstd_target = root / f"{workload}.tar.zst"
        if progress:
            progress(f"creating {workload}:zst (+tzst)")
        if tar_source is not None and _create_zstd_archive(zstd_target, tar_source):
            corpus[f"{workload}:zst"] = {"workload": workload, "format": "zst", "path": zstd_target}
            tzst_target = root / f"{workload}.tzst"
            copy_file(zstd_target, tzst_target)
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
        stat = tool.stat() if tool.exists() else None
        tool_fingerprints.append((tool.name, stat.st_size if stat else 0, stat.st_mtime_ns if stat else 0))
    payload = {
        "schema": 1,
        "small_files": small_files,
        "large_files": large_files,
        "large_file_mib": large_file_mib,
        "tools": tool_fingerprints,
        "formats": GENERATED_FORMATS,
    }
    return f"s{small_files}-l{large_files}-m{large_file_mib}-{zlib.crc32(json.dumps(payload, sort_keys=True).encode()):08x}"

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
        _remove_cache_path(staging, cache_root)
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
            _remove_cache_path(entry, cache_root)
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
