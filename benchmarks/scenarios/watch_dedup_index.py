"""Measure the production Watch dedup index through an opt-in Rust test binary.

No extraction/discovery/GUI timing: inputs are already-confirmed ArchiveInput
models of valid stored ZIP files. Each result uses a fresh test process/index.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import uuid
from zipfile import ZipFile, ZipInfo, ZIP_STORED


ROOT = Path(__file__).resolve().parents[2]
TEST = "runtime::watch::dedup::bench::measure_watch_dedup_index"
PAYLOAD_BLOCK = bytes((j * 31 + j // 79) % 256 for j in range(64 * 1024))
SHAPES = ("same_size_duplicate", "same_size_distinct", "different_size_distinct", "hardlink")


def build(profile):
    result = subprocess.run([
        "cargo", "test", "--locked", "--manifest-path", str(ROOT / "sunpack/Cargo.toml"),
        "-p", "sunpack-runtime", "--lib", "--profile", profile, "--no-run", "--message-format=json",
    ], cwd=ROOT, text=True, encoding="utf-8", errors="replace", capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr + result.stdout)
    for line in result.stdout.splitlines():
        row = json.loads(line)
        if row.get("reason") == "compiler-artifact" and row.get("executable") and row["target"]["name"] == "sunpack_runtime":
            return Path(row["executable"])
    raise RuntimeError("Cargo did not report the runtime test executable")


def write_zip(path, length, identity=0):
    # Large read-heavy fixtures stay bounded too: never materialize the ZIP or
    # its payload as a whole Python bytes object.
    block = PAYLOAD_BLOCK
    info = ZipInfo("payload.bin", date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_STORED
    info.file_size = length
    with ZipFile(path, "w") as archive, archive.open(info, "w") as writer:
        first = True
        while length:
            chunk = block[:min(length, len(block))]
            if first:
                chunk = identity.to_bytes(8, "little") + chunk[8:]
                first = False
            writer.write(chunk)
            length -= len(chunk)


def fixtures(folder, shape, count, payload_size):
    folder.mkdir()
    original = folder / "000/00000.zip"
    for i in range(count):
        path = folder / f"{i // 512:03}" / f"{i:05}.zip"
        path.parent.mkdir(exist_ok=True)
        if shape == "hardlink" and i % 512:
            # NTFS has a finite per-object hard-link limit; bounded groups avoid
            # changing the workload into an unsupported 8192-link single object.
            os.link(path.parent / f"{i - i % 512:05}.zip", path)
        elif shape in ("hardlink", "same_size_duplicate") and i:
            shutil.copyfile(original, path)
        else:
            length = payload_size + (i if shape == "different_size_distinct" else 0)
            write_zip(path, length, i if shape.endswith("distinct") else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("ci", "release"), default="ci")
    parser.add_argument("--binary", type=Path, help="Use an already-built runtime lib test executable")
    parser.add_argument("--counts", default="512,2048,8192")
    parser.add_argument("--modes", default="none,file_id,hash")
    parser.add_argument("--shapes", default=",".join(SHAPES))
    parser.add_argument("--phases", default="online,baseline")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--payload-bytes", type=int, default=4096)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()
    counts = [int(n) for n in args.counts.split(",")]
    modes, shapes, phases = (v.split(",") for v in (args.modes, args.shapes, args.phases))
    if (not counts or min(counts) < 1 or args.runs < 1 or args.payload_bytes < 8
            or set(modes) - {"none", "file_id", "hash"} or set(shapes) - set(SHAPES)
            or set(phases) - {"online", "baseline"}):
        parser.error("invalid workload selection")
    binary = args.binary.resolve() if args.binary else build(args.profile)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    work = ROOT / "benchmarks/.work" / f"watch-dedup-{uuid.uuid4().hex}"
    work.mkdir(parents=True)
    output = args.output or ROOT / "benchmarks/results" / f"watch-dedup-{stamp}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "host":platform.platform(), "binary":str(binary), "profile":args.profile,
        "git_head":subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "payload_bytes":args.payload_bytes, "rows":[],
        "method":"Fresh process/index per result; none is the harness lower bound (production Watch bypasses admission entirely). Memory is whole-process, not isolated index heap; deterministic valid ZIP_STORED fixtures; measured native admission only, excluding fixture creation, process launch, discovery and extraction. Online unique-size fingerprints and all baseline fingerprints are deferred; matching live identities do not require hashing. Filesystem cache retained, no claim of cold-disk throughput. Private/RSS delta measured within child; peak RSS includes process startup. WAL size includes framing; fsync finish reported separately. Hardlinks use groups of <=512 links. A fixed 512-file subtree rename/removal from recorded paths is measured separately from invalidate_tree; remaining index may be much larger.",
    }
    try:
        for shape in shapes:
            fixtures(work / shape, shape, max(counts), args.payload_bytes)
        for shape in shapes:
            for count in counts:
                for mode in modes:
                    for phase in phases:
                        for run in range(args.runs):
                            index = work / "indexes" / f"{shape}-{count}-{mode}-{phase}-{run}"
                            env = {**os.environ,
                                "SUNPACK_DEDUP_BENCH_ROOT":str(work / shape),
                                "SUNPACK_DEDUP_BENCH_INDEX":str(index),
                                "SUNPACK_DEDUP_BENCH_COUNT":str(count),
                                "SUNPACK_DEDUP_BENCH_MODE":mode,
                                "SUNPACK_DEDUP_BENCH_PHASE":phase,
                            }
                            result = subprocess.run([str(binary), "--exact", TEST, "--ignored", "--nocapture"],
                                                    cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace", capture_output=True)
                            if result.returncode:
                                raise RuntimeError(result.stdout + result.stderr)
                            line = next((line for line in result.stdout.splitlines() if line.startswith("SUNPACK_DEDUP_BENCH ")), None)
                            if line is None:
                                raise RuntimeError("Benchmark entry missing from binary: " + result.stdout)
                            row = json.loads(line.split(" ", 1)[1])
                            row.update(shape=shape, phase=phase, run=run)
                            report["rows"].append(row)
                            output.write_text(json.dumps(report, indent=2), encoding="utf-8")
                            print(json.dumps(row), flush=True)
    finally:
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        if args.keep_workdir:
            print(f"Kept fixtures: {work}")
        else:
            if (ROOT / "benchmarks/.work").resolve() not in work.resolve().parents:
                raise ValueError("Benchmark cleanup escaped its workspace")
            shutil.rmtree(work)
    print(f"Report: {output}")


if __name__ == "__main__":
    main()
