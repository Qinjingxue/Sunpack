from __future__ import annotations

import json
import os
from pathlib import Path
import random
import subprocess
import sys
import zipfile

from .build import CACHE, ROOT, command, environment
from .cases import Case, PROTOCOL
from .capture import instrumented_module


def invoke_json(arguments, *, env=None) -> dict:
    result = subprocess.run([str(x) for x in arguments], env=env or environment(), cwd=ROOT,
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        # A crashed baseline is part of the coverage result, never silently
        # discarded or replaced with an invented timing score.
        return {"status": "invalid", "error": "Native process did not return one JSON result",
                "exit_code": result.returncode, "stdout": result.stdout[-4000:], "stderr": result.stderr[-4000:]}
    if result.returncode and data.get("status") == "ok":
        raise RuntimeError("Successful result with failed process exit")
    data["exit_code"] = result.returncode
    if result.stderr:
        data["stderr"] = result.stderr
    return data


def public_cases(executable: Path, suite: str, *, fetch: bool) -> tuple[list[Case], dict]:
    checkout = CACHE / "sources/croaring"
    families = ["census-income", "weather_sept_85"]
    missing = [family for family in families if not (checkout / "benchmarks/realdata" / family).is_dir()]
    if missing:
        if not fetch:
            raise RuntimeError("Pinned public data missing; --fetch retrieves the CRoaring reference corpora")
        command(["git", "-C", checkout, "sparse-checkout", "add", *["/benchmarks/realdata/" + x + "/" for x in families], "/benchmarks/realdata/README.md"])
    selected = []
    inventory = {}
    rng = random.Random(PROTOCOL["seeds"]["selection"])
    per_bin = 1 if suite == "quick" else 3
    for family in families:
        directory = checkout / "benchmarks/realdata" / family
        data = invoke_json([executable, "--mode", "inventory", "--directory", directory])
        if data["status"] != "ok":
            raise RuntimeError(data)
        bins = {}
        for row in data["sets"]:
            bins.setdefault(int(row["n"]).bit_length(), []).append(row)
        chosen = []
        for key, rows in sorted(bins.items()):
            rows = sorted(rows, key=lambda x: x["path"])
            chosen.extend(rng.sample(rows, min(per_bin, len(rows))))
        inventory[family] = {"total_sets": len(data["sets"]), "length_bins": {str(k): len(v) for k, v in bins.items()}, "selected": chosen}
        for row in chosen:
            path = Path(row["path"])
            selected.append(Case(f"{family}-{path.stem}", "public-" + family,
                                 {"integer-set": str(path), "seed": PROTOCOL["seeds"]["evaluation"][0]},
                                 {"repository": "RoaringBitmap/CRoaring", "commit": "1575f7d45eb1b7808a5817d7216ba0441bb6729b",
                                  "path": path.relative_to(checkout).as_posix(), "selection": "seeded sampling by native-measured log2 cardinality", "n": row["n"]}))
    return selected, inventory


def real_cases(workspace, *, module_root: Path | None = None) -> tuple[list[Case], list[dict]]:
    from tests.helpers.real_archives import ArchiveFixtureFactory
    from tests.real.plan5_embedded_archives.plan5_support import build_large_embedded_case
    from sunpack_native import fast_hash128_file

    module_root = module_root or instrumented_module()
    root = workspace.corpus / "real"
    root.mkdir()
    factory = ArchiveFixtureFactory()
    artifacts = []
    for name, fmt, options in [
        ("zip-stored", "zip", {"compression_level": 0}),
        ("tar", "tar", {}),
        ("xz", "xz", {}),
        ("encrypted-7z", "7z", {"password": "sunpack-hit-index-fixture"}),
        ("disguised-split-carrier", "rar", {"password": "sunpack-hit-index-fixture", "split": True,
            "split_volume_size": 65536, "carrier": "png", "disguise_ext": ".opaque"}),
    ]:
        case = factory.create(root, name, fmt, payload_size=262144, **options)
        artifacts.append({"name": name, "path": case.entry_path, "required_roots": [(fmt, 0)] if not options.get("split") else [],
                          "recipe": {"factory": "ArchiveFixtureFactory", "format": fmt, **options}})
        if options.get("split"):
            siblings = sorted(p for p in case.archive_dir.iterdir() if p.is_file() and p != case.entry_path)
            if siblings:
                artifacts.append({"name": "split-nonhead", "path": siblings[-1], "required_roots": [],
                                  "recipe": {"same_case": name, "physical_volume": "last"}})
    for count in [2048, 32768]:
        path = root / f"zip-entries-{count}.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            for i in range(count):
                archive.writestr(f"entry-{i:08d}.txt", b"hit-index-fixture\n")
        artifacts.append({"name": f"zip-many-{count}", "path": path, "required_roots": [("zip", 0)],
                          "recipe": {"producer": "stdlib zipfile ZIP_STORED", "entries": count, "payload": "hit-index-fixture\\n"}})
    for count in [2048, 32768]:
        path = root / f"zip-variable-{count}.zip"
        sizes = random.Random(1729 + count)
        contents = random.Random(7919 + count)
        names = random.Random(104729 + count)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            for i in range(count):
                bucket = sizes.randrange(100)
                length = sizes.randrange(513) if bucket < 70 else sizes.randrange(512, 8193) if bucket < 99 else sizes.randrange(65536, 262145)
                name = f"dir-{i % 17}/entry-{i:08d}-{'x' * names.randrange(48)}.bin"
                archive.writestr(name, contents.randbytes(length))
        artifacts.append({"name": f"zip-variable-{count}", "path": path, "required_roots": [("zip", 0)],
                          "recipe": {"producer": "stdlib zipfile ZIP_STORED", "entries": count,
                                     "size_mixture": "70% U[0,512],29% U[512,8192],1% U[65536,262144]",
                                     "size_seed": 1729 + count, "content_seed": 7919 + count,
                                     "name_seed": 104729 + count, "purpose": "irregular offsets, wide gaps and multiple IOCP jobs"}})
    nested = root / "nested.opaque"
    with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.write(artifacts[0]["path"], "inner.opaque")
    artifacts.append({"name": "nested-stored", "path": nested, "required_roots": [("zip", 0)],
                      "recipe": {"producer": "ZIP_STORED wrapping zip-stored", "layers": 2}})
    empty = root / "empty.opaque"
    empty.write_bytes(b"")
    artifacts.append({"name": "empty-file", "path": empty, "required_roots": [], "recipe": {"bytes": 0}})
    mixed = build_large_embedded_case(root / "mixed", count=128, payload_size=64)
    artifacts.append({"name": "mixed-carrier-128", "path": mixed.file_path,
                      "required_roots": [(x.archive_format, x.offset) for x in mixed.segments],
                      "recipe": {"producer": "build_large_embedded_case", "count": 128, "payload_size": 64}})
    cases = []
    manifest = []
    env = environment().copy()
    env["PYTHONPATH"] = os.pathsep.join([str(module_root), str(ROOT)])
    for artifact in artifacts:
        name, path = artifact["name"], artifact["path"]
        input_path = workspace.preserve(path, f"corpus/{name}{path.suffix}")
        trace = workspace.result_dir / f"corpus/{name}.hits"
        result = invoke_json([sys.executable, "-m", "benchmarks.hit_index.capture", "--path", input_path, "--trace", trace], env=env)
        if result["status"] != "ok" or not result["complete"] or result["read_bytes"] != input_path.stat().st_size:
            raise RuntimeError(f"Incomplete real scan: {name}: {result}")
        roots = {(x["format"], int(x["offset"])) for x in result["candidates"]}
        missing = set(artifact["required_roots"]) - roots
        if missing:
            raise RuntimeError(f"Fixture ground-truth roots absent ({name}): {sorted(missing)[:8]}")
        workspace.write_result_json(f"corpus/{name}.capture.json", result)
        row = {"name": name, "input": str(input_path), "trace": str(trace), "bytes": input_path.stat().st_size,
               "input_xxh128": fast_hash128_file(input_path), "trace_xxh128": fast_hash128_file(trace),
               "required_roots": artifact["required_roots"], "recipe": artifact["recipe"],
               "semantic_reference": {"hits": result["hits"], "candidates": result["candidates"]}}
        manifest.append(row)
        cases.append(Case(name, "real-matcher-trace", {"trace": str(trace), "seed": PROTOCOL["seeds"]["evaluation"][0]},
                          {"capture_stage": "actual retained matcher facts, before prepare", "input_xxh128": row["input_xxh128"],
                           "trace_xxh128": row["trace_xxh128"], "instrumented_timing_excluded": True}))
        print(f"captured {name}", flush=True)
    return cases, manifest


def full_scan_cases(manifest: list[dict], blocks: int, *, candidate_module_root: Path | None = None) -> list[dict]:
    from sunpack_native import fast_hash128_file
    rows = []
    versions = [("installed", None)] + ([("candidate", candidate_module_root)] if candidate_module_root else [])
    for block in range(blocks):
        for case in manifest:
            if fast_hash128_file(Path(case["input"])) != case["input_xxh128"]:
                raise RuntimeError("Frozen real input changed")
            for name, root in (versions if block % 2 == 0 else list(reversed(versions))):
                env = environment().copy()
                env.pop("SUNPACK_BENCH_HIT_TRACE", None)
                env["PYTHONPATH"] = os.pathsep.join(([str(root)] if root else []) + [str(ROOT)])
                result = invoke_json([sys.executable, "-m", "benchmarks.hit_index.capture", "--path", case["input"]], env=env)
                reference = case["semantic_reference"]
                if (result.get("status") != "ok" or not result.get("complete")
                        or result.get("read_bytes") != case["bytes"]
                        or result.get("hits") != reference["hits"] or result.get("candidates") != reference["candidates"]):
                    result["status"] = "invalid"
                    result["error"] = "Full scan differs from frozen semantic reference"
                result.update(case=case["name"], block=block, version=name)
                rows.append(result)
    return rows
