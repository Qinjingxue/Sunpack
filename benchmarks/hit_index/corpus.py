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
