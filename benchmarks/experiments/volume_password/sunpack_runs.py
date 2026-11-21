"""Run the packaged CLI and a two-pass, fixed-layout black-box control."""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from benchmarks.harness.launcher import NativePackage


def save(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def invoke(pkg, args):
    start = time.perf_counter()
    p = subprocess.run(
        [pkg.launcher, *map(str, args)], cwd=pkg.data, env=pkg.env, capture_output=True
    )
    data = json.loads(p.stdout) if p.stdout.strip() else {}
    return dict(
        seconds=time.perf_counter() - start,
        args=list(map(str, args)),
        code=p.returncode,
        stdout=data,
        stderr=p.stderr.decode("utf-8", "replace"),
    )


def layout(item):
    plan = item.get("volume_attempts")
    if plan:
        # Freeze exactly one structurally proposed layout; honour the native slot order.
        slots = plan["layouts"][0]["slots"]
        used = set()
        result = []
        for slot in slots:
            choices = plan["domains"][slot["domain"]]["choices"]
            idx = next((v for v in choices if v not in used), None)
            if idx is None:
                return []
            used.add(idx)
            extent = plan["sources"][idx]
            source = Path(extent["path"])
            if extent["start"] != 0 or extent["end"] != source.stat().st_size:
                raise ValueError("fixtures require whole-file extents")
            result.append((source, slot["canonical_name"]))
        return result
    original = [Path(v) for v in item.get("all_parts") or [item["main_path"]]]
    # Preserve the no-password scan order even when later headers would contradict it.
    return [(p, p.name) for p in original]


def run(root, out, mode):
    cases = json.loads((root / "manifest.json").read_text())
    repo = Path(__file__).resolve().parents[3]
    records = 0

    def isolated(args):
        nonlocal records
        records += 1
        with NativePackage(
            out / ("pkg-" + mode) / name / str(records),
            launcher=repo / "dist/sunpack-x64/sunpack.exe",
        ) as pkg:
            cfgfile = pkg.data / "sunpack_config.json"
            cfg = json.loads(cfgfile.read_text())
            cfg["filesystem"] = {"scan_filters_enabled": False}
            save(cfgfile, cfg)
            observer = os.environ.get("RQ2_OBSERVER")
            if observer:
                capture = out / mode / name / "frames" / str(records)
                capture.mkdir(parents=True)
                worker = pkg.install / "tools/sunpack_sevenzip_worker.exe"
                worker.rename(worker.with_name("measured-worker.exe"))
                shutil.copyfile(observer, worker)
                pkg.env["RQ2_FRAMES"] = str(capture)
                save(capture / "call.json", list(map(str, args)))
            return invoke(pkg, args)

    for name, case in cases.items():
        if sys.argv[4:] and name not in sys.argv[4:]:
            continue
        folder = root / "visible" / name
        work = out / mode / name
        work.mkdir(parents=True)
        pw = [a for v in case["passwords"] for a in ("-p", v)]
        base = ["-j", "-npa", "-d"]
        scan = isolated(["scan", *base, *(pw if mode == "joint" else []), folder])
        save(work / "scan.json", scan)
        if "items" not in scan["stdout"]:
            raise RuntimeError(scan)
        commands = []

        def extract(source, target):
            commands.append(
                isolated(
                    ["extract", *base, "-nf", "-c", "k", "-o", target, *pw, source]
                )
            )

        preparation_seconds = 0.0
        if mode == "joint":
            extract(folder, work / "output")
        else:
            selections = []
            qualifications = []
            for i, item in enumerate(scan["stdout"].get("items", [])):
                prep = time.perf_counter()
                parts = layout(item)
                selections.append([(p.name, n) for p, n in parts])
                if not parts or item.get("volume_completeness") == "missing":
                    qualifications.append({"status": "no_complete_layout"})
                    continue
                private = work / "frozen" / str(i)
                private.mkdir(parents=True)
                fmt = item["format"]
                if fmt == "zip" and len(parts) > 1:
                    # Raw-slice corpus: one physical byte stream makes reordering impossible.
                    source = private / "locked.zip"
                    with source.open("wb") as stream:
                        for path, _ in parts:
                            with path.open("rb") as handle:
                                shutil.copyfileobj(handle, stream)
                elif fmt == "rar" and len(parts) > 1:
                    # Native RAR headers retain their own volume numbers. Reject any proposed
                    # correction of the frozen physical order, even if a re-scan could fix it.
                    frozen = []
                    for slot, (path, _) in enumerate(parts, 1):
                        dest = private / f"locked.part{slot:03}.rar"
                        shutil.copyfile(path, dest)
                        frozen.append(dest)
                    preparation_seconds += time.perf_counter() - prep
                    check = isolated(["scan", *base, *pw, private])
                    found = check["stdout"].get("items", [])
                    order = (
                        [Path(x) for x in found[0].get("all_parts", [])]
                        if len(found) == 1
                        else []
                    )
                    ok = order == frozen and not found[0].get("volume_attempts")
                    qualifications.append(
                        {
                            "status": "fixed" if ok else "order_not_confirmed",
                            "scan": check,
                        }
                    )
                    if not ok:
                        continue
                    source = private
                    extract(source, work / "output" / str(i))
                    continue
                else:
                    source = private / ("locked." + fmt)
                    shutil.copyfile(parts[0][0], source)
                preparation_seconds += time.perf_counter() - prep
                qualifications.append({"status": "fixed"})
                extract(source, work / "output" / str(i))
            save(work / "qualification.json", qualifications)
            save(work / "selected.json", selections)
            save(work / "preparation.json", preparation_seconds)
        save(work / "extract.json", commands)
        print(
            mode,
            name,
            len(scan["stdout"].get("items", [])),
            [x["code"] for x in commands],
            flush=True,
        )


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3])
