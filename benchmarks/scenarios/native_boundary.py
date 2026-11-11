"""Coarse performance workloads through the same native launcher users run."""
from __future__ import annotations

import argparse
import ctypes
import json
import platform
import re
import shutil
import statistics
import subprocess
import time
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path

from benchmarks.harness.corpus import DEFAULT_CACHE_ROOT, _cached_corpus, _timed_seven_zip_extract
from benchmarks.harness.launcher import NativePackage
from benchmarks.harness.workspace import BenchmarkWorkspace
from benchmarks.watch_broker import SERVICE_ENV, isolated_broker_environment


def output_summary(root: Path):
    files = [path for path in root.rglob("*") if path.is_file()] if root.exists() else []
    return {"files": len(files), "bytes": sum(path.stat().st_size for path in files)}


def _copy_case(item, destination: Path, shape: str):
    destination.mkdir(parents=True, exist_ok=True)
    source = Path(item["path"])
    members = [source]
    if re.search(r"\.\d{3,}$", source.name):
        prefix = source.name.rsplit(".", 1)[0] + "."
        members = [path for path in source.parent.iterdir() if path.name.startswith(prefix) and path.suffix[1:].isdigit()]
    elif re.search(r"\.part\d+\.rar$", source.name, re.I):
        prefix = re.split(r"\.part\d+\.rar$", source.name, flags=re.I)[0]
        members = list(source.parent.glob(prefix + ".part*.rar"))
    for member in members:
        if member.is_file():
            shutil.copy2(member, destination / member.name)
    result = destination / source.name
    if shape == "disguised":
        # Keep numbered-volume suffixes: renaming only one part changes the
        # archive, rather than measuring disguised input discovery.
        if "split" not in item["format"]:
            result = result.rename(result.with_suffix(".opaque"))
    elif shape == "carrier":
        if "split" in item["format"]:
            raise ValueError("carrier shape requires a single-file archive")
        carrier = result.with_suffix(".carrier")
        with carrier.open("wb") as output, result.open("rb") as archive:
            output.write(b"unrelated carrier prefix\0" * 257)
            shutil.copyfileobj(archive, output, 1024 * 1024)
            output.write(b"unrelated trailer\0" * 19)
        result.unlink()
        result = carrier
    return result


def _case_rows(args, workspace):
    if args.archive:
        source = args.archive.resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        # Preserve volume siblings for externally supplied split inputs.
        return {"external": {"path": source, "format": args.archive_format or source.suffix.lstrip("."), "workload": "external"}}, {}, {"external": True}
    corpus, skipped, cache = _cached_corpus(
        workspace.corpus, cache_root=args.cache_root, small_files=args.small_files,
        large_files=args.large_files, large_file_mib=args.large_file_mib, rebuild=args.rebuild_corpus,
    )
    selected = set(args.formats.split(",")) if args.formats else None
    return {key: item for key, item in corpus.items() if selected is None or item["format"] in selected}, skipped, cache


def _configure_watch(app, args, inputs, outputs, *, live=False):
    path = app.data / "sunpack_config.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    config["recursive_extract"] = args.recursive
    if live:
        # Removing the isolated input is the observable success boundary after
        # extraction and post-processing, even for empty or multi-file outputs.
        config["post_extract"]["archive_cleanup_mode"] = "d"
    path.write_text(json.dumps(config), encoding="utf-8")
    (app.data / "builtin_passwords.json").write_text(
        json.dumps({"passwords": [{"value": value} for value in args.password]}), encoding="utf-8",
    )
    app.run("watch", "add", "-R", "-d", "-o", outputs, inputs)


@contextmanager
def _name_changes(directory):
    """Wake for native file-name changes instead of polling the watched tree."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.FindFirstChangeNotificationW.argtypes = (wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD)
    kernel.FindFirstChangeNotificationW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.FindNextChangeNotification.argtypes = (wintypes.HANDLE,)
    kernel.FindCloseChangeNotification.argtypes = (wintypes.HANDLE,)
    handle = kernel.FindFirstChangeNotificationW(str(directory), True, 0x3)  # File and directory names.
    if handle in (None, ctypes.c_void_p(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())

    def wait():
        if kernel.WaitForSingleObject(handle, 0xFFFFFFFF) != 0:
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.FindNextChangeNotification(handle):
            raise ctypes.WinError(ctypes.get_last_error())

    try:
        yield wait
    finally:
        kernel.FindCloseChangeNotification(handle)


def _watch_arrivals(app, workspace, args, corpus, skipped):
    inputs = workspace.work / "arrivals"
    inputs.mkdir()
    staging = workspace.work / "arrival-staging"
    staging.mkdir()
    _configure_watch(app, args, inputs, workspace.outputs, live=True)
    app.run("watch", "start", "--no-tray", require_broker=True)
    rows = []
    sampler = app.sampler()
    with _name_changes(inputs) as wait, sampler:
        for run in range(args.runs):
            if run and args.arrival_interval_ms:
                time.sleep(args.arrival_interval_ms / 1000)
            staged = []
            for key, item in corpus.items():
                if args.shape == "carrier" and "split" in item["format"]:
                    skipped[key] = "carrier shape excludes multi-file volume sets"
                    continue
                for index in range(args.copies):
                    name = f"round-{run}-{key.replace(':', '-')}-{index}"
                    folder = staging / name
                    source = _copy_case(item, folder, args.shape)
                    peers = list(folder.iterdir())
                    if len(peers) > 1:
                        # Publish the complete split set together under a new
                        # directory, preserving its original member names.
                        destination = inputs / name
                        staged.append((key, folder, destination, [destination / peer.name for peer in peers]))
                    else:
                        destination = inputs / f"{name}{source.suffix}"
                        staged.append((key, source, destination, [destination]))
            if not staged:
                raise ValueError("No Watch arrivals selected")
            first_sample = len(sampler.samples)
            started = time.perf_counter()
            pending = []
            for key, source, destination, members in staged:
                # Time from publication start, not corpus generation. Rename
                # publishes a file which was fully written outside the root.
                arrived = time.perf_counter()
                source.replace(destination)
                pending.append((key, destination, members, arrived))
            arrivals = []
            while pending:
                remaining = []
                for key, destination, members, arrived in pending:
                    if any(member.exists() for member in members):
                        remaining.append((key, destination, members, arrived))
                    else:
                        arrivals.append({"case": key, "input": destination.name,
                                         "seconds": time.perf_counter() - arrived})
                pending = remaining
                if pending:
                    wait()
            elapsed = time.perf_counter() - started
            sampler.take()
            end_sample = len(sampler.samples)
            rows.append({
                "case": "live-arrival", "run": run, "seconds": elapsed, "arrivals": arrivals,
                "sample_range": [first_sample, end_sample],
                **app.memory_result(sampler.samples[first_sample:end_sample], require_broker=True),
            })
            for _, source, _, _ in staged:
                if source.parent != staging:
                    source.parent.rmdir()
            print(f"Watch wave {run + 1}: {len(arrivals)} arrivals in {elapsed:.3f}s", flush=True)
    app.run("watch", "stop")
    return rows, [sample.to_dict() for sample in sampler.samples]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("scan", "extract", "memory", "passwords", "watch"))
    parser.add_argument("--archive", type=Path, help="Use an existing archive and its volume siblings.")
    parser.add_argument("--archive-format", help="Format for raw 7-Zip comparison of composite streams.")
    parser.add_argument("--launcher", type=Path, help="Packaged sunpack.exe; runtime and tools must be siblings.")
    parser.add_argument("--profile", default="release", choices=("release", "ci"))
    parser.add_argument("--arch", default="x64", choices=("x64", "arm64"))
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--copies", type=int, default=1, help="Independent archive copies per case in directory/Watch workloads.")
    parser.add_argument("--sample-ms", type=float, default=50)
    parser.add_argument("--formats", default="zip,7z,tar,gz,bz2,xz,zst,7z-split,rar,rar-split")
    parser.add_argument("--shape", choices=("ordinary", "disguised", "carrier"), default="ordinary")
    parser.add_argument("--small-files", type=int, default=2048)
    parser.add_argument("--large-files", type=int, default=2)
    parser.add_argument("--large-file-mib", type=int, default=16)
    parser.add_argument("--ordinary-files", type=int, default=10000, help="Additional non-archive files for scan.")
    parser.add_argument("--password-entries", type=int, default=10000)
    parser.add_argument("--password", action="append", default=[])
    parser.add_argument("--compare-7z", action="store_true")
    parser.add_argument("--cold", action="store_true", help="Shut down the resident runtime between rounds.")
    parser.add_argument("--live-arrival", action="store_true", help="Feed new files to one continuous Watch session.")
    parser.add_argument("--arrival-interval-ms", type=float, default=0, help="Idle time between live Watch waves.")
    parser.add_argument("--recursive", default="*")
    parser.add_argument("--cache-root", type=Path, default=DEFAULT_CACHE_ROOT)
    parser.add_argument("--rebuild-corpus", action="store_true")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args(argv)
    if args.runs <= 0 or args.sample_ms <= 0 or args.copies <= 0:
        parser.error("--runs, --copies and --sample-ms must be positive")
    if args.mode == "watch" and not isolated_broker_environment():
        parser.error("Run Watch through `python -m benchmarks watch` for an isolated broker.")
    if args.live_arrival and (args.mode != "watch" or args.cold):
        parser.error("--live-arrival requires Watch without --cold")
    if args.arrival_interval_ms < 0 or (args.arrival_interval_ms and not args.live_arrival):
        parser.error("--arrival-interval-ms requires live Watch and must be nonnegative")
    with BenchmarkWorkspace(f"native-{args.mode}", results_root=args.results_root, keep_workdir=args.keep_workdir) as workspace:
        with NativePackage(workspace.work, launcher=args.launcher, profile=args.profile, arch=args.arch,
                           sample_ms=args.sample_ms, watch=args.mode == "watch") as app:
            rows = []
            skipped = {}
            cache = None
            timeline = None
            password_args = [argument for password in args.password for argument in ("-p", password)]
            if args.mode == "passwords":
                selected = workspace.corpus / "selected"
                selected.mkdir()
                payload = workspace.work / "password-payload.txt"
                payload.write_bytes(b"scoped password benchmark\n" * 4096)
                archive = selected / "encrypted.opaque"
                tool = Path(__file__).resolve().parents[2] / ("tools" if args.arch == "x64" else "tools-arm64") / "7z.exe"
                subprocess.run([str(tool), "a", "-t7z", "-mhe=on", "-pbenchmark-key", str(archive), str(payload)], check=True, stdout=subprocess.DEVNULL)
                entries = [
                    {"value": f"candidate-{i}", "scopes": [str(workspace.corpus / f"unrelated-{i}")]}
                    for i in range(args.password_entries)
                ]
                entries.append({"value": "benchmark-key", "scopes": [str(selected)]})
                (app.data / "builtin_passwords.json").write_text(json.dumps({"passwords": entries}), encoding="utf-8")
                for run in range(args.runs):
                    if args.cold:
                        app.shutdown()
                    measurement = app.run("scan", archive, *password_args)
                    rows.append({"case": "scoped-password-store-encrypted-probe", "run": run, **measurement})
            elif args.live_arrival:
                corpus, skipped, cache = _case_rows(args, workspace)
                rows, timeline = _watch_arrivals(app, workspace, args, corpus, skipped)
            else:
                corpus, skipped, cache = _case_rows(args, workspace)
                if not corpus:
                    raise ValueError("No archives selected")
                inputs = workspace.work / "inputs"
                for key, item in corpus.items():
                    if args.shape == "carrier" and "split" in item["format"]:
                        skipped[key] = "carrier shape excludes multi-file volume sets"
                        continue
                    for copy in range(args.copies):
                        name = key.replace(":", "-") + (f"-copy-{copy}" if copy else "")
                        _copy_case(item, inputs / name, args.shape)
                if args.mode == "scan":
                    ordinary = inputs / "ordinary"
                    ordinary.mkdir()
                    for i in range(args.ordinary_files):
                        (ordinary / f"ordinary-{i}.txt").write_bytes(b"ordinary file\n")
                if args.mode == "watch":
                    _configure_watch(app, args, inputs, workspace.outputs)
                for run in range(args.runs):
                    if args.cold or args.mode == "watch":
                        app.shutdown()
                    if args.mode in ("scan", "memory", "watch"):
                        output = workspace.outputs / f"round-{run}"
                        command = ("scan", "-R", "-d", inputs, *password_args) if args.mode == "scan" else (
                            ("watch", "start", "--once", "--no-tray") if args.mode == "watch" else
                            ("extract", "-R", "-d", "-r", args.recursive, "-c", "k", "--no-flatten", "--no-pause", "-o", output, inputs, *password_args)
                        )
                        measurement = app.run(*command, require_broker=args.mode == "watch")
                        if args.mode == "memory" and not measurement["response"]["summary"]["processed_count"]:
                            raise RuntimeError("The extraction workload found no archive inputs.")
                        observed = workspace.outputs if args.mode == "watch" else output
                        rows.append({"case": "directory" if args.mode != "watch" else ("bootstrap" if run == 0 else "completed-state-restart"), "run": run, "output": output_summary(observed), **measurement})
                        if output.exists():
                            shutil.rmtree(output)
                    else:
                        for key, item in corpus.items():
                            directory = inputs / key.replace(":", "-")
                            if not directory.exists():
                                continue
                            entry = next(iter(directory.iterdir())) if "split" not in item["format"] else directory / Path(item["path"]).name
                            output = workspace.outputs / f"round-{run}-{key.replace(':', '-')}"
                            measurement = app.run("extract", "--direct-file", "-d", "-r", args.recursive, "-c", "k", "--no-flatten", "--no-pause", "-o", output, entry, *password_args)
                            row = {"case": key, "format": item["format"], "run": run, "output": output_summary(output), **measurement}
                            if args.compare_7z:
                                # Compare identical unwrapped archive input; carrier
                                # discovery is a separate SunPack workload.
                                baseline = workspace.outputs / f"sevenzip-{run}-{key.replace(':', '-')}"
                                seconds, code = _timed_seven_zip_extract(Path(item["path"]), baseline, item["format"])
                                row["sevenzip"] = {"seconds": seconds, "returncode": code, "output": output_summary(baseline)}
                                shutil.rmtree(baseline)
                            rows.append(row)
                            shutil.rmtree(output)
                            print(f"{key} round {run + 1}: {measurement['seconds']:.3f}s, peak {measurement['peak_rss_mib']:.1f} MiB", flush=True)
            report = {
                "schema_version": 2, "boundary": "native-launcher", "mode": args.mode,
                "broker_service": app.env[SERVICE_ENV] if args.mode == "watch" else None,
                "machine": {"platform": platform.platform(), "machine": platform.machine()},
                "options": vars(args), "corpus_cache": cache, "skipped": skipped, "rows": rows,
                "cases": {
                    case: {
                        "median_seconds": statistics.median(row["seconds"] for row in rows if row["case"] == case),
                        "max_sampled_rss_mib": max(row["peak_rss_mib"] for row in rows if row["case"] == case),
                    }
                    for case in dict.fromkeys(row["case"] for row in rows)
                },
                "memory_scope": (
                    "isolated native launcher, resident runtime and its descendants, and temporary Broker service and its descendants; excludes benchmark Python"
                    if args.mode == "watch" else "isolated native launcher and resident runtime and its descendants; excludes benchmark Python"
                ),
                "sampling_note": "Sampled peak is a lower bound; short-lived allocations between samples may be missed.",
            }
            if timeline is not None:
                latencies = [item["seconds"] for row in rows for item in row["arrivals"]]
                report["arrival_latency"] = {
                    "boundary": "atomic publication start to observed deletion of all isolated source members",
                    "median_seconds": statistics.median(latencies), "max_seconds": max(latencies),
                }
                report["service_timeline"] = timeline
                report["output"] = output_summary(workspace.outputs)
            target = workspace.write_result_json("result.json", report)
            print(f"Result: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
