"""Paired ENC worker measurements: authenticated reads, CTR and real writes.

Prebuild each worker with the desired Rust stream policy and pass LABEL=PATH.
Python only schedules jobs/metrics; Rust validates output CRC outside the timer.
Writer memory modes require a probe build and intentionally produce no files.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import statistics
import tempfile
import time

import psutil
from sunpack_native import compute_directory_crc_manifest, resolve_output_volume_key
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _AsyncNativeWorkerProcess


async def run(args):
    modes = dict(spec.split("=", 1) for spec in args.writer_mode)
    labels = {spec.split("=", 1)[0] for spec in args.worker}
    if len(modes) != len(args.writer_mode) or not modes.keys() <= labels:
        raise ValueError("writer modes require unique existing worker labels")
    if any(mode not in {"real", "memory", "memory-nocopy"} for mode in modes.values()):
        raise ValueError("writer modes: real, memory, memory-nocopy")
    report = {"method": "Persistent workers; alternating order; one warmup; cached inputs; "
              "no fsync; real outputs: size/CRC validation and cleanup outside timer; "
              "memory modes: no output files or CRC validation; KDF included.",
              "capacity": args.capacity, "concurrency": args.concurrency, "rounds": args.rounds,
              "logical_cpu_affinity": args.affinity,
              "writer_modes": modes, "workers": {}, "results": []}
    workers = {}
    work_root = Path("benchmarks/.work/enc").resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    try:
        for spec in args.worker:
            label, path = spec.split("=", 1)
            if label in workers:
                raise ValueError(f"duplicate worker label: {label}")
            report["workers"][label] = str(Path(path).resolve())
            process = _AsyncNativeWorkerProcess(report["workers"][label], None,
                                               {"thread_capacity": args.capacity})
            workers[label] = process
            mode = modes.get(label)
            saved_env = {name: os.environ.get(name) for name in
                         ("SUNPACK_WRITER_PROBE", "SUNPACK_WRITER_PROBE_MODE")}
            try:
                if mode:
                    os.environ["SUNPACK_WRITER_PROBE"] = "1"
                    os.environ["SUNPACK_WRITER_PROBE_MODE"] = mode
                await process.start()
            finally:
                for name, value in saved_env.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
            if args.affinity:
                psutil.Process(process.process.pid).cpu_affinity(args.affinity)
        for path in args.path:
            path = path.resolve()
            expected = next(row for row in compute_directory_crc_manifest(str(path.parent), 100)["files"]
                            if Path(row["path"]).name == "large.expected")
            for width in args.concurrency:
                samples = {label: [] for label in workers}
                for trial in range(-1, args.rounds):
                    labels = list(workers)
                    if trial % 2:
                        labels.reverse()
                    for label in labels:
                        worker = workers[label]
                        memory_sink = modes.get(label, "real").startswith("memory")
                        with tempfile.TemporaryDirectory(prefix="worker-enc-", dir=work_root) as temp:
                            output = Path(temp)
                            results, errors, events = {}, [], []
                            finished = []
                            volume = resolve_output_volume_key(str(output))
                            if not volume:
                                raise RuntimeError("output volume unavailable")

                            def on_line(_line, event):
                                if event.get("type") == "result":
                                    results[event["job_id"]] = event
                                elif event.get("type") == "native_cpu":
                                    events.append(event)
                                return event.get("event") == "job_finished"

                            started = time.perf_counter()
                            for index in range(width):
                                job_id = f"{trial}-{index}"
                                job = {"job_id": job_id, "origin": "watch" if index % 2 else "foreground",
                                       "archive_path": str(path), "format_hint": "enc",
                                       "output_dir": str(output / str(index)), "output_volume_key": volume,
                                       "password_candidates": [args.password]}
                                await worker.submit(json.dumps(job), job_id, parsed_events=True,
                                                    on_line=on_line, on_timeout=errors.append)
                                finished.append(worker._jobs[job_id]["finished"])
                            await asyncio.wait_for(asyncio.gather(*finished), 120)
                            elapsed = (time.perf_counter() - started) * 1000
                            assert not errors and len(results) == width, (errors, results)
                            for result in results.values():
                                assert result["status"] == "ok", result
                                if not memory_sink:
                                    assert result["verified_manifest"]["validated"], result
                                assert result["bytes_written"] == expected["size"], result
                            if memory_sink:
                                assert not any(p.is_file() for p in output.rglob("*")), "diagnostic sink wrote files"
                            else:
                                actual = compute_directory_crc_manifest(str(output), width + 1)
                                assert actual["status"] == "ok" and not actual.get("truncated"), actual
                                assert len(actual["files"]) == width
                                assert all(row["size"] == expected["size"] and row["crc32"] == expected["crc32"]
                                           for row in actual["files"]), actual
                            memory = psutil.Process(worker.process.pid).memory_info()
                            row = {"trial": trial, "ms": elapsed,
                                   "mib_s": expected["size"] * width / (1024**2) * 1000 / elapsed,
                                   "rss_mib": memory.rss / 1024**2,
                                   "peak_rss_mib": getattr(memory, "peak_wset", memory.rss) / 1024**2,
                                   "diagnostic_only_no_output": memory_sink,
                                   "writer_profiles": [json.loads(line.removeprefix("WRITER_PROBE "))
                                                       for line in worker.take_stderr()
                                                       if line.startswith("WRITER_PROBE ")],
                                   "cpu_events": events}
                            if memory_sink and trial == -1 and not row["writer_profiles"]:
                                raise RuntimeError("memory sinks require a worker built with writer probes")
                            if trial >= 0:
                                samples[label].append(row)
                entry = {"path": str(path), "bytes": expected["size"], "concurrency": width,
                         "samples": samples,
                         "medians_mib_s": {label: statistics.median(row["mib_s"] for row in rows)
                                           for label, rows in samples.items()}}
                report["results"].append(entry)
                args.json_out.parent.mkdir(parents=True, exist_ok=True)
                args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
                print(path.parent.name, width, entry["medians_mib_s"], flush=True)
        report["complete"] = True
        args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    finally:
        for worker in workers.values():
            await worker.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="append", required=True, help="LABEL=PATH")
    parser.add_argument("--writer-mode", action="append", default=[], help="LABEL=real|memory|memory-nocopy; probe builds only")
    parser.add_argument("--path", type=Path, action="append", required=True)
    parser.add_argument("--password", default="sunpack-test")
    parser.add_argument("--capacity", type=int, default=4)
    parser.add_argument("--concurrency", type=lambda value: [int(x) for x in value.split(",")], default=[1])
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--affinity", type=lambda value: [int(x) for x in value.split(",")],
                        help="Optional logical CPU IDs, applied only to benchmark workers")
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    if args.rounds < 1 or args.capacity < 1 or not args.concurrency or min(args.concurrency) < 1:
        parser.error("rounds, capacity and concurrency must be positive")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
