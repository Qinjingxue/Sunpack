from __future__ import annotations

import argparse
import os
import shutil
import statistics
import time
from pathlib import Path

from sunpack_native import NativeArchiveSession

from benchmarks.harness import BenchmarkWorkspace, measure, render_report, report_from_payload
from tests.helpers.tool_config import get_test_tools
from benchmarks.scenarios.reader_password_fast_path import DEFAULT_PASSWORD, run


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark each 7z fast-password optimization stage."
    )
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--wrong-passwords", type=int, default=100)
    parser.add_argument("--cross-candidates", type=int, default=16)
    parser.add_argument("--archives", type=int, nargs="+", default=[100, 1000])
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--label", default="unlabeled")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    return parser.parse_args()


def timed_calls(session: NativeArchiveSession, passwords: list[str], rounds: int) -> dict:
    measured = measure(lambda: dict(session.seven_zip_fast_verify_passwords(passwords)), runs=rounds)
    wall_ms = [row.wall_ms for row in measured]
    cpu_ms = [row.cpu_ms for row in measured]
    last = measured[-1].value
    warm_wall = wall_ms[2:] or wall_ms
    warm_cpu = cpu_ms[2:] or cpu_ms
    return {
        "status": last["status"],
        "matched_index": int(last["matched_index"]),
        "attempts": int(last.get("attempts") or 0),
        "wall_ms": [round(value, 3) for value in wall_ms],
        "warm_wall_median_ms": round(statistics.median(warm_wall), 3),
        "warm_cpu_median_ms": round(statistics.median(warm_cpu), 3),
    }


def cross_archive_benchmark(
    source: Path,
    root: Path,
    passwords: list[str],
    archive_count: int,
) -> dict:
    paths: list[Path] = []
    for index in range(archive_count):
        path = root / f"archive-{index:04d}.7z"
        shutil.copyfile(source, path)
        paths.append(path)

    durations_ms: list[float] = []
    cpu_started = time.process_time_ns()
    wall_started = time.perf_counter_ns()
    for path in paths:
        session = NativeArchiveSession(str(path))
        started = time.perf_counter_ns()
        outcome = dict(session.seven_zip_fast_verify_passwords(passwords))
        durations_ms.append((time.perf_counter_ns() - started) / 1_000_000)
        assert outcome["status"] == "match", outcome
        assert int(outcome["matched_index"]) == len(passwords) - 1, outcome
    total_wall_ms = (time.perf_counter_ns() - wall_started) / 1_000_000
    total_cpu_ms = (time.process_time_ns() - cpu_started) / 1_000_000
    warm = durations_ms[1:] or durations_ms
    return {
        "archives": archive_count,
        "candidates": len(passwords),
        "first_ms": round(durations_ms[0], 3),
        "warm_median_ms": round(statistics.median(warm), 3),
        "total_wall_ms": round(total_wall_ms, 3),
        "total_cpu_ms": round(total_cpu_ms, 3),
        "archives_per_second": round(archive_count * 1000 / total_wall_ms, 2),
    }


def main() -> None:
    args = parse_args()
    if (
        args.rounds < 3
        or args.wrong_passwords < 1
        or args.cross_candidates < 1
        or not args.archives
        or min(args.archives) < 1
    ):
        raise SystemExit("invalid benchmark dimensions")

    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        raise SystemExit("7z.exe is unavailable; configure tests/test_tools.json")

    with BenchmarkWorkspace(
        "reader.seven-zip-password",
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        work = workspace.corpus
        payload = work / "payload.bin"
        payload.write_bytes(bytes(range(256)) * 4096)
        archive = work / "encrypted.7z"
        run(
            [
                str(seven_zip),
                "a",
                "-t7z",
                str(archive),
                str(payload),
                f"-p{args.password}",
                "-mhe=on",
                "-mx=0",
                "-y",
            ],
            work,
        )

        session = NativeArchiveSession(str(archive))
        wrong = [f"sunpack-wrong-{index:04d}" for index in range(args.wrong_passwords)]
        full_last = wrong + [args.password]
        full_first = [args.password] + wrong
        middle = len(wrong) // 2
        full_middle = wrong[:middle] + [args.password] + wrong[middle:]
        cross_passwords = wrong[: args.cross_candidates] + [args.password]

        cross_root = work / "cross"
        cross_root.mkdir()
        cross = {}
        for archive_count in sorted(set(args.archives)):
            case_root = cross_root / str(archive_count)
            case_root.mkdir()
            cross[str(archive_count)] = cross_archive_benchmark(
                archive, case_root, cross_passwords, archive_count
            )
        isolated = {
            "zero_candidates": timed_calls(session, [], args.rounds),
            "one_wrong": timed_calls(session, wrong[:1], args.rounds),
            "one_correct": timed_calls(session, [args.password], args.rounds),
        }
        positions = {
            "correct_first": timed_calls(session, full_first, args.rounds),
            "correct_middle": timed_calls(session, full_middle, args.rounds),
            "correct_last": timed_calls(session, full_last, args.rounds),
            "all_wrong": timed_calls(session, wrong, args.rounds),
        }

        rendered = render_report(report_from_payload(
            "reader.seven-zip-password",
            {
                    "label": args.label,
                    "configuration": {
                        "rounds": args.rounds,
                        "wrong_passwords": args.wrong_passwords,
                        "cross_candidates": args.cross_candidates,
                        "archives": sorted(set(args.archives)),
                        "logical_processors": os.cpu_count(),
                        "worker_override": os.environ.get(
                            "SUNPACK_7Z_PASSWORD_WORKERS"
                        ),
                    },
                    "isolated": isolated,
                    "positions": positions,
                    "cross_archive": cross,
                },
        ))
        workspace.write_result_text("report.json", rendered)
        print(rendered)


if __name__ == "__main__":
    main()
