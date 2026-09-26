from __future__ import annotations

import argparse
import os
import statistics
import subprocess
from pathlib import Path

from sunpack_native import NativeArchiveSession, reader_cache_stats

from benchmarks.harness import BenchmarkWorkspace, measure, metrics_delta, render_report, report_from_payload
from tests.helpers.tool_config import get_test_tools


DEFAULT_PASSWORD = "sunpack-reader-benchmark-correct"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark 100 wrong passwords followed by one correct password."
    )
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--payload-mib", type=int, default=1)
    parser.add_argument("--wrong-passwords", type=int, default=100)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    parser.add_argument(
        "--disable-seven-zip-probe",
        action="store_true",
        help="Run the legacy Archive::read-per-password path for A/B comparison.",
    )
    parser.add_argument(
        "--tool-timeout",
        type=float,
        default=300.0,
        help="Wall-clock timeout for the archive-generation subprocesses.",
    )
    return parser.parse_args()


def run(command: list[str], cwd: Path, timeout_seconds: float = 300.0) -> None:
    try:
        completed = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True, timeout=timeout_seconds
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"command timed out after {timeout_seconds:g}s: {command}\n"
        ) from exc
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )


def benchmark(
    path: Path,
    method_name: str,
    passwords: list[str],
    expected_index: int,
    rounds: int,
) -> dict:
    session = NativeArchiveSession(str(path))
    method = getattr(session, method_name)
    before = dict(reader_cache_stats())
    def invoke() -> dict:
        outcome = dict(method(passwords))
        assert outcome["status"] == "match", outcome
        assert int(outcome["matched_index"]) == expected_index, outcome
        return outcome

    measured = measure(invoke, runs=rounds)
    durations_ms = [row.wall_ms for row in measured]
    last_outcome = measured[-1].value
    after = dict(reader_cache_stats())
    warm = durations_ms[1:] or durations_ms
    median_ms = statistics.median(warm)
    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "rounds_ms": [round(value, 3) for value in durations_ms],
        "first_ms": round(durations_ms[0], 3),
        "warm_median_ms": round(median_ms, 3),
        "warm_min_ms": round(min(warm), 3),
        "passwords_per_second": round(len(passwords) * 1000 / median_ms, 1),
        "matched_index": int(last_outcome["matched_index"]),
        "attempts": int(last_outcome.get("attempts") or 0),
        "reader_delta": metrics_delta(before, after),
    }


def main() -> None:
    args = parse_args()
    if args.disable_seven_zip_probe:
        os.environ["SUNPACK_DISABLE_7Z_PASSWORD_PROBE"] = "1"
    if args.rounds < 1 or args.payload_mib < 1 or args.wrong_passwords < 0:
        raise SystemExit("rounds/payload-mib must be positive and wrong-passwords nonnegative")
    tools = get_test_tools()
    seven_zip = tools["seven_zip"]
    rar = tools["rar_exe"]
    if not seven_zip or not seven_zip.is_file():
        raise SystemExit("7z.exe is unavailable; configure tests/test_tools.json")
    if not rar or not rar.is_file():
        raise SystemExit("Rar.exe is unavailable; configure tests/test_tools.json")

    passwords = [f"sunpack-wrong-{index:04d}" for index in range(args.wrong_passwords)]
    passwords.append(args.password)
    expected_index = len(passwords) - 1
    with BenchmarkWorkspace(
        "reader.password-fast-path",
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        work = workspace.corpus
        payload = work / "payload.bin"
        unit = bytes(range(256))
        payload.write_bytes(unit * (args.payload_mib * 1024 * 1024 // len(unit)))
        zip_path = work / "encrypted.zip"
        seven_path = work / "encrypted.7z"
        rar_path = work / "encrypted.rar"
        run(
            [
                str(seven_zip), "a", "-tzip", str(zip_path), str(payload),
                f"-p{args.password}", "-mem=AES256", "-mx=0", "-y",
            ],
            work,
            args.tool_timeout,
        )
        run(
            [
                str(seven_zip), "a", "-t7z", str(seven_path), str(payload),
                f"-p{args.password}", "-mhe=on", "-mx=0", "-y",
            ],
            work,
            args.tool_timeout,
        )
        run(
            [
                str(rar), "a", "-ep1", "-idq", "-m0", "-ma5", "-y",
                f"-hp{args.password}", str(rar_path), str(payload),
            ],
            work,
            args.tool_timeout,
        )
        results = {
            "configuration": {
                "rounds": args.rounds,
                "wrong_passwords": args.wrong_passwords,
                "correct_password_index": expected_index,
                "payload_mib": args.payload_mib,
            },
            "zip_aes256": benchmark(
                zip_path, "zip_fast_verify_passwords", passwords, expected_index, args.rounds
            ),
            "seven_zip_header": benchmark(
                seven_path,
                "seven_zip_fast_verify_passwords",
                passwords,
                expected_index,
                args.rounds,
            ),
            "rar5_header": benchmark(
                rar_path, "rar_fast_verify_passwords", passwords, expected_index, args.rounds
            ),
        }
        rendered = render_report(report_from_payload("reader.password-fast-path", results))
        workspace.write_result_text("report.json", rendered)
        print(rendered)


if __name__ == "__main__":
    main()
