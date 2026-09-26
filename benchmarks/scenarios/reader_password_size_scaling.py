from __future__ import annotations

import argparse
from pathlib import Path

from tests.helpers.tool_config import get_test_tools
from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from benchmarks.scenarios.reader_password_fast_path import (
    DEFAULT_PASSWORD,
    benchmark,
    run,
)


DEFAULT_PAYLOAD_SIZES_MIB = (1, 16, 64)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure whether fast wrong-password probing grows with encrypted "
            "archive size for ZIP AES-256, encrypted-header 7z, and RAR5."
        )
    )
    parser.add_argument(
        "--payload-mib",
        type=int,
        nargs="+",
        default=list(DEFAULT_PAYLOAD_SIZES_MIB),
        help="Payload sizes to test (default: 1 16 64).",
    )
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--wrong-passwords", type=int, default=100)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    return parser.parse_args()


def create_archives(
    work: Path,
    payload_mib: int,
    password: str,
    seven_zip: Path,
    rar: Path,
) -> dict[str, tuple[Path, str]]:
    case_dir = work / f"{payload_mib}-mib"
    case_dir.mkdir()
    payload = case_dir / "payload.bin"
    unit = bytes(range(256))
    payload.write_bytes(unit * (payload_mib * 1024 * 1024 // len(unit)))

    zip_path = case_dir / "encrypted.zip"
    seven_path = case_dir / "encrypted.7z"
    rar_path = case_dir / "encrypted.rar"
    run(
        [
            str(seven_zip), "a", "-tzip", str(zip_path), str(payload),
            f"-p{password}", "-mem=AES256", "-mx=0", "-y",
        ],
        case_dir,
    )
    run(
        [
            str(seven_zip), "a", "-t7z", str(seven_path), str(payload),
            f"-p{password}", "-mhe=on", "-mx=0", "-y",
        ],
        case_dir,
    )
    run(
        [
            str(rar), "a", "-ep1", "-idq", "-m0", "-ma5", "-y",
            f"-hp{password}", str(rar_path), str(payload),
        ],
        case_dir,
    )
    return {
        "zip_aes256": (zip_path, "zip_fast_verify_passwords"),
        "seven_zip_header": (seven_path, "seven_zip_fast_verify_passwords"),
        "rar5_header": (rar_path, "rar_fast_verify_passwords"),
    }


def growth_summary(rows: list[dict]) -> dict:
    smallest = rows[0]
    largest = rows[-1]
    size_ratio = largest["size_bytes"] / smallest["size_bytes"]
    latency_ratio = largest["warm_median_ms"] / smallest["warm_median_ms"]
    return {
        "archive_size_ratio": round(size_ratio, 3),
        "latency_ratio": round(latency_ratio, 3),
        "latency_growth_percent": round((latency_ratio - 1) * 100, 1),
        "material_size_dependence": latency_ratio >= 2.0 and size_ratio >= 4.0,
        "criterion": "largest latency >= 2x smallest latency while size >= 4x",
    }


def main() -> None:
    args = parse_args()
    sizes = sorted(set(args.payload_mib))
    if args.rounds < 2 or args.wrong_passwords < 0 or not sizes or sizes[0] < 1:
        raise SystemExit(
            "rounds must be >= 2, payload sizes positive, and wrong-passwords nonnegative"
        )

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
    format_rows: dict[str, list[dict]] = {
        "zip_aes256": [],
        "seven_zip_header": [],
        "rar5_header": [],
    }

    with BenchmarkWorkspace(
        "reader.password-size-scaling",
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        work = workspace.corpus
        for payload_mib in sizes:
            archives = create_archives(
                work, payload_mib, args.password, seven_zip, rar
            )
            for format_name, (path, method_name) in archives.items():
                row = benchmark(
                    path, method_name, passwords, expected_index, args.rounds
                )
                row["payload_mib"] = payload_mib
                format_rows[format_name].append(row)

        results = {
            "configuration": {
                "rounds": args.rounds,
                "wrong_passwords": args.wrong_passwords,
                "correct_password_index": expected_index,
                "payload_mib": sizes,
            },
            "formats": {
                name: {
                    "measurements": rows,
                    "growth": growth_summary(rows),
                }
                for name, rows in format_rows.items()
            },
        }
        rendered = render_report(report_from_payload("reader.password-size-scaling", results))
        workspace.write_result_text("report.json", rendered)
        print(rendered)


if __name__ == "__main__":
    main()
