from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from sunpack.platform.windows.elevation import is_process_elevated
from sunpack.platform.windows.process_launch import launch_unelevated


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a command with the interactive shell's normal user token.")
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    parser.add_argument("--capture-directory", help=argparse.SUPPRESS)
    parser.add_argument("--env", action="append", default=[], help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    environment_overrides = {}
    for assignment in args.env:
        name, separator, value = assignment.partition("=")
        if not separator or not name:
            parser.error("--env requires NAME=VALUE")
        environment_overrides[name] = value
    args.environment_overrides = environment_overrides
    return args


def _child_environment(args: argparse.Namespace) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(args.environment_overrides)
    return environment


def _run_captured_child(args: argparse.Namespace, cwd: str) -> int:
    capture_root = Path(args.capture_directory)
    capture_root.mkdir(parents=True, exist_ok=True)
    try:
        with (capture_root / "stdout.bin").open("wb") as stdout, (
            capture_root / "stderr.bin"
        ).open("wb") as stderr:
            completed = subprocess.run(
                args.command,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env=_child_environment(args),
                timeout=max(0.1, args.timeout_seconds),
                check=False,
            )
        return int(completed.returncode)
    except subprocess.TimeoutExpired:
        with (capture_root / "stderr.bin").open("ab") as stderr:
            stderr.write(
                f"Unelevated process timed out after {args.timeout_seconds:.1f}s\n".encode("utf-8")
            )
        return 124


def _replay(path: Path, stream) -> None:
    if path.is_file():
        stream.buffer.write(path.read_bytes())
        stream.flush()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cwd = str(Path(args.cwd).resolve())
    if args.capture_directory:
        return _run_captured_child(args, cwd)
    if not is_process_elevated():
        try:
            return int(
                subprocess.run(
                    args.command,
                    cwd=cwd,
                    env=_child_environment(args),
                    timeout=max(0.1, args.timeout_seconds),
                    check=False,
                ).returncode
            )
        except subprocess.TimeoutExpired:
            print(f"Unelevated process timed out after {args.timeout_seconds:.1f}s", file=sys.stderr)
            return 124

    temporary = tempfile.TemporaryDirectory(prefix="sunpack-unelevated-output-")
    capture_root = Path(temporary.name)
    helper_command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--cwd",
        cwd,
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--capture-directory",
        str(capture_root),
        *(item for assignment in args.env for item in ("--env", assignment)),
        "--",
        *args.command,
    ]
    process = launch_unelevated(
        helper_command,
        cwd=cwd,
        env=_child_environment(args),
    )
    try:
        try:
            exit_code = process.wait(timeout=max(0.1, args.timeout_seconds) + 10.0)
        except subprocess.TimeoutExpired:
            exit_code = None
        if exit_code is None:
            process.terminate()
            process.wait(timeout=5.0)
            print(f"Unelevated process timed out after {args.timeout_seconds:.1f}s", file=sys.stderr)
            return 124
        _replay(capture_root / "stdout.bin", sys.stdout)
        _replay(capture_root / "stderr.bin", sys.stderr)
        return int(exit_code)
    finally:
        close = getattr(process, "close", None)
        if callable(close):
            close()
        temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
