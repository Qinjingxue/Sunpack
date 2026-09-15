from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from .registry import SCENARIOS


BENCHMARKS_ROOT = Path(__file__).resolve().parent
BENCHMARK_CACHE_ROOT = BENCHMARKS_ROOT / ".cache"
BENCHMARK_WORK_ROOT = BENCHMARKS_ROOT / ".work"
BENCHMARK_RUN_ID_ENV = "SUNPACK_BENCH_RUN_ID"

# A scenario that makes a stale API call must fail loudly instead of hanging the
# whole benchmark run.  Every scenario therefore runs in a child process under
# a hard wall-clock deadline; on expiry the child is killed and the run reports
# exit code 124 (the conventional "timeout" status).
DEFAULT_TIMEOUT_SECONDS = float(os.environ.get("SUNPACK_BENCH_TIMEOUT", "3600"))
TIMEOUT_EXIT_CODE = 124


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SunPack performance benchmark runner")
    parser.add_argument("--list", action="store_true", help="List available scenarios.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(
            "Hard wall-clock limit in seconds for the whole scenario "
            f"(default: {DEFAULT_TIMEOUT_SECONDS:g}; env SUNPACK_BENCH_TIMEOUT). "
            "On expiry the scenario process is killed and the run exits with "
            f"{TIMEOUT_EXIT_CODE}."
        ),
    )
    parser.add_argument("group", nargs="?", choices=[*sorted({key[0] for key in SCENARIOS}), "clean"])
    parser.add_argument("scenario", nargs="?")
    parser.add_argument("scenario_args", nargs=argparse.REMAINDER)
    return parser


def _cleanup_benchmark_run_workdir(run_id: str) -> None:
    """Remove only workspaces tagged with one benchmark parent run ID."""
    if not BENCHMARK_WORK_ROOT.is_dir():
        return
    marker = f"-{run_id}-"
    try:
        candidates = list(BENCHMARK_WORK_ROOT.iterdir())
    except OSError:
        return
    for candidate in candidates:
        if candidate.is_dir() and marker in candidate.name:
            shutil.rmtree(candidate, ignore_errors=True)


def _run_scenario_in_subprocess(module: str, scenario_args: list[str], timeout: float) -> int:
    """Run one scenario module in a child process with a hard timeout.

    The child inherits stdout/stderr so real-time progress stays visible, and
    its exit code becomes the benchmark's exit code.  A stale scenario that
    blocks forever is killed by ``subprocess.run``'s timeout and reported as
    ``TIMEOUT_EXIT_CODE`` instead of hanging the parent.
    """
    command = [sys.executable, "-m", module, *scenario_args]
    run_id = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
    environment = os.environ.copy()
    environment[BENCHMARK_RUN_ID_ENV] = run_id
    keep_workdir = "--keep-workdir" in scenario_args
    try:
        try:
            completed = subprocess.run(
                command,
                cwd=os.getcwd(),
                env=environment,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            print(
                f"benchmark timed out after {timeout:g}s and was killed: {' '.join(command)}",
                file=sys.stderr,
                flush=True,
            )
            return TIMEOUT_EXIT_CODE
        return int(completed.returncode)
    finally:
        if not keep_workdir:
            _cleanup_benchmark_run_workdir(run_id)


def _clean_benchmark_artifacts(args: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Remove regenerable benchmark artifacts.")
    parser.add_argument("--cache", action="store_true", help="Remove benchmarks/.cache.")
    parser.add_argument("--work", action="store_true", help="Remove benchmarks/.work.")
    parser.add_argument("--dry-run", action="store_true", help="Print paths without removing them.")
    selected = parser.parse_args(args)
    paths = [
        ("cache", BENCHMARK_CACHE_ROOT, selected.cache),
        ("work", BENCHMARK_WORK_ROOT, selected.work),
    ]
    if not any(enabled for _, _, enabled in paths):
        parser.error("choose at least one of --cache or --work")
    for label, path, enabled in paths:
        if not enabled:
            continue
        if selected.dry_run:
            print(f"would remove benchmark {label}: {path}")
        elif path.exists():
            shutil.rmtree(path)
            print(f"removed benchmark {label}: {path}")
        else:
            print(f"benchmark {label} is already absent: {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.list:
        for scenario in SCENARIOS.values():
            print(f"{scenario.group:10} {scenario.name:24} {scenario.description}")
        return 0
    if args.group == "clean":
        if args.scenario:
            _parser().error("clean accepts only --cache and/or --work")
        return _clean_benchmark_artifacts(list(args.scenario_args))
    if not args.group or not args.scenario:
        _parser().error("group and scenario are required unless --list is used")
    selected = SCENARIOS.get((args.group, args.scenario))
    if selected is None:
        names = ", ".join(name for group, name in SCENARIOS if group == args.group)
        _parser().error(f"unknown {args.group} scenario {args.scenario!r}; choose one of: {names}")
    if args.timeout <= 0:
        _parser().error("--timeout must be positive")
    if args.group == "watch":
        from .watch_broker import temporary_watch_broker_service

        with temporary_watch_broker_service():
            return _run_scenario_in_subprocess(selected.module, list(args.scenario_args), args.timeout)
    return _run_scenario_in_subprocess(selected.module, list(args.scenario_args), args.timeout)
