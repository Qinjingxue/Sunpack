from __future__ import annotations

import argparse
import os
import sys
import traceback
from datetime import datetime, timezone

from sunpack.runtime.watch.log import append_jsonl_record
from sunpack.core.support.resources import get_resource_path
from sunpack.core.support.runtime_cwd import runtime_working_directory


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        os.chdir(runtime_working_directory())
        return _run_watch_service(
            once=args.once,
            no_tray=args.no_tray,
            initial_scan=args.initial_scan,
        )
    except Exception as exc:
        _write_bootstrap_error(exc)
        return 1


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--no-tray", action="store_true")
    parser.add_argument("--initial-scan", action="store_true")
    return parser.parse_args(sys.argv[1:] if argv is None else argv)


def _run_watch_service(*, once: bool, no_tray: bool, initial_scan: bool = False) -> int:
    from sunpack.runtime.cli.persistent_process import submit_request

    argv = ["watch", "start"]
    if once:
        argv.append("--once")
    if no_tray:
        argv.append("--no-tray")
    if initial_scan:
        argv.append("--initial-scan")
    return submit_request(argv)
def _write_bootstrap_error(exc: BaseException) -> None:
    try:
        state_dir = get_resource_path(".sunpack_watch")
        state_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "gui_bootstrap_error",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }
        append_jsonl_record(state_dir / "events.jsonl", payload)
    except Exception:
        pass
