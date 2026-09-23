"""Deprecated compatibility namespace.

The active Watch domain lives in :mod:`sunpack.watch`. Submodule aliases are
registered here so older imports resolve to the standalone Watch layer instead
of keeping a second implementation under ``filesystem``.
"""

from importlib import import_module
import sys


for _name in (
    "config_observer",
    "journal_commit",
    "log",
    "quiet_policy",
    "scanner",
    "scheduler",
    "service",
    "state",
    "toast",
):
    sys.modules.setdefault(
        f"{__name__}.{_name}",
        import_module(f"sunpack.watch.{_name}"),
    )

from sunpack.watch import (
    WatchCandidate,
    WatchRunResult,
    WatchScheduler,
    WatchService,
    WatchStateEntry,
    WatchStateStore,
    scan_watch_candidates,
)

__all__ = [
    "WatchCandidate",
    "WatchRunResult",
    "WatchScheduler",
    "WatchService",
    "WatchStateEntry",
    "WatchStateStore",
    "scan_watch_candidates",
]
