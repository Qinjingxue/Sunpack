"""File quiescence through production Watch admission with a virtual clock."""
from benchmarks.scenarios.watch_quiet_window import main as window_main


def main(argv=None):
    return window_main(argv, scheduler_mode=True)


if __name__ == "__main__":
    raise SystemExit(main())
