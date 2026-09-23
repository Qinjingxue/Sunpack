from __future__ import annotations

from pathlib import Path

from sunpack.core.support.process_executable import current_process_executable

LAUNCHER_EXECUTABLE_NAME = "sunpack.exe"


def packaged_runtime_executable(executable: str | Path | None = None) -> Path | None:
    current = Path(executable).resolve() if executable is not None else current_process_executable()
    candidate = current.parent / LAUNCHER_EXECUTABLE_NAME
    return candidate if candidate.is_file() else None


def watch_launch_argv(
    *,
    once: bool = False,
    no_tray: bool = False,
    initial_scan: bool = False,
    prefer_windowed_python: bool = False,
) -> list[str]:
    packaged = packaged_runtime_executable()
    if packaged is not None:
        argv = [str(packaged), "watch", "start"]
    else:
        executable = current_process_executable()
        if prefer_windowed_python and executable.name.lower() == "python.exe":
            pythonw = executable.with_name("pythonw.exe")
            if pythonw.is_file():
                executable = pythonw
        argv = [str(executable), "-m", "sunpack", "watch", "start"]
    if once:
        argv.append("--once")
    if no_tray:
        argv.append("--no-tray")
    if initial_scan:
        argv.append("--initial-scan")
    return argv
