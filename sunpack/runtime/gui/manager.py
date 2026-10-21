from __future__ import annotations

import platform
import threading
from pathlib import Path

from sunpack.core.platform.windows.process_launch import launch_unelevated
from sunpack.core.support.process_executable import current_process_executable, is_packaged_process
from sunpack.core.support.resources import writable_data_dir


def manager_launch_argv() -> list[str]:
    executable = current_process_executable()
    if is_packaged_process():
        manager = executable.parent / "SunPackGUI.exe"
        argv = [str(manager)]
    else:
        root = Path(__file__).resolve().parents[3]
        arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
        manager = root / ".cache" / f"gui-{arch}" / "Release" / "SunPackGUI.exe"
        if executable.name.lower() == "pythonw.exe":
            executable = executable.with_name("python.exe")
        argv = [
            str(manager), "--data-dir", str(writable_data_dir()),
            "--cli", str(executable), "--cli-prefix", "-m", "--cli-prefix", "sunpack",
        ]
    if not manager.is_file():
        raise FileNotFoundError(f"SunPack GUI manager was not found: {manager}. Build it with scripts/build_gui.ps1.")
    return argv


def launch_manager() -> None:
    process = launch_unelevated(manager_launch_argv(), cwd=str(writable_data_dir()))
    # A GUI window owns its lifetime; the long-lived tray must retain no child handle.
    close = getattr(process, "close", None)
    if close is not None:
        close()
    else:
        # Popen has no public detach/close API. Reap with a kernel process wait,
        # so repeated tray clicks cannot accumulate Popen's global _active entries.
        threading.Thread(target=process.wait, name="SunPackGUI-reaper", daemon=True).start()
