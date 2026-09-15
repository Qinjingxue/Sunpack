from __future__ import annotations

import subprocess
import winreg

from sunpack.gui.launcher import watch_launch_argv
from sunpack.support.process_executable import current_process_executable
from sunpack.support.runtime_identity import runtime_id_argument, runtime_id_available


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "SunPackWatchService"


def startup_command() -> str:
    executable = current_process_executable()
    if executable.name.lower() == "sunpack-runtime.exe" and runtime_id_available():
        argv = [str(executable), runtime_id_argument(), "watch", "start"]
    else:
        argv = watch_launch_argv(prefer_windowed_python=True)
    return subprocess.list2cmdline(argv)


def enable_startup(command: str | None = None) -> str:
    command = command or startup_command()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
    return command


def disable_startup() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, VALUE_NAME)
        return True
    except FileNotFoundError:
        return False


def startup_status() -> tuple[bool, str]:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
        return True, str(value)
    except FileNotFoundError:
        return False, ""
