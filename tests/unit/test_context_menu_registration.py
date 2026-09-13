import ctypes
import json
import ntpath
import os
import subprocess
from ctypes import wintypes
from pathlib import Path


def test_context_menu_commands_are_safe_for_drive_roots_and_keep_password_flag():
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "register_context_menu.ps1"
    executable = repo / "dist" / "sunpack-x64" / "sunpack.exe"
    if not executable.exists():
        executable = Path(os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"))

    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-AppPath",
            str(executable),
            "-DryRun",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
    )
    commands = json.loads(completed.stdout.strip().splitlines()[-1])
    assert commands["menu_text"] == "sunpack"

    for key in ("folder_prompt", "background_prompt"):
        expanded = commands[key].replace("%1", "D:\\").replace("%V", "D:\\")
        argv = _windows_argv(expanded)
        assert argv[1] == "extract"
        assert ntpath.normpath(argv[2]) == "D:\\"
        assert ntpath.normpath(argv[argv.index("--out-dir") + 1]) == "D:\\"
        assert "--ask-pw" in argv
        assert "--pause" in argv

    for key in ("folder_direct", "background_direct"):
        expanded = commands[key].replace("%1", "D:\\").replace("%V", "D:\\")
        argv = _windows_argv(expanded)
        assert argv[1] == "extract"
        assert "--reuse" not in argv
        assert "--ask-pw" not in argv
        assert "--pause" in argv

    for key in ("folder_watch", "background_watch"):
        expanded = commands[key].replace("%1", "D:\\").replace("%V", "D:\\")
        argv = _windows_argv(expanded)
        assert ntpath.basename(argv[0]).lower() == "powershell.exe"
        assert "-WindowStyle" in argv
        assert "Hidden" in argv
        command_text = argv[argv.index("-Command") + 1]
        assert "Start-Process" in command_text
        assert "-WindowStyle Hidden" in command_text
        assert "'watch','add'," in command_text
        assert "D:" in command_text
        assert "\\." in command_text
        assert "'--start'" in command_text
        assert "'--initial-scan'" in command_text
        assert "--pause" not in command_text

    for key in ("folder_unwatch", "background_unwatch"):
        expanded = commands[key].replace("%1", "D:\\").replace("%V", "D:\\")
        argv = _windows_argv(expanded)
        assert ntpath.basename(argv[0]).lower() == "powershell.exe"
        command_text = argv[argv.index("-Command") + 1]
        assert "Start-Process" in command_text
        assert "-WindowStyle Hidden" in command_text
        assert "'watch','remove'," in command_text
        assert "D:" in command_text
        assert "\\." in command_text


def test_context_menu_directory_token_is_stable_for_normal_paths():
    command = 'sunpack.exe extract "%V\\." --out-dir "%V\\." --ask-pw --pause'
    argv = _windows_argv(command.replace("%V", r"D:\Archives"))

    assert ntpath.normpath(argv[2]) == r"D:\Archives"
    assert ntpath.normpath(argv[4]) == r"D:\Archives"
    assert argv[5:] == ["--ask-pw", "--pause"]

    watch_command = '"powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process -WindowStyle Hidden -FilePath ''sunpack.exe'' -ArgumentList @(''watch'',''add'',''%V\\.'',''--start'',''--initial-scan'')"'
    watch_argv = _windows_argv(watch_command.replace("%V", r"D:\Archives"))
    command_text = watch_argv[watch_argv.index("-Command") + 1]
    assert "watch" in command_text
    assert "add" in command_text
    assert r"D:\Archives\." in command_text
    assert "--start" in command_text
    assert "--initial-scan" in command_text


def _windows_argv(command: str) -> list[str]:
    parse = ctypes.windll.shell32.CommandLineToArgvW
    parse.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    parse.restype = ctypes.POINTER(wintypes.LPWSTR)
    argc = ctypes.c_int()
    argv = parse(command, ctypes.byref(argc))
    try:
        return [argv[index] for index in range(argc.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(argv)
