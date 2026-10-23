import ctypes
import json
import ntpath
import os
import shutil
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

import pytest


def test_context_menu_dry_run_preserves_unicode_with_ascii_json():
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "register_context_menu.ps1"
    menu_text = "中文菜单"

    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-AppPath",
            os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"),
            "-MenuText",
            menu_text,
            "-DryRun",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
    )
    assert completed.stdout.isascii()
    assert json.loads(completed.stdout.strip().splitlines()[-1])["menu_text"] == menu_text


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
    english_labels = {
        "folder": {
            "direct": "Extract files in this folder",
            "prompt": "Enter password to extract files in this folder",
            "recursive_extract": "Recursively extract files in this folder",
            "recursive_watch": "Watch this folder recursively",
        },
        "background": {
            "direct": "Extract files in this folder",
            "prompt": "Enter password to extract files in this folder",
            "recursive_extract": "Recursively extract files in this folder",
            "recursive_watch": "Watch this folder recursively",
        },
        "file": {
            "direct": "Extract this file",
            "prompt": "Enter password to extract this file",
        },
    }
    chinese_labels = {
        "folder": {
            "direct": "解压该目录下文件",
            "prompt": "输入密码解压该目录下文件",
            "recursive_extract": "递归解压该目录下文件",
            "recursive_watch": "递归监控此目录",
        },
        "background": {
            "direct": "解压目录下文件",
            "prompt": "输入密码解压目录下文件",
            "recursive_extract": "递归解压目录下文件",
            "recursive_watch": "递归监控此目录",
        },
        "file": {
            "direct": "解压该文件",
            "prompt": "输入密码解压该文件",
        },
    }
    # The registered language is taken from the local SunPack configuration.
    assert commands["menu_labels"] in (english_labels, chinese_labels)

    for key in ("folder_prompt", "background_prompt"):
        expanded = commands[key].replace("%1", "D:\\").replace("%V", "D:\\")
        argv = _windows_argv(expanded)
        assert argv[1] == "extract"
        assert ntpath.normpath(argv[2]) == "D:\\"
        assert ntpath.normpath(argv[argv.index("--out-dir") + 1]) == "D:\\"
        assert "--deep-detect" not in argv
        assert "--ask-pw" in argv
        assert "--pause" in argv
        assert "--recursive" not in argv

    for key in ("folder_direct", "background_direct"):
        expanded = commands[key].replace("%1", "D:\\").replace("%V", "D:\\")
        argv = _windows_argv(expanded)
        assert argv[1] == "extract"
        assert "--reuse" not in argv
        assert "--deep-detect" not in argv
        assert "--ask-pw" not in argv
        assert "--pause" in argv
        assert "--recursive" not in argv

    for key in ("folder_recursive_extract", "background_recursive_extract"):
        argv = _windows_argv(commands[key].replace("%1", "D:\\").replace("%V", "D:\\"))
        assert argv[1] == "extract"
        assert ntpath.normpath(argv[2]) == "D:\\"
        assert ntpath.normpath(argv[argv.index("--out-dir") + 1]) == "D:\\"
        assert "--recursive" in argv
        assert "--ask-pw" not in argv
        assert "--pause" in argv

    for key in ("file_prompt",):
        expanded = commands[key].replace("%1", r"D:\archive.bin")
        argv = _windows_argv(expanded)
        assert argv[1] == "extract"
        assert ntpath.normpath(argv[2]) == r"D:\archive.bin"
        assert "--out-dir" not in argv
        assert "--deep-detect" in argv
        assert "--ask-pw" in argv
        assert "--pause" in argv

    for key in ("file_direct",):
        expanded = commands[key].replace("%1", r"D:\archive.bin")
        argv = _windows_argv(expanded)
        assert argv[1] == "extract"
        assert ntpath.normpath(argv[2]) == r"D:\archive.bin"
        assert "--out-dir" not in argv
        assert "--deep-detect" in argv
        assert "--ask-pw" not in argv
        assert "--pause" in argv

    for surface in ("folder", "background"):
        assert {key for key in commands if key.startswith(surface + "_")} == {
            f"{surface}_{action}"
            for action in ("direct", "prompt", "watch", "unwatch", "recursive_extract", "recursive_watch")
        }

    for key in ("folder_watch", "background_watch", "folder_recursive_watch", "background_recursive_watch"):
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
        assert ("'--recursive'" in command_text) == ("recursive_watch" in key)
        assert "--pause" not in command_text
        assert "--deep-detect" not in command_text

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


@pytest.mark.parametrize("launcher_mode", ["app", "python"])
def test_context_menu_registration_survives_rebuild_and_uninstalls(tmp_path, launcher_mode):
    # Dry-run tests cannot detect commands erased by a later parent rebuild, or
    # leftover registry entries after reinstall/uninstall. This one isolated
    # lifecycle check covers those failures for both launch modes without admin.
    repo = Path(__file__).resolve().parents[2]
    scripts = tmp_path / "menu scripts"
    scripts.mkdir()
    for name in ("register_context_menu.ps1", "unregister_context_menu.ps1"):
        shutil.copyfile(repo / "scripts" / name, scripts / name)
    (tmp_path / "sunpack.py").touch()
    (tmp_path / "sunpack_config.json").write_text('{"cli":{"language":"zh"}}', encoding="utf-8")
    harness = tmp_path / "registry_lifecycle.ps1"
    harness.write_text(r'''
param([string]$Scripts, [string]$LauncherMode, [string]$PythonPath)
$ErrorActionPreference = "Stop"
$testRootName = "SunPack.ContextMenuTest_" + [guid]::NewGuid().ToString("N")
$testRoot = "HKCU:\Software\$testRootName"
$null = New-Item -Path $testRoot -Force
try {
    # Redirect only this process's HKLM drive to an isolated user registry key.
    Remove-PSDrive -Name HKLM
    $null = New-PSDrive -Name HKLM -PSProvider Registry -Root "HKEY_CURRENT_USER\Software\$testRootName"
    $registrationArgs = if ($LauncherMode -eq "app") { @{ AppPath = $env:COMSPEC } } else { @{ PythonPath = $PythonPath } }
    $snapshots = @()
    foreach ($pass in 1..2) {
        $null = New-Item -Path "HKLM:\Software\Classes\SunPack.BackgroundContextMenu\shell\Obsolete" -Force
        $null = New-Item -Path "HKLM:\Software\Classes\Directory\Background\shell\SunPack\shell\Obsolete" -Force
        & (Join-Path $Scripts "register_context_menu.ps1") @registrationArgs | Out-Null
        $snapshot = @{}
        foreach ($surface in @("Folder", "Background", "File")) {
            $shell = "HKLM:\Software\Classes\SunPack.${surface}ContextMenu\shell"
            $snapshot[$surface] = @(Get-ChildItem -LiteralPath $shell | ForEach-Object {
                [pscustomobject]@{
                    name = $_.PSChildName
                    label = $_.GetValue("MUIVerb")
                    command = (Get-Item -LiteralPath (Join-Path $_.PSPath "command")).GetValue("")
                }
            })
        }
        if (Test-Path -LiteralPath "HKLM:\Software\Classes\Directory\Background\shell\SunPack\shell") {
            throw "Legacy inline submenu survived registration"
        }
        $snapshots += $snapshot
    }
    & (Join-Path $Scripts "unregister_context_menu.ps1") | Out-Null
    $remaining = @(@(
        "Directory\shell\SunPack", "Directory\Background\shell\SunPack", "*\shell\SunPack",
        "SunPack.FolderContextMenu", "SunPack.BackgroundContextMenu", "SunPack.FileContextMenu"
    ) | Where-Object { Test-Path -LiteralPath "HKLM:\Software\Classes\$_" })
    $result = @{ snapshots = $snapshots; remaining = $remaining } | ConvertTo-Json -Depth 8 -Compress
    $result = [regex]::Replace($result, '[^\x00-\x7F]', [System.Text.RegularExpressions.MatchEvaluator]{
        param($match)
        '\u{0:X4}' -f [int][char]$match.Value
    })
    Write-Output $result
} finally {
    Remove-PSDrive -Name HKLM -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
''', encoding="ascii")
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness),
         "-Scripts", str(scripts), "-LauncherMode", launcher_mode, "-PythonPath", sys.executable],
        check=True, capture_output=True, text=True, encoding="utf-8-sig", timeout=30,
    )
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result["remaining"] == []
    assert len(result["snapshots"]) == 2
    assert result["snapshots"][0] == result["snapshots"][1]
    for surface, token in (("Folder", "%1"), ("Background", "%V")):
        entries = {entry["name"]: entry for entry in result["snapshots"][0][surface]}
        assert set(entries) == {
            "DirectExtract", "PromptPassword", "RecursiveExtract",
            "WatchFolder", "WatchFolderRecursive", "UnwatchFolder",
        }
        subject = "该目录下文件" if surface == "Folder" else "目录下文件"
        assert entries["RecursiveExtract"]["label"] == "递归解压" + subject
        assert entries["WatchFolderRecursive"]["label"] == "递归监控此目录"
        command = entries["RecursiveExtract"]["command"].replace(token, "D:\\")
        argv = _windows_argv(command)
        offset = 1 if launcher_mode == "app" else 2
        assert argv[offset] == "extract"
        assert ntpath.normpath(argv[offset + 1]) == "D:\\"
        assert ntpath.normpath(argv[argv.index("--out-dir") + 1]) == "D:\\"
        assert "--recursive" in argv
        watch = entries["WatchFolderRecursive"]["command"]
        assert "'watch','add'," in watch
        assert f"'{token}\\.'" in watch
        assert "'--recursive'" in watch
        assert "-WindowStyle Hidden" in watch
        assert "--recursive" not in entries["DirectExtract"]["command"]
        assert "--recursive" not in entries["WatchFolder"]["command"]
    assert {entry["name"] for entry in result["snapshots"][0]["File"]} == {"DirectExtract", "PromptPassword"}


def test_context_menu_directory_token_is_stable_for_normal_paths():
    command = 'sunpack.exe extract "%V\\." --out-dir "%V\\." --ask-pw --pause'
    argv = _windows_argv(command.replace("%V", r"D:\Archives"))

    assert ntpath.normpath(argv[2]) == r"D:\Archives"
    assert ntpath.normpath(argv[4]) == r"D:\Archives"
    assert argv[5:] == ["--ask-pw", "--pause"]

    watch_command = '"powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process -WindowStyle Hidden -FilePath ''sunpack.exe'' -ArgumentList @(''watch'',''add'',''%V\\.'',''--start'')"'
    watch_argv = _windows_argv(watch_command.replace("%V", r"D:\Archives"))
    command_text = watch_argv[watch_argv.index("-Command") + 1]
    assert "watch" in command_text
    assert "add" in command_text
    assert r"D:\Archives\." in command_text
    assert "--start" in command_text
    assert "--start" in command_text


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
