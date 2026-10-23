"""Print system-tar Unicode reproductions without changing the corpus or writer."""
from __future__ import annotations

import argparse
import ctypes
import json
import locale
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import winreg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tar", default=shutil.which("tar.exe"))
    args = parser.parse_args()
    if not args.tar:
        parser.error("Windows tar.exe is required")
    tar = str(Path(args.tar).resolve())

    def execute(command, cwd=None):
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=30)
        return {"command": command, "returncode": result.returncode,
                "returncode_hex": f"0x{result.returncode & 0xFFFFFFFF:08X}",
                "stdout": result.stdout, "stderr": result.stderr}

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        build = f"{winreg.QueryValueEx(key, 'CurrentBuildNumber')[0]}.{winreg.QueryValueEx(key, 'UBR')[0]}"
    print(json.dumps({"windows": str(sys.getwindowsversion()), "build": build,
                      "acp": ctypes.windll.kernel32.GetACP(), "oemcp": ctypes.windll.kernel32.GetOEMCP(),
                      "locale": locale.setlocale(locale.LC_ALL),
                      "environment": {name: os.environ.get(name) for name in ("LANG", "LC_ALL", "LC_CTYPE")},
                      "version": execute([tar, "--version"])}, ensure_ascii=True), flush=True)
    # Include the DLL actually supplied beside tar, or the system library when
    # using the OS executable. Versions distinguish image updates from inputs.
    dll = Path(tar).with_name("archiveint.dll")
    if not dll.exists():
        dll = Path(os.environ["SystemRoot"]) / "System32/archiveint.dll"
    ps_paths = ",".join("'" + str(path).replace("'", "''") + "'" for path in (Path(tar), dll))
    print(json.dumps(execute([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        f"Get-Item -LiteralPath {ps_paths} | ForEach-Object {{ $_.FullName; $_.VersionInfo.FileVersion }}",
    ]), ensure_ascii=True), flush=True)
    with tempfile.TemporaryDirectory(prefix="sunpack-tar-diagnostic-") as temporary:
        root = Path(temporary)
        for case, name in (("ascii", "folder/file.txt"), ("unicode-file", "folder/说明.txt"),
                           ("unicode-directory", "日本語/file.txt"),
                           ("long-ascii", "nested/" + "long-name-" * 16 + "/payload.txt")):
            source = root / case
            path = source / name
            path.parent.mkdir(parents=True)
            path.write_text("minimal payload\n", encoding="utf-8")
            for format in ("pax", "zip"):
                command = [tar, "--format", format, "-cf", str(root / f"{case}.{format}")]
                if format == "zip":
                    command += ["--options", "zip:hdrcharset=UTF-8"]
                print(json.dumps({"case": case, "format": format,
                                  **execute(command + ["."], source)}, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
