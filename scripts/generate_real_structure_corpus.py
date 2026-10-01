"""Regenerate small, self-authored fixtures with tools independent of SunPack.

Run with .venv/Scripts/python.exe -m scripts.generate_real_structure_corpus.
No archive bytes are read or written by Python; the tools and Rust own binary IO.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from tests.helpers.native_fixture import file_inventory
from tests.helpers.tool_config import get_optional_rar, get_optional_winrar


ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "tests/real/corpus/structure"
STRUCTURE_CASES = (
    ("bsdtar-ustar", "tar", "ustar"),
    ("bsdtar-pax-long-unicode", "tar", "pax"),
    ("bsdtar-gnu-long", "tar", "gnutar"),
    ("bsdtar-duplicate", "tar", "duplicate"),
    ("bsdtar-zip", "zip", "zip"),
    ("bsdtar-zip-cp437", "zip", "zip-cp437"),
    ("bsdtar-zip-duplicate", "zip", "zip-duplicate"),
    ("bsdtar-empty-zip", "zip", "zip-empty"),
    ("winrar-zip", "zip", "winrar-zip"),
    ("rar5-solid", "rar", "rar5"),
)


def run(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert result.returncode == 0, (command, result.stdout, result.stderr)
    return result.stdout


def generate(destination: Path = DESTINATION, cases: tuple = STRUCTURE_CASES) -> list[dict]:
    tar = shutil.which("tar.exe")
    rar, winrar = get_optional_rar(), get_optional_winrar()
    assert tar, "Windows tar is required to regenerate the corpus"
    destination.mkdir(parents=True, exist_ok=True)
    samples = []
    with tempfile.TemporaryDirectory(prefix="sunpack-corpus-") as temporary:
        workspace = Path(temporary)
        for case_id, archive_format, variant in cases:
            source = workspace / case_id
            source.mkdir()
            long_name = "nested/" + "long-name-" * 16 + "/payload.txt"
            members = {"marker.txt": f"corpus::{case_id}\n", "empty.bin": "", "nested/second.txt": "second member\n"}
            if variant in {"pax", "gnutar"}:
                members[long_name] = "long path payload\n"
            if variant in {"pax", "zip", "winrar-zip", "rar5"}:
                members["日本語/说明.txt"] = "多语言文件名与内容\n"
            if variant == "duplicate":
                members = {"same.txt": "first revision\n"}
            if variant == "zip-cp437":
                members["café/über.txt"] = "CP437 legacy filename\n"
            if variant == "zip-duplicate":
                members = {"same.txt": "duplicate ZIP member\n"}
            if variant == "zip-empty":
                members = {}
            for name, text in members.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8", newline="\n")
                os.utime(path, (1704067200, 1704067200))
            expected = file_inventory(source)
            archive = destination / f"{case_id}.{archive_format}"
            archive.unlink(missing_ok=True)
            if variant.startswith("winrar"):
                assert winrar, "WinRAR ZIP writer is required"
                command = [str(winrar), "a", "-afzip", "-r", "-ep1", "-ibck", "-inul", "-y", str(archive), "*"]
                quoted_winrar = str(winrar).replace("'", "''")
                version = run([
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    f"(Get-Item -LiteralPath '{quoted_winrar}').VersionInfo.FileVersion",
                ], source).strip()
                creator = f"WinRAR {version} ZIP writer (independent of the 7-Zip fixture generator)"
            elif variant == "rar5":
                assert rar, "Rar.exe writer is required"
                command = [str(rar), "a", "-ma5", "-s", "-m3", "-r", "-ep1", "-idq", "-y", str(archive), "*"]
                creator = run([str(rar)], source).splitlines()[1].strip()
            else:
                writer_format = "ustar" if variant == "duplicate" else "zip" if variant.startswith("zip") else variant
                command = [tar, "--format", writer_format, "-cf", str(archive)]
                if variant == "zip-cp437":
                    command.extend(["--options", "zip:hdrcharset=CP437"])
                command.extend(sorted(members))
                if variant == "zip-duplicate":
                    command.append("same.txt")
                    expected["same(1).txt"] = expected["same.txt"]
                if variant == "zip-empty":
                    file_list = source / "empty-list.txt"
                    file_list.write_text("", encoding="utf-8")
                    command.extend(["-T", file_list.name])
                creator = run([tar, "--version"], source).strip()
            run(command, source)
            commands = [command]
            if variant == "duplicate":
                (source / "same.txt").write_text("second revision\n", encoding="utf-8", newline="\n")
                replacement = file_inventory(source)["same.txt"]
                expected["same(1).txt"] = replacement
                append = [tar, "-rf", str(archive), "same.txt"]
                run(append, source)
                commands.append(append)
            samples.append({
                "id": case_id, "file": archive.name, "format": archive_format,
                "creator": creator, "commands": [
                    [Path(arg).name if arg in {tar, str(rar), str(winrar), str(archive)} else arg for arg in command]
                    for command in commands
                ], "expected_files": expected,
            })
    artifacts = file_inventory(destination)
    for sample in samples:
        sample["archive"] = artifacts[sample["file"]]
    (destination / "manifest.json").write_text(json.dumps({"samples": samples}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return samples


if __name__ == "__main__":
    generate()
