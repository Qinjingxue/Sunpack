"""Inno Setup compiler discovery shared by installer and GUI tests."""
import os
from pathlib import Path
import shutil

import pytest


def inno_compiler():
    candidates = [shutil.which("ISCC.exe")]
    candidates.extend(str(Path(os.environ.get(key, "")) / suffix) for key, suffix in (
        ("ProgramFiles(x86)", "Inno Setup 6/ISCC.exe"),
        ("ProgramFiles", "Inno Setup 6/ISCC.exe"),
        ("LOCALAPPDATA", "Programs/Inno Setup 6/ISCC.exe"),
    ))
    compiler = next((path for path in candidates if path and Path(path).is_file()), None)
    if compiler is None:
        pytest.skip("Inno Setup compiler is not installed")
    return compiler
