from __future__ import annotations

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE_MODULE = ROOT / "sunpack" / "core" / "support" / "resource_lifecycle.py"
FORBIDDEN_NAMES = {"open"}
FORBIDDEN_ATTRIBUTES = {
    "open",
    "scandir",
    "walk",
    "read_bytes",
    "read_text",
    "write_bytes",
    "write_text",
    "rglob",
    "glob",
    "iterdir",
    "NamedTemporaryFile",
    "TemporaryFile",
    "ZipFile",
    "TarFile",
    "mmap",
}


def test_python_business_code_cannot_bypass_tracked_file_entry_points():
    violations: list[str] = []
    for path in sorted((ROOT / "sunpack").rglob("*.py")):
        if path == LIFECYCLE_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_NAMES:
                violations.append(f"{path.relative_to(ROOT)}:{node.lineno}:{node.func.id}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN_ATTRIBUTES:
                violations.append(f"{path.relative_to(ROOT)}:{node.lineno}:{node.func.attr}")
    assert violations == [], "untracked file-handle entry points:\n" + "\n".join(violations)


def test_rust_file_creation_cannot_bypass_tracked_file():
    lifecycle = "native/sunpack_native/src/io/resource_lifecycle.rs"
    patterns = (
        r"(?<!Tracked)File::(?:open|create|options)\(",
        r"(?:std::)?fs::File::",
        r"OpenOptions::new\(",
    )
    violations: list[str] = []
    for path in sorted((ROOT / "native" / "sunpack_native" / "src").rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        if relative != lifecycle and any(re.search(pattern, text) for pattern in patterns):
            violations.append(relative)
    assert violations == []


def test_rust_raw_windows_handle_sites_are_lifecycle_audited():
    allowed = {
        "native/sunpack_native/src/filesystem/windows.rs",
        "native/sunpack_native/src/io/iocp.rs",
    }
    discovered: set[str] = set()
    for path in sorted((ROOT / "native" / "sunpack_native" / "src").rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        if "CreateFileW(" in text:
            assert "NativeResourceGuard::register" in text
            discovered.add(path.relative_to(ROOT).as_posix())
    assert discovered <= allowed
