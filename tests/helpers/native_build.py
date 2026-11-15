"""Resolve test binaries from the selected native architecture and build profile."""
from __future__ import annotations

import os
import sysconfig
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUST_TARGETS = {"x64": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-msvc"}


def selected_build() -> tuple[str, str]:
    default_arch = "arm64" if sysconfig.get_platform() == "win-arm64" else "x64"
    arch = os.environ.get("SUNPACK_TEST_ARCH", default_arch).lower()
    # Match the development setup and both test runners' default profile.
    profile = os.environ.get("SUNPACK_TEST_BUILD_PROFILE", "ci").lower()
    if arch not in RUST_TARGETS:
        raise ValueError(f"Unsupported SUNPACK_TEST_ARCH: {arch!r}")
    if profile not in {"ci", "release"}:
        raise ValueError(f"Unsupported SUNPACK_TEST_BUILD_PROFILE: {profile!r}")
    return arch, profile


def rust_build_dir(root: Path, arch: str, profile: str) -> Path:
    return root / ".cache" / "rust-target" / RUST_TARGETS[arch] / profile


def native_build_dir(root: Path, arch: str, profile: str, component: str) -> Path:
    return root / ".cache" / "native" / arch / profile / component / "Release"


def sevenzip_build_dir() -> Path:
    return native_build_dir(ROOT, *selected_build(), "sevenzip_bridge")


def sevenzip_artifact(name: str) -> Path:
    artifact = sevenzip_build_dir() / name
    if not artifact.is_file():
        raise FileNotFoundError(
            f"Native test artifact is missing: {artifact}. "
            "Run scripts/setup_windows_dev.ps1 with the matching -Arch and "
            "-BuildProfile before pytest; tests never build or fall back to other profiles."
        )
    return artifact
