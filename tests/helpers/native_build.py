"""Resolve test binaries from the selected native architecture and build profile."""
from __future__ import annotations

import os
import sysconfig
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def sevenzip_build_dir() -> Path:
    default_arch = "arm64" if sysconfig.get_platform() == "win-arm64" else "x64"
    arch = os.environ.get("SUNPACK_TEST_ARCH", default_arch).lower()
    # Match the development setup and both test runners' default profile.
    profile = os.environ.get("SUNPACK_TEST_BUILD_PROFILE", "ci").lower()
    if arch not in {"x64", "arm64"}:
        raise ValueError(f"Unsupported SUNPACK_TEST_ARCH: {arch!r}")
    if profile not in {"ci", "release"}:
        raise ValueError(f"Unsupported SUNPACK_TEST_BUILD_PROFILE: {profile!r}")
    suffix = "-ci" if profile == "ci" else ""
    return ROOT / "native" / "sevenzip_bridge" / f"build-{arch}{suffix}" / "Release"


def sevenzip_artifact(name: str) -> Path:
    artifact = sevenzip_build_dir() / name
    if not artifact.is_file():
        raise FileNotFoundError(
            f"Native test artifact is missing: {artifact}. "
            "Run scripts/setup_windows_dev.ps1 with the matching -Arch and "
            "-BuildProfile before pytest; tests never build or fall back to other profiles."
        )
    return artifact
