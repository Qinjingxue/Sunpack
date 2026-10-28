from __future__ import annotations

import os
import platform
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from sunpack_native import fast_hash128_file


SERVICE_ENV = "SUNPACK_WATCH_BROKER_SERVICE_NAME"
PIPE_ENV = "SUNPACK_WATCH_BROKER_PIPE_NAME"
BINARY_ENV = "SUNPACK_WATCH_BROKER_BINARY_PATH"
HASH_ENV = "SUNPACK_WATCH_BROKER_BINARY_XXH128"
TEST_SERVICE_PREFIX = "SunPackWatchBrokerTest_"
TEST_PIPE_PREFIX = r"\\.\pipe\SunPack.WatchBroker.Test."
REPO_ROOT = Path(__file__).resolve().parents[1]
SERVICE_MANAGER = REPO_ROOT / "scripts" / "manage_test_watch_service.ps1"
MANAGED_ENVIRONMENT = (SERVICE_ENV, PIPE_ENV, BINARY_ENV, HASH_ENV)


def isolated_broker_environment() -> bool:
    return (
        os.environ.get(SERVICE_ENV, "").startswith(TEST_SERVICE_PREFIX)
        and os.environ.get(PIPE_ENV, "").startswith(TEST_PIPE_PREFIX)
    )


def _powershell_host() -> str:
    host = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if host is None:
        raise RuntimeError("PowerShell is required to manage the temporary Watch Broker service")
    return host


def _ensure_watch_broker_binary() -> Path:
    configured = os.environ.get(BINARY_ENV, "").strip()
    if configured:
        binary = Path(configured).resolve()
        if not binary.is_file():
            raise RuntimeError(f"configured Watch Broker executable does not exist: {binary}")
        return binary

    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        build_arch, rust_target = "x64", "x86_64-pc-windows-msvc"
    elif machine in {"arm64", "aarch64"}:
        build_arch, rust_target = "arm64", "aarch64-pc-windows-msvc"
    else:
        raise RuntimeError(f"unsupported Windows architecture for Watch Broker: {platform.machine()}")

    target_dir = REPO_ROOT / ".cache" / "rust-target" / build_arch
    manifest = REPO_ROOT / "native" / "sunpack_watch_broker" / "Cargo.toml"
    binary = target_dir / rust_target / "release" / "sunpack-watch-broker.exe"
    print("==> Building temporary Watch Broker service", flush=True)
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "--manifest-path",
            str(manifest),
            "--release",
            "--target",
            rust_target,
            "--target-dir",
            str(target_dir),
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    if not binary.is_file():
        raise RuntimeError(f"Watch Broker build did not produce the expected executable: {binary}")
    return binary


def _run_service_manager(action: str, service_name: str, pipe_name: str, binary: Path) -> None:
    command = [
        _powershell_host(),
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SERVICE_MANAGER),
        "-Action",
        action,
        "-ServiceName",
        service_name,
        "-PipeName",
        pipe_name,
    ]
    if action == "Install":
        command.extend(["-BrokerPath", str(binary)])
    subprocess.run(command, cwd=REPO_ROOT, check=True)


@contextmanager
def temporary_watch_broker_service() -> Iterator[None]:
    """Build and expose one isolated Broker service for a watch benchmark run."""
    binary = _ensure_watch_broker_binary()
    run_id = uuid4().hex
    service_name = f"{TEST_SERVICE_PREFIX}{run_id}"
    pipe_name = f"{TEST_PIPE_PREFIX}{run_id}"
    previous = {name: os.environ.get(name) for name in MANAGED_ENVIRONMENT}
    installed = False
    try:
        os.environ[SERVICE_ENV] = service_name
        os.environ[PIPE_ENV] = pipe_name
        os.environ[BINARY_ENV] = str(binary)
        os.environ[HASH_ENV] = fast_hash128_file(binary)
        print(f"==> Installing temporary Watch Broker service: {service_name}", flush=True)
        _run_service_manager("Install", service_name, pipe_name, binary)
        installed = True
        yield
    finally:
        try:
            if installed:
                print(f"==> Uninstalling temporary Watch Broker service: {service_name}", flush=True)
                _run_service_manager("Uninstall", service_name, pipe_name, binary)
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


@contextmanager
def watch_broker_lease() -> Iterator[dict[str, object]]:
    if not isolated_broker_environment():
        raise RuntimeError(
            "watch benchmarks require the isolated Broker launcher; "
            "run them with `python -m benchmarks watch <scenario>`"
        )
    from sunpack_native import (
        watch_broker_acquire,
        watch_broker_is_connected,
        watch_broker_release,
    )

    watch_broker_acquire()
    try:
        connected = bool(watch_broker_is_connected())
        if not connected:
            raise RuntimeError("isolated Watch Broker did not connect")
        binary_path = os.environ.get(BINARY_ENV, "")
        yield {
            "service_name": os.environ[SERVICE_ENV],
            "pipe_name": os.environ[PIPE_ENV],
            "binary_path": binary_path,
            "binary_xxh128": os.environ.get(HASH_ENV, "").strip().lower()
            or (fast_hash128_file(binary_path) if binary_path else ""),
            "connected": connected,
        }
    finally:
        watch_broker_release()
