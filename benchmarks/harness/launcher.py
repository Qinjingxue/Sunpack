"""Measure a uniquely staged native installation, including its resident runtime."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import psutil

from .memory import ProcessSampler
from .workspace import REPO_ROOT


class NativePackage:
    def __init__(self, root: Path, *, launcher: Path | None = None, profile="release", arch="x64", sample_ms=50):
        self.root = root.resolve()
        self.install = self.root / "installation"
        self.data = self.root / "ProgramData/SunPack"
        self.sample_seconds = sample_ms / 1000
        self.install.mkdir(parents=True)
        self.data.mkdir(parents=True)
        target = {"x64": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-msvc"}[arch]
        wrapper = REPO_ROOT / "native/sevenzip_bridge" / f"build-{arch}{'-ci' if profile == 'ci' else ''}" / "Release"
        sources = {
            "sunpack.exe": launcher or wrapper / "sunpack_launcher.exe",
            "sunpack-runtime.exe": launcher.parent / "sunpack-runtime.exe" if launcher else REPO_ROOT / ".cache/rust-target" / arch / target / profile / "sunpack-runtime.exe",
            "tools/sunpack_sevenzip_worker.exe": launcher.parent / "tools/sunpack_sevenzip_worker.exe" if launcher else wrapper / "sunpack_sevenzip_worker.exe",
            "sunpack_advanced_config.json": launcher.parent / "sunpack_advanced_config.json" if launcher else REPO_ROOT / "sunpack_advanced_config.json",
        }
        for name, source in sources.items():
            if not source.is_file():
                raise FileNotFoundError(f"Build the native {profile} package first, or supply --launcher: {source}")
            destination = self.install / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Copies avoid locking the developer build artifacts while the
            # staged runtime stays alive between measured requests.
            shutil.copy2(source, destination)
        (self.install / "VERSION.txt").write_text("product=SunPack\nversion=benchmark\n", encoding="utf-8")
        (self.data / "sunpack_config.json").write_text(json.dumps({
            "cli": {"language": "en"},
            "passwords": {"clipboard_passwords_enabled": False},
            "watch": {"tray_enabled": False, "toast_enabled": False, "clipboard_monitor_enabled": False},
            "post_extract": {"archive_cleanup_mode": "k"},
        }), encoding="utf-8")
        (self.data / "builtin_passwords.json").write_text('{"passwords":[]}', encoding="utf-8")
        self.launcher = self.install / "sunpack.exe"
        self.env = {**os.environ, "PROGRAMDATA": str(self.data.parent)}
        self.env.pop("SUNPACK_CONFIG_OVERRIDES", None)
        self._known: dict[int, psutil.Process] = {}
        self._active: psutil.Process | None = None

    def _processes(self):
        # Follow the active launcher during the measured command. Cache detached
        # runtime/worker handles so their resident memory remains in later samples.
        active = self._active
        if active is not None:
            try:
                for child in [active, *active.children(recursive=True)]:
                    self._known[child.pid] = child
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        alive = []
        for pid, process in list(self._known.items()):
            if process.is_running():
                alive.append(process)
            else:
                self._known.pop(pid, None)
        return alive

    def _discover_resident(self):
        # Startup can detach faster than the first sample. This scan is outside
        # the timed interval and scopes discovery to this unique installation.
        prefix = str(self.install).casefold() + os.sep
        for process in psutil.process_iter(["exe"]):
            if str(process.info.get("exe") or "").casefold().startswith(prefix):
                self._known[process.pid] = process

    def run(self, *arguments, json_output=True, accepted=(0,)) -> dict:
        command = [str(self.launcher), *map(str, arguments)]
        if json_output:
            command.append("--json")
        started = time.perf_counter()
        process = subprocess.Popen(command, cwd=self.data, env=self.env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self._active = psutil.Process(process.pid)
        except psutil.NoSuchProcess:
            self._active = None
        sampler = ProcessSampler(self.sample_seconds, processes=self._processes)
        with sampler:
            stdout, stderr = process.communicate()
            elapsed = time.perf_counter() - started
        self._active = None
        self._discover_resident()
        resident = ProcessSampler(processes=self._processes).take().to_dict()
        if process.returncode not in accepted:
            raise RuntimeError(f"native command failed ({process.returncode}): {command}\n{stdout.decode('utf-8', 'replace')}\n{stderr.decode('utf-8', 'replace')}")
        payload = json.loads(stdout) if json_output else stdout.decode("utf-8", "replace")
        return {
            "seconds": elapsed, "returncode": process.returncode, "response": payload,
            "peak_rss_mib": max(resident["rss_mib"], *(sample.rss_mib for sample in sampler.samples)),
            "peak_private_mib": max(resident["private_mib"], *(sample.private_mib for sample in sampler.samples)),
            "resident": resident,
            "samples": [sample.to_dict() for sample in sampler.samples],
        }

    def shutdown(self):
        self.run("--persistent-shutdown", json_output=False)
        self._known.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.shutdown()
