import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import psutil


@dataclass
class Package:
    launcher: Path
    data: Path
    tools: Path
    env: dict[str, str]

    def run(self, *arguments, cwd=None, input=None):
        return subprocess.run(
            [str(self.launcher), *map(str, arguments)],
            cwd=cwd or self.data,
            env=self.env,
            text=True,
            encoding="utf-8",
            input=input,
            capture_output=True,
            timeout=60,
        )

    def json(self, *arguments, cwd=None, code=0):
        result = self.run(*arguments, "--json", cwd=cwd)
        assert result.returncode == code, (result.stdout, result.stderr)
        return json.loads(result.stdout)


@pytest.fixture
def package(tmp_path, repo_root):
    arch = os.environ.get("SUNPACK_TEST_ARCH", "x64")
    profile = os.environ.get("SUNPACK_TEST_BUILD_PROFILE", "ci")
    target = {"x64": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-msvc"}[arch]
    suffix = "-ci" if profile == "ci" else ""
    built = repo_root / ".cache" / "rust-target" / arch / target / profile
    wrapper = repo_root / "native" / "sevenzip_bridge" / f"build-{arch}{suffix}" / "Release"
    tool_root = repo_root / ("tools" if arch == "x64" else "tools-arm64")
    sources = {
        "bin/sunpack.exe": wrapper / "sunpack_launcher.exe",
        "sunpack-runtime.exe": built / "sunpack-runtime.exe",
        "tools/sunpack_sevenzip_worker.exe": wrapper / "sunpack_sevenzip_worker.exe",
        "sunpack_advanced_config.json": repo_root / "sunpack_advanced_config.json",
        "VERSION.txt": None,
    }
    staged = tmp_path / "程序"
    data = tmp_path / "ProgramData" / "SunPack"
    staged.mkdir()
    data.mkdir(parents=True)
    for relative, source in sources.items():
        destination = staged / relative
        destination.parent.mkdir(exist_ok=True)
        if source is None:
            destination.write_text("product=SunPack\nversion=test\n", encoding="utf-8")
            continue
        assert source.is_file(), f"Run scripts/setup_windows_dev.ps1 first: {source}"
        try:
            os.link(source, destination)
        except OSError:
            shutil.copyfile(source, destination)
    overrides = {
        "cli": {"language": "en"},
        "passwords": {"clipboard_passwords_enabled": False},
        "watch": {"tray_enabled": False, "toast_enabled": False, "clipboard_monitor_enabled": False},
        "post_extract": {"archive_cleanup_mode": "k"},
    }
    (data / "sunpack_config.json").write_text(json.dumps(overrides), encoding="utf-8")
    (data / "builtin_passwords.json").write_text('{"passwords":[]}', encoding="utf-8")
    env = {**os.environ, "PROGRAMDATA": str(data.parent)}
    env.pop("SUNPACK_CONFIG_OVERRIDES", None)
    app = Package(staged / "bin" / "sunpack.exe", data, tool_root, env)
    try:
        yield app
    finally:
        owners = []
        for state in data.glob("runtime-*.state"):
            try:
                owners.append(psutil.Process(int(state.read_text(encoding="utf-8").splitlines()[3])))
            except (OSError, ValueError, IndexError, psutil.NoSuchProcess):
                pass
        result = app.run("--persistent-shutdown")
        assert result.returncode == 0, (result.stdout, result.stderr)
        for owner in owners:
            owner.wait(timeout=30)
