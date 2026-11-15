import json
import os
import re
import subprocess
import shutil
from pathlib import Path

from tests.helpers.native_build import selected_build


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _config_path() -> Path:
    return Path(__file__).resolve().parents[1] / "test_tools.json"


def _resolve_tool(value: str | None, repo_root: Path) -> Path | None:
    if not value:
        return None
    expanded = os.path.expandvars(value)
    path = Path(expanded)
    if not path.is_absolute():
        path = repo_root / path
    return path.resolve()


def _resolve_configured_tool(
    *,
    env_name: str,
    config: dict[str, str],
    config_key: str,
    default: str | None,
    repo_root: Path,
) -> Path | None:
    return _resolve_tool(os.environ.get(env_name) or config.get(config_key) or default, repo_root)


def get_test_tools() -> dict[str, Path | None]:
    repo_root = _repo_root()
    config = {}
    path = _config_path()
    if path.exists():
        config = json.loads(path.read_text(encoding="utf-8"))

    arch, _ = selected_build()
    seven_zip_root = "tools/arm64" if arch == "arm64" else "tools"
    seven_zip = _resolve_configured_tool(
        env_name="sunpack_TEST_7Z",
        config=config,
        config_key="seven_zip",
        default=f"{seven_zip_root}/7z.exe",
        repo_root=repo_root,
    )
    seven_zip_sfx = _resolve_configured_tool(
        env_name="sunpack_TEST_7Z_SFX",
        config=config,
        config_key="seven_zip_sfx",
        default=f"{seven_zip_root}/7zCon.sfx",
        repo_root=repo_root,
    )
    seven_zip_zstd = _resolve_configured_tool(
        env_name="sunpack_TEST_7Z_ZSTD", config=config, config_key="seven_zip_zstd",
        default="tools/7zip-zstd/7z.exe", repo_root=repo_root,
    )
    zstd_exe = _resolve_configured_tool(
        env_name="sunpack_TEST_ZSTD",
        config=config,
        config_key="zstd_exe",
        default="tools/zstd/zstd.exe",
        repo_root=repo_root,
    )
    rar_exe = _resolve_configured_tool(
        env_name="sunpack_TEST_RAR",
        config=config,
        config_key="rar_exe",
        default="tools/winrar/Rar.exe",
        repo_root=repo_root,
    )
    winrar_exe = _resolve_configured_tool(
        env_name="sunpack_TEST_WINRAR",
        config=config,
        config_key="winrar_exe",
        default="tools/winrar/WinRAR.exe",
        repo_root=repo_root,
    )
    if not winrar_exe or not winrar_exe.is_file():
        winrar_from_path = shutil.which("WinRAR.exe")
        winrar_exe = _resolve_tool(winrar_from_path, repo_root)

    return {
        "seven_zip": seven_zip,
        "seven_zip_zstd": seven_zip_zstd,
        "seven_zip_sfx": seven_zip_sfx,
        "zstd_exe": zstd_exe,
        "rar_exe": rar_exe,
        "winrar_exe": winrar_exe,
    }


def require_7z() -> Path:
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        raise FileNotFoundError("7z.exe is required for this test. Configure tests/test_tools.json or sunpack_TEST_7Z.")
    return seven_zip


def require_7z_zstd() -> Path:
    tool = get_test_tools()["seven_zip_zstd"]
    if not tool or not tool.is_file():
        raise FileNotFoundError("7-Zip-Zstandard fixture writer requires sunpack_TEST_7Z_ZSTD or seven_zip_zstd in tests/test_tools.json")
    return tool


def get_7z_cli_dll_path() -> str:
    """Locate the 7z.dll that belongs to the 7-Zip *command line* tool.

    This is part of the fixture-generator toolchain, not of the SunPack
    runtime: the product's 7-Zip backend is compiled into
    sunpack_sevenzip_worker.exe and never loads 7z.dll.
    It exists so tests and benchmarks that generate archives with tools\\7z.exe
    can assert its companion module is present.
    """
    dll = require_7z().parent / "7z.dll"
    if not dll.is_file():
        raise FileNotFoundError(
            f"7z.dll (companion module of the 7z.exe fixture generator) is missing next to {dll.parent}"
        )
    return str(dll)


def require_zstd() -> Path:
    zstd_exe = get_test_tools()["zstd_exe"]
    if not zstd_exe or not zstd_exe.is_file():
        raise FileNotFoundError("zstd.exe is required for this test. Configure tests/test_tools.json or sunpack_TEST_ZSTD.")
    return zstd_exe


def get_optional_rar() -> Path | None:
    rar = get_test_tools()["rar_exe"]
    return rar if rar and rar.is_file() else None


def get_optional_rar_sfx() -> Path | None:
    rar = get_optional_rar()
    if rar is None or not (rar.parent / "Default.SFX").is_file():
        return None
    return rar


def get_optional_winrar() -> Path | None:
    winrar = get_test_tools()["winrar_exe"]
    return winrar if winrar and winrar.is_file() else None


def acceptance_generator_errors() -> list[str]:
    """The mandatory real-format matrix, shared by setup and acceptance.

    Resolve the same overrides as the fixture writers. Optional private corpora
    remain optional; only generators required by the public matrix are checked.
    """
    tools = get_test_tools()
    seven_zip = tools["seven_zip"]
    rar = tools["rar_exe"]
    lz4 = tools["seven_zip_zstd"]
    requirements = (
        ("7-Zip", seven_zip, ("i",), None),
        ("7-Zip DLL", seven_zip.parent / "7z.dll" if seven_zip else None, None, None),
        ("7-Zip SFX", tools["seven_zip_sfx"], None, None),
        # Match setup's pinned writer: later WinRAR releases removed -ma4.
        ("RAR4/RAR5 (WinRAR 6.22 x64)", rar, ("iver",), r"RAR 6\.22 x64"),
        ("RAR SFX", rar.parent / "Default.SFX" if rar else None, None, None),
        ("WinRAR", tools["winrar_exe"], None, None),
        ("Zstandard", tools["zstd_exe"], ("--version",), None),
        ("7-Zip-Zstandard LZ4", lz4, ("i",), r"(?m)^\s*\d+\s+ED\s+\S+\s+LZ4\s*$"),
        ("7-Zip-Zstandard DLL", lz4.parent / "7z.dll" if lz4 else None, None, None),
    )
    errors = []
    for label, path, arguments, pattern in requirements:
        if path is None or not path.is_file():
            errors.append(f"{label} generator is missing: {path}")
            continue
        if arguments is None:
            continue
        try:
            result = subprocess.run(
                [str(path), *arguments], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="replace", check=False,
            )
        except OSError as error:
            errors.append(f"{label} generator cannot run: {path}: {error}")
            continue
        # Rar's informational iver command returns 7 even when it succeeds.
        valid_exit = arguments == ("iver",) or result.returncode == 0
        if not valid_exit or (pattern is not None and re.search(pattern, result.stdout) is None):
            errors.append(f"{label} generator lacks the required capability: {path}")
    return errors


if __name__ == "__main__":
    errors = acceptance_generator_errors()
    if errors:
        print("Acceptance generator preflight failed:\n  - " + "\n  - ".join(errors))
        print("Run scripts\\setup_windows_dev.ps1 or configure tests/test_tools.json / sunpack_TEST_*.")
        raise SystemExit(1)
    print("Acceptance generators are ready (7-Zip/SFX, RAR4/RAR5/SFX, Zstandard, LZ4).")
