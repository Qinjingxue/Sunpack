import json
import os
import shutil
from pathlib import Path


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
    legacy: str | None,
    repo_root: Path,
) -> Path | None:
    explicit = os.environ.get(env_name)
    value = explicit or config.get(config_key) or default
    resolved = _resolve_tool(value, repo_root)
    if explicit or (resolved and resolved.is_file()) or not legacy:
        return resolved
    legacy_path = _resolve_tool(legacy, repo_root)
    return legacy_path if legacy_path and legacy_path.is_file() else resolved


def get_test_tools() -> dict[str, Path | None]:
    repo_root = _repo_root()
    config = {}
    path = _config_path()
    if path.exists():
        config = json.loads(path.read_text(encoding="utf-8"))

    seven_zip = _resolve_configured_tool(
        env_name="sunpack_TEST_7Z",
        config=config,
        config_key="seven_zip",
        default="tools/7z.exe",
        legacy=None,
        repo_root=repo_root,
    )
    seven_zip_sfx = _resolve_configured_tool(
        env_name="sunpack_TEST_7Z_SFX",
        config=config,
        config_key="seven_zip_sfx",
        default="tools/7zCon.sfx",
        legacy=None,
        repo_root=repo_root,
    )
    zstd_exe = _resolve_configured_tool(
        env_name="sunpack_TEST_ZSTD",
        config=config,
        config_key="zstd_exe",
        default=".sunpack_test_tools/zstd/zstd.exe",
        legacy="tools/zstd.exe",
        repo_root=repo_root,
    )
    rar_exe = _resolve_configured_tool(
        env_name="sunpack_TEST_RAR",
        config=config,
        config_key="rar_exe",
        default=".sunpack_test_tools/winrar/Rar.exe",
        legacy="tools/Rar.exe",
        repo_root=repo_root,
    )
    winrar_exe = _resolve_configured_tool(
        env_name="sunpack_TEST_WINRAR",
        config=config,
        config_key="winrar_exe",
        default=".sunpack_test_tools/winrar/WinRAR.exe",
        legacy="tools/WinRAR.exe",
        repo_root=repo_root,
    )
    if not winrar_exe or not winrar_exe.is_file():
        winrar_from_path = shutil.which("WinRAR.exe")
        winrar_exe = _resolve_tool(winrar_from_path, repo_root)

    return {
        "seven_zip": seven_zip,
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


def get_7z_cli_dll_path() -> str:
    """Locate the 7z.dll that belongs to the 7-Zip *command line* tool.

    This is part of the fixture-generator toolchain, not of the SunPack
    runtime: the product's 7-Zip backend is compiled into
    sunpack_sevenzip.dll / sunpack_sevenzip_worker.exe and never loads 7z.dll.
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
