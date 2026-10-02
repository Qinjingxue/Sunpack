import os
import platform
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

from sunpack.core.support.process_executable import current_process_executable, is_packaged_process


_REQUEST_RESOLVED_PATHS: ContextVar[dict[Path, Path] | None] = ContextVar(
    "resource_request_resolved_paths", default=None,
)


@contextmanager
def resource_path_resolution_scope(*, enabled: bool = True):
    """Reuse canonical resource paths within one request, never across requests."""
    token = _REQUEST_RESOLVED_PATHS.set({} if enabled else None)
    try:
        yield
    finally:
        _REQUEST_RESOLVED_PATHS.reset(token)


def resolve_resource_path(path: Path) -> Path:
    resolved = _REQUEST_RESOLVED_PATHS.get()
    if resolved is None:
        return path.resolve()
    # Absolute lexical keys keep relative paths correct if a command changes cwd.
    key = Path(os.path.abspath(path))
    value = resolved.get(key)
    if value is None:
        value = path.resolve()
        resolved[key] = value
        resolved.setdefault(value, value)
    return value


def program_data_dir() -> Path:
    program_data = os.environ.get("PROGRAMDATA", "").strip()
    if not program_data:
        raise RuntimeError("PROGRAMDATA is not defined; SunPack requires the Windows ProgramData directory.")
    return Path(program_data) / "SunPack"


def writable_data_dir() -> Path:
    return program_data_dir() if is_packaged_process() else candidate_resource_roots()[0]


def dedupe_paths(paths: list[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(resolve_resource_path(path)).lower()
        if key not in seen:
            seen.add(key)
            deduped.append(path)
    return deduped


def first_existing_path(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def candidate_resource_roots(request_cwd: str | Path | None = None) -> list[Path]:
    roots: list[Path] = []

    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        roots.append(current_process_executable().parent)
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(resolve_resource_path(Path(meipass)))

    module_root = resolve_resource_path(Path(__file__)).parents[3]
    invocation_root = resolve_resource_path(Path(request_cwd) if request_cwd is not None else Path.cwd())
    roots.extend([
        module_root,
        invocation_root,
        invocation_root / "sunpack-2",
    ])

    return dedupe_paths(roots)


def candidate_resource_paths(filename: str, request_cwd: str | Path | None = None) -> list[Path]:
    return [root / filename for root in candidate_resource_roots(request_cwd)]


def tool_dir_candidates() -> tuple[Path, ...]:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return (Path("tools-arm64"), Path("tools"))
    return (Path("tools"), Path("tools-x64"))


def find_resource_path(filename: str) -> Path | None:
    return first_existing_path(candidate_resource_paths(filename))


def get_resource_path(filename: str) -> Path:
    return writable_data_dir() / filename


def get_7z_path() -> str:
    for root in candidate_resource_roots():
        for relative in tuple(tool_dir / "7z.exe" for tool_dir in tool_dir_candidates()) + (Path("7z.exe"),):
            seven_z = root / relative
            if seven_z.exists():
                return str(seven_z)
    raise FileNotFoundError("Required bundled 7z.exe was not found under tools\\ or the application root.")


def get_sevenzip_bridge_worker_path() -> str:
    relatives = (
        Path("native") / "sevenzip_bridge" / "build-x64" / "Release" / "sunpack_sevenzip_worker.exe",
        Path("native") / "sevenzip_bridge" / "build-arm64" / "Release" / "sunpack_sevenzip_worker.exe",
        Path("native") / "sevenzip_bridge" / "build" / "Release" / "sunpack_sevenzip_worker.exe",
        Path("native") / "sevenzip_bridge" / "build" / "Debug" / "sunpack_sevenzip_worker.exe",
        *tuple(tool_dir / "sunpack_sevenzip_worker.exe" for tool_dir in tool_dir_candidates()),
        Path("sunpack_sevenzip_worker.exe"),
    )
    for root in candidate_resource_roots():
        for relative in relatives:
            worker = root / relative
            if worker.exists():
                return str(worker)
    raise FileNotFoundError("Required sunpack_sevenzip_worker.exe was not found under tools\\ or native\\sevenzip_bridge\\build.")


def get_toast_library_path() -> str:
    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    relatives = (
        Path("native") / "toast_host" / f"build-{arch}" / "Release" / "sunpack_toast.dll",
        Path("native") / "toast_host" / "build" / "Release" / "sunpack_toast.dll",
        Path("native") / "toast_host" / "build" / "Debug" / "sunpack_toast.dll",
        *tuple(tool_dir / "sunpack_toast.dll" for tool_dir in tool_dir_candidates()),
        Path("sunpack_toast.dll"),
    )
    for root in candidate_resource_roots():
        for relative in relatives:
            host = root / relative
            if host.exists():
                return str(host)
    raise FileNotFoundError(
        "Optional sunpack_toast.dll was not found under tools\\ or native\\toast_host\\build."
    )
