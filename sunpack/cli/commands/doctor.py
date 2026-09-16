from __future__ import annotations

import os
from sunpack.support.resource_lifecycle import named_task_temporary_file

from sunpack.cli.cli_constants import EXIT_TASK_FAILED
from sunpack.cli.cli_parsers import CliHelpFormatter, build_config_output_parser, localize_help_action
from sunpack.cli.cli_types import CliCommandResult
from sunpack.cli.persistent_runtime import load_request_config_payload
from sunpack.config.config_validator import validate_config_payload
from sunpack.filesystem.watcher.service import list_watch_roots
from sunpack.support.process_executable import current_process_executable, is_packaged_process
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path, program_data_dir


COMMAND = "doctor"
ORDER = 60

SUNPACK_REGISTRY_KEY = r"Software\SunPack"
ENVIRONMENT_REGISTRY_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
SERVICE_REGISTRY_KEY = r"SYSTEM\CurrentControlSet\Services\SunPackWatchBroker"
TOAST_APP_ID_KEY = r"Software\Classes\AppUserModelId\SunPack.Watch.Toast"
TOAST_CLSID = "{C5A6B4E9-3184-44E2-9F15-6A71804F7A36}"
TOAST_LOCAL_SERVER_KEY = rf"Software\Classes\CLSID\{TOAST_CLSID}\LocalServer32"
PATH_MARKER_NAME = "PathAddedByInstaller"

CONTEXT_PARENT_KEYS = (
    r"Software\Classes\Directory\shell\SunPack",
    r"Software\Classes\Directory\Background\shell\SunPack",
    r"Software\Classes\*\shell\SunPack",
)
CONTEXT_COMMAND_KEYS = (
    r"Software\Classes\SunPack.FolderContextMenu\shell\DirectExtract\command",
    r"Software\Classes\SunPack.BackgroundContextMenu\shell\DirectExtract\command",
    r"Software\Classes\SunPack.FileContextMenu\shell\DirectExtract\command",
)

_INSTALL_CHECK_LABELS = {
    "data_dir": {"en": "Program data", "zh": "程序数据目录"},
    "broker_service": {"en": "Watch Broker service", "zh": "Watch Broker 服务"},
    "toast_registration": {"en": "Toast registration", "zh": "Toast 注册"},
    "machine_path": {"en": "Machine PATH", "zh": "系统 PATH"},
    "context_menu": {"en": "Explorer context menu", "zh": "资源管理器右键菜单"},
    "startup": {"en": "Windows startup", "zh": "Windows 开机启动"},
}


def register(subparsers, ctx):
    common_parser = build_config_output_parser(ctx)
    parser = subparsers.add_parser(
        COMMAND,
        parents=[common_parser],
        help=ctx.t("cli.doctor.help"),
        usage="sunpack doctor [options]",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)


def _check(name: str, status: str, detail: str | None = None, **extra) -> dict:
    result = {"name": name, "status": status}
    if detail:
        result["detail"] = str(detail)
    result.update(extra)
    return result


def _config_check(ctx) -> tuple[dict, dict | None, bool]:
    try:
        config_path, payload = load_request_config_payload(ctx.cwd)
        validation = validate_config_payload(payload)
    except Exception as exc:
        return _check("config", "fail", str(exc)), None, False
    if not validation.get("ok"):
        errors = [str(error) for error in validation.get("errors", [])]
        return (
            _check(
                "config",
                "fail",
                "; ".join(errors) or "configuration validation failed",
                config_path=str(config_path),
                errors=errors,
            ),
            payload,
            False,
        )
    return _check("config", "ok", str(config_path)), payload, True


def _native_check() -> dict:
    try:
        import sunpack_native

        return _check("native", "ok", getattr(sunpack_native, "__file__", None))
    except Exception as exc:
        return _check("native", "fail", str(exc))


def _resource_check(name: str, resolver) -> dict:
    try:
        return _check(name, "ok", resolver())
    except Exception as exc:
        return _check(name, "fail", str(exc))


def _read_hklm_value(path: str, name: str = ""):
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
            value, _value_type = winreg.QueryValueEx(key, name)
        return value
    except FileNotFoundError:
        return None


def _hklm_key_exists(path: str) -> bool:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False


def _install_dir():
    return current_process_executable().parent


def _normalized_path_entry(value) -> str:
    return str(value).strip().strip('"').replace("/", "\\").rstrip("\\").casefold()


def _text_contains_path(text, path) -> bool:
    return _normalized_path_entry(path) in str(text).replace("/", "\\").casefold()


def _normalized_command(value) -> str:
    return " ".join(str(value).strip().split()).casefold()


def _data_dir_check() -> dict:
    try:
        path = program_data_dir()
        if not path.is_dir():
            return _check("data_dir", "fail", f"directory not found: {path}")
        with named_task_temporary_file(
            prefix=".sunpack-doctor-",
            dir=path,
        ):
            pass
        return _check("data_dir", "ok", str(path))
    except Exception as exc:
        return _check("data_dir", "fail", str(exc))


def _broker_service_check() -> dict:
    try:
        image_path = _read_hklm_value(SERVICE_REGISTRY_KEY, "ImagePath")
        if image_path is None:
            return _check("broker_service", "fail", "service is not installed")
        expected = _install_dir() / "service" / "sunpack-watch-broker.exe"
        if not _text_contains_path(image_path, expected):
            return _check("broker_service", "fail", f"service points to: {image_path}")
        return _check("broker_service", "ok", str(expected))
    except Exception as exc:
        return _check("broker_service", "fail", str(exc))


def _toast_registration_check() -> dict:
    try:
        activator = _read_hklm_value(TOAST_APP_ID_KEY, "CustomActivator")
        command = _read_hklm_value(TOAST_LOCAL_SERVER_KEY)
        if activator is None or command is None:
            return _check("toast_registration", "fail", "machine registration is missing")
        if str(activator).casefold() != TOAST_CLSID.casefold():
            return _check("toast_registration", "fail", f"unexpected activator: {activator}")
        executable = current_process_executable()
        if not _text_contains_path(command, executable) or "--toast-activated" not in str(command):
            return _check("toast_registration", "fail", f"activation command is stale: {command}")
        return _check("toast_registration", "ok", str(command))
    except Exception as exc:
        return _check("toast_registration", "fail", str(exc))


def _machine_path_check() -> dict:
    try:
        marker = _read_hklm_value(SUNPACK_REGISTRY_KEY, PATH_MARKER_NAME)
        if marker is None:
            return _check("machine_path", "skip", "not enabled by installer")
        if marker != 1:
            return _check("machine_path", "fail", f"invalid installer marker: {marker}")
        machine_path = _read_hklm_value(ENVIRONMENT_REGISTRY_KEY, "Path")
        if machine_path is None:
            return _check("machine_path", "fail", "machine PATH is unavailable")
        install_dir = _normalized_path_entry(_install_dir())
        entries = {_normalized_path_entry(entry) for entry in str(machine_path).split(";") if entry.strip()}
        if install_dir not in entries:
            return _check("machine_path", "fail", "installer marker exists but install directory is missing")
        return _check("machine_path", "ok", str(_install_dir()))
    except Exception as exc:
        return _check("machine_path", "fail", str(exc))


def _context_menu_check() -> dict:
    try:
        parents = [_hklm_key_exists(path) for path in CONTEXT_PARENT_KEYS]
        if not any(parents):
            return _check("context_menu", "skip", "not installed")
        if not all(parents):
            return _check("context_menu", "fail", "registration is incomplete")

        launcher = _install_dir() / "sunpack.exe"
        for command_key in CONTEXT_COMMAND_KEYS:
            command = _read_hklm_value(command_key)
            if command is None:
                return _check("context_menu", "fail", f"missing command: {command_key}")
            if not _text_contains_path(command, launcher):
                return _check("context_menu", "fail", f"command points to another launcher: {command}")
        return _check("context_menu", "ok", str(launcher))
    except Exception as exc:
        return _check("context_menu", "fail", str(exc))


def _startup_registration() -> tuple[bool, str, str]:
    from sunpack.platform.windows.startup import startup_command, startup_status

    enabled, command = startup_status()
    return enabled, command, startup_command() if enabled else ""


def _startup_check() -> dict:
    try:
        enabled, command, expected = _startup_registration()
        if not enabled:
            return _check("startup", "skip", "disabled")
        if _normalized_command(command) != _normalized_command(expected):
            return _check("startup", "fail", f"startup command is stale: {command}")
        return _check("startup", "ok", command)
    except Exception as exc:
        return _check("startup", "fail", str(exc))


def _installation_checks() -> list[dict]:
    return [
        _data_dir_check(),
        _broker_service_check(),
        _toast_registration_check(),
        _machine_path_check(),
        _context_menu_check(),
        _startup_check(),
    ]


def _toast_check(config: dict | None, config_valid: bool) -> dict:
    if not config_valid:
        return _check("toast", "skip", "configuration is invalid")
    watch = config.get("watch") if isinstance(config, dict) else None
    if not isinstance(watch, dict):
        return _check("toast", "skip", "watch configuration is unavailable")
    if not bool(watch.get("toast_enabled", True)):
        return _check("toast", "skip", "disabled")
    try:
        from sunpack.platform.windows.toast_host import self_test_toast

        self_test_toast()
        return _check("toast", "ok")
    except Exception as exc:
        return _check("toast", "fail", str(exc))


def _watch_root_checks() -> list[dict]:
    _roots_path, roots = list_watch_roots()
    checks = []
    for root in roots:
        if os.path.isdir(root):
            checks.append(_check("watch_root", "ok", path=root))
        else:
            checks.append(_check("watch_root", "warn", "directory not found", path=root))
    return checks


def _human_check_text(check: dict, ctx) -> str:
    name = check["name"]
    label = _INSTALL_CHECK_LABELS.get(name, {}).get(ctx.language)
    if not label:
        label = ctx.t(f"cli.doctor.check.{name}")
    if name == "watch_root":
        label = f"{label} {check.get('path', '')}".rstrip()
    detail = check.get("detail")
    return f"[{str(check['status']).upper()}] {label}" + (f": {detail}" if detail else "")


def handle(args, ctx):
    config_check, config, config_valid = _config_check(ctx)
    checks = [
        config_check,
        _native_check(),
        _resource_check("sevenzip_dll", get_7z_dll_path),
        _resource_check("sevenzip_worker", get_sevenzip_bridge_worker_path),
    ]
    if is_packaged_process():
        checks.extend(_installation_checks())
    checks.append(_toast_check(config, config_valid))
    try:
        checks.extend(_watch_root_checks())
    except Exception as exc:
        checks.append(_check("watch_root", "warn", f"unable to read watch roots: {exc}"))

    counts = {
        "checks": len(checks),
        "ok": sum(check["status"] == "ok" for check in checks),
        "warnings": sum(check["status"] == "warn" for check in checks),
        "skipped": sum(check["status"] == "skip" for check in checks),
        "failed": sum(check["status"] == "fail" for check in checks),
    }
    errors = [str(check.get("detail", check["name"])) for check in checks if check["status"] == "fail"]
    if ctx.reporter is not None:
        for check in checks:
            text = _human_check_text(check, ctx)
            if check["status"] == "fail":
                ctx.reporter.error(text)
            else:
                ctx.reporter.info(text)
        ctx.reporter.info(
            ctx.t(
                "cli.doctor.summary",
                ok=counts["ok"],
                warnings=counts["warnings"],
                skipped=counts["skipped"],
                failed=counts["failed"],
            )
        )

    return (
        EXIT_TASK_FAILED if counts["failed"] else 0,
        CliCommandResult(
            command=COMMAND,
            inputs={},
            summary=counts,
            errors=errors,
            items=checks,
        ),
    )
