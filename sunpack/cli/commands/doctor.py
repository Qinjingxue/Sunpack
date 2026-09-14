from __future__ import annotations

import os

from sunpack.cli.cli_constants import EXIT_TASK_FAILED
from sunpack.cli.cli_parsers import CliHelpFormatter, build_config_output_parser, localize_help_action
from sunpack.cli.cli_types import CliCommandResult
from sunpack.cli.persistent_runtime import load_request_config_payload
from sunpack.config.config_validator import validate_config_payload
from sunpack.filesystem.watcher.service import list_watch_roots
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path


COMMAND = "doctor"
ORDER = 60


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
        _toast_check(config, config_valid),
    ]
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
