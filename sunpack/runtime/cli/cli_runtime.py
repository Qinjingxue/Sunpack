import os
from dataclasses import asdict
from typing import Any

from sunpack.runtime.cli.cli_constants import EXIT_USAGE
from sunpack.runtime.cli.cli_types import CliCommandResult, CliPasswordSummary
from sunpack.core.config.loader import apply_config_overrides
from sunpack.core.config.schema import normalize_config_value
from sunpack.core.config.detection_view import directory_scan_mode, scan_filter_config, scan_filters_enabled
from sunpack.core.config.cli_settings import load_cli_language_from_config
from sunpack.core.i18n import I18nContext
from sunpack.core.passwords import dedupe_passwords, get_builtin_passwords, PasswordStore, read_password_file
from sunpack.core.passwords.internal.clipboard import read_clipboard_passwords


def build_effective_config(config: dict) -> dict[str, Any]:
    size_rule = scan_filter_config(config, "size_range")
    size_range_min_bytes = None
    if isinstance(size_rule, dict):
        if "gte" in size_rule:
            size_range_min_bytes = size_rule["gte"]
        elif "greater_than_or_equal" in size_rule:
            size_range_min_bytes = size_rule["greater_than_or_equal"]
    return {
        "size_range_min_bytes": size_range_min_bytes,
        "worker": {
            "controller": "native_worker",
            "sizing": "selected_by_worker",
        },
        "detection": {
            "enabled": bool(config.get("detection", {}).get("enabled", True)),
        },
        "embedded_scan": dict(config.get("embedded_scan") or {}),
        "filesystem": {
            "directory_scan_mode": directory_scan_mode(config),
            "scan_filters_enabled": scan_filters_enabled(config),
            "scan_filters": [
                {"name": item.get("name"), "enabled": item.get("enabled", False)}
                for item in config.get("filesystem", {}).get("scan_filters", [])
                if isinstance(item, dict)
            ]
        },
    }

def resolve_target_paths(paths: list[str], *, base_dir: str | None = None) -> tuple[list[str], list[str]]:
    target_paths = []
    missing_paths = []
    for raw_path in paths:
        norm_path = os.path.normpath(raw_path)
        if not os.path.isabs(norm_path):
            norm_path = os.path.join(base_dir or os.getcwd(), norm_path)
        norm_path = os.path.abspath(norm_path)
        if os.path.exists(norm_path):
            target_paths.append(norm_path)
        else:
            missing_paths.append(raw_path)
    return target_paths, missing_paths


def resolve_common_root(paths: list[str]) -> str:
    normalized_paths = [os.path.normpath(path) for path in paths if path]
    if not normalized_paths:
        return os.getcwd()
    try:
        common_root = os.path.commonpath(normalized_paths)
    except ValueError:
        first = normalized_paths[0]
        common_root = first if os.path.isdir(first) else os.path.dirname(first)
    if os.path.isfile(common_root):
        common_root = os.path.dirname(common_root)
    return common_root or os.getcwd()


def collect_cli_passwords(
    args,
    prompt_text: str | None = None,
    input_prompt: str | None = None,
) -> list[str]:
    i18n = I18nContext(load_cli_language_from_config())
    prompt_text = prompt_text or i18n.t("cli.password_prompt")
    input_prompt = input_prompt or i18n.t("cli.password_input_prompt")
    passwords = list(getattr(args, "password", []) or [])
    if getattr(args, "password_file", None):
        passwords.extend(read_password_file(args.password_file))
    if getattr(args, "prompt_passwords", False):
        passwords.extend(prompt_for_passwords(prompt_text=prompt_text, input_prompt=input_prompt))
    return dedupe_passwords(passwords)


def collect_clipboard_passwords(config: dict | None) -> list[str]:
    password_config = config.get("passwords") if isinstance(config, dict) else {}
    if not isinstance(password_config, dict) or not bool(password_config.get("clipboard_passwords_enabled", False)):
        return []
    return read_clipboard_passwords()


def prompt_for_passwords(
    prompt_text: str | None = None,
    input_prompt: str | None = None,
) -> list[str]:
    i18n = I18nContext(load_cli_language_from_config())
    prompt_text = prompt_text or i18n.t("cli.password_prompt")
    input_prompt = input_prompt or i18n.t("cli.password_input_prompt")
    passwords = []
    print(prompt_text, flush=True)
    while True:
        line = input(input_prompt)
        # ``input()`` normally removes the line ending, but some Windows
        # console hosts used by Explorer context-menu launches leave a bare
        # carriage return behind.  That is still an empty submitted line, not
        # a password.  Do not strip other whitespace: it may intentionally be
        # part of a password.
        line = line.rstrip("\r\n")
        if not line:
            break
        passwords.append(line)
    return dedupe_passwords(passwords)


async def prompt_for_passwords_async(
    ctx,
    prompt_text: str | None = None,
    input_prompt: str | None = None,
) -> list[str]:
    prompt_text = prompt_text or ctx.t("cli.password_prompt")
    input_prompt = input_prompt or ctx.t("cli.password_input_prompt")
    passwords = []
    print(prompt_text, file=ctx.stdout, flush=True)
    while True:
        line = (await ctx.readline(input_prompt)).rstrip("\r\n")
        if not line:
            break
        passwords.append(line)
    return dedupe_passwords(passwords)


async def collect_cli_passwords_async(
    args,
    ctx,
    prompt_text: str | None = None,
    input_prompt: str | None = None,
) -> list[str]:
    prompt_text = prompt_text or ctx.t("cli.password_prompt")
    input_prompt = input_prompt or ctx.t("cli.password_input_prompt")
    passwords = list(getattr(args, "password", []) or [])
    if getattr(args, "password_file", None):
        password_file = str(args.password_file)
        if not os.path.isabs(password_file):
            password_file = os.path.join(ctx.cwd, password_file)
        passwords.extend(read_password_file(password_file))
    if getattr(args, "prompt_passwords", False):
        passwords.extend(
            await prompt_for_passwords_async(
                ctx,
                prompt_text=prompt_text,
                input_prompt=input_prompt,
            )
        )
    return dedupe_passwords(passwords)


def build_password_summary(
    user_passwords: list[str],
    use_builtin_passwords: bool,
    recent_passwords: list[str] | None = None,
    clipboard_passwords: list[str] | None = None,
) -> CliPasswordSummary:
    recent = dedupe_passwords(recent_passwords or [])
    clipboard = dedupe_passwords(clipboard_passwords or [])
    builtin = get_builtin_passwords() if use_builtin_passwords else []
    store = PasswordStore.from_sources(
        cli_passwords=user_passwords,
        clipboard_passwords=clipboard,
        recent_passwords=recent,
        builtin_passwords=builtin,
    )
    return CliPasswordSummary(
        user_passwords=store.user_passwords,
        clipboard_passwords=store.clipboard_passwords,
        recent_passwords=store.recent_passwords,
        builtin_passwords=store.builtin_passwords,
        combined_passwords=store.candidates(),
        use_builtin_passwords=use_builtin_passwords,
    )


def apply_runtime_config_overrides(config: dict, args, *, base_dir: str | None = None) -> dict:
    """Apply CLI flag overrides as one config layer, then report the summary keys."""
    overrides = {}
    payload: dict[str, Any] = {}
    section = payload.setdefault
    if getattr(args, "recursive_extract", None) is not None:
        overrides["recursive_extract"] = args.recursive_extract
        payload["recursive_extract"] = normalize_config_value(("recursive_extract",), args.recursive_extract)
    if getattr(args, "archive_cleanup_mode", None) is not None:
        overrides["archive_cleanup_mode"] = args.archive_cleanup_mode
        section("post_extract", {})["archive_cleanup_mode"] = normalize_config_value(
            ("post_extract", "archive_cleanup_mode"), args.archive_cleanup_mode,
        )
    output_dir = getattr(args, "output_dir", None)
    if output_dir and not os.path.isabs(output_dir) and base_dir is not None:
        output_dir = os.path.join(base_dir, output_dir)
    output_root = os.path.abspath(os.path.normpath(output_dir or base_dir or "."))
    overrides["output_dir"] = output_root
    section("output", {})["root"] = output_root
    if getattr(args, "flatten_single_directory", None) is not None:
        overrides["flatten_single_directory"] = args.flatten_single_directory
        section("post_extract", {})["flatten_single_directory"] = args.flatten_single_directory
    if getattr(args, "write_progress_manifest", False):
        overrides["write_progress_manifest"] = True
        section("extraction", {})["write_progress_manifest"] = True
    if getattr(args, "allow_partial", False):
        overrides["content_requirement"] = "allow_partial"
        section("extraction", {})["content_requirement"] = "allow_partial"
    if getattr(args, "directory_passwords", None) is not None:
        overrides["directory_passwords"] = bool(args.directory_passwords)
        section("passwords", {})["directory_passwords_enabled"] = bool(args.directory_passwords)
    apply_config_overrides(config, payload)
    return overrides


def result_for_missing(command: str, args, missing_paths: list[str], ctx) -> tuple[int, CliCommandResult]:
    errors = [ctx.t("cli.target_not_found", path=path) for path in missing_paths]
    return EXIT_USAGE, CliCommandResult(
        command=command,
        inputs={"paths": list(getattr(args, "paths", []) or [])},
        summary={"missing_count": len(missing_paths)},
        errors=errors,
    )


def scan_result_to_item(res) -> dict[str, Any]:
    return {
        "main_path": res.main_path,
        "all_parts": list(res.all_parts or []),
        "format": str(res.format or ""),
        "discovery_source": str(res.discovery_source or ""),
        "discovery_reason": str(res.discovery_reason or ""),
        "archive_input": dict(res.archive_input or {}),
        "split_role": "first" if len(res.all_parts or []) > 1 else "",
    }


def inspect_result_to_item(res) -> dict[str, Any]:
    return {
        "path": res.path,
        "status": res.status,
        "should_extract": res.should_extract,
        "format": str(res.format or ""),
        "discovery_source": str(res.source or ""),
        "reason": str(res.reason or ""),
        "archive_input": dict(res.archive_input or {}) if res.archive_input else None,
    }

def password_summary_item(summary: CliPasswordSummary) -> dict[str, Any]:
    return asdict(summary)
