import os
from dataclasses import asdict
from typing import Any

from sunpack.cli.cli_constants import EXIT_USAGE
from sunpack.cli.cli_types import CliCommandResult, CliPasswordSummary
from sunpack.config.loader import apply_config_overrides
from sunpack.config.schema import normalize_config_value
from sunpack.config.detection_view import directory_scan_mode, rule_pipeline_config, scan_filter_config, scan_filters_enabled
from sunpack.config.cli_settings import load_cli_language_from_config
from sunpack.i18n import I18nContext
from sunpack.passwords import dedupe_passwords, get_builtin_passwords, PasswordStore, read_password_file
from sunpack.passwords.internal.clipboard import read_clipboard_passwords


def build_effective_config(config: dict) -> dict[str, Any]:
    pipeline_config = rule_pipeline_config(config)
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
            "rule_pipeline": {
                layer: [
                    {"name": rule.get("name"), "enabled": rule.get("enabled", False)}
                    for rule in pipeline_config.get(layer, [])
                    if isinstance(rule, dict)
                ]
                for layer in ("precheck",)
            }
        },
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


def _fact_dict(res) -> dict:
    facts = getattr(res, "facts", None)
    if isinstance(facts, dict):
        return facts
    bag = getattr(res, "fact_bag", None)
    if bag is not None and hasattr(bag, "to_dict"):
        result = bag.to_dict()
        errors = bag.get_errors() if hasattr(bag, "get_errors") else {}
        if errors:
            result["_fact_errors"] = errors
        return result
    return {}


def scan_result_to_item(res) -> dict[str, Any]:
    facts = _fact_dict(res)
    main_path = res.main_path
    all_parts = list(res.all_parts or [])
    return {
        "main_path": main_path,
        "all_parts": all_parts,
        "decision": res.decision,
        "detected_ext": res.detected_ext,
        "split_role": getattr(res, "split_role", facts.get("file.split_role")),
        "reasons": list(res.matched_rules or []),
        "facts": facts,
    }


def inspect_result_to_item(res) -> dict[str, Any]:
    facts = _fact_dict(res)
    path_info = facts.get("path") or {}
    size = facts.get("file.size", 0)
    ext = facts.get("file.ext") or path_info.get("ext") or ""
    fact_errors = facts.get("_fact_errors") or []
    return {
        "path": res.path,
        "decision": getattr(res, "decision", "archive" if res.should_extract else "not_archive"),
        "decision_stage": getattr(res, "decision_stage", ""),
        "discarded_at": getattr(res, "discarded_at", "") or None,
        "deciding_rule": getattr(res, "deciding_rule", "") or None,
        "stop_reason": getattr(res, "stop_reason", "") or None,
        "should_extract": res.should_extract,
        "size": facts.get("file.size", size),
        "ext": ext,
        "detected_ext": res.detected_ext or facts.get("file.detected_ext") or None,
        "container_type": facts.get("file.container_type") or "unknown",
        "identity_confirmed": bool(facts.get("file.probe_detected_archive")),
        "identity_offset": int(facts.get("file.probe_offset") or 0),
        "is_split_candidate": bool(res.split_role or facts.get("file.is_split_candidate")),
        "skipped_by_size_limit": bool(res.stop_reason and "size below" in res.stop_reason.lower()),
        "reasons": list(res.matched_rules or []),
        "fact_errors": fact_errors,
    }


def password_summary_item(summary: CliPasswordSummary) -> dict[str, Any]:
    return asdict(summary)
