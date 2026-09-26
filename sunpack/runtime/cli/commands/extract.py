from sunpack.runtime.cli.cli_aliases import COMMAND_ALIASES
from sunpack.runtime.cli.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from sunpack.runtime.cli.cli_parsers import (
    CliHelpFormatter,
    build_common_parser,
    build_detection_parser,
    build_extract_config_override_parser,
    build_password_parser,
    build_process_mode_parser,
    localize_help_action,
)
from sunpack.runtime.cli.cli_runtime import (
    apply_runtime_config_overrides,
    build_password_summary,
    collect_clipboard_passwords,
    collect_cli_passwords_async,
    password_summary_item,
    prompt_for_passwords_async,
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
)
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.cli.persistent_runtime import load_request_config, pipeline_engine
from sunpack.core.contracts.failures import FailureInfo
from sunpack.core.contracts.retry_targets import (
    merge_latest_results,
    password_retry_paths,
    result_error,
    result_failure,
    result_outcome,
    result_path,
)
from sunpack.core.contracts.results import OutcomeKind
from sunpack.core.passwords import dedupe_passwords
from sunpack.core.support.collections import dedupe_values
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
import asyncio
import os
import uuid

COMMAND = "extract"
ORDER = 10


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        aliases=COMMAND_ALIASES[COMMAND],
        parents=[build_common_parser(ctx), build_detection_parser(ctx), build_password_parser(ctx), build_extract_config_override_parser(ctx), build_process_mode_parser(ctx)],
        help=ctx.t("cli.extract.help"),
        usage="sunpack extract [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    parser.set_defaults(command=COMMAND)
    localize_help_action(parser, ctx)
    parser.add_argument("--direct-file", "--direct", dest="direct_file", action="store_true", help=ctx.t("cli.extract.direct_file"))
    parser.add_argument("paths", nargs="+", help=ctx.t("cli.extract.paths"))


async def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths, base_dir=ctx.cwd)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths, ctx)

    from sunpack.runtime.cli.runtime_state import runtime_host

    host = runtime_host()
    lease_owner = uuid.uuid4().hex
    if host is not None:
        conflict = host.archive_registry.reserve(lease_owner, "foreground", target_paths)
        if conflict is not None and conflict.origin == "watch":
            return EXIT_TASK_FAILED, CliCommandResult(
                command=COMMAND,
                inputs={"paths": target_paths},
                summary={"status": "watch_busy", "conflicts": list(conflict.paths)},
                errors=[ctx.t("cli.watch_busy")],
            )
        if conflict is not None:
            return EXIT_TASK_FAILED, CliCommandResult(
                command=COMMAND,
                inputs={"paths": target_paths},
                summary={"status": "busy", "conflicts": list(conflict.paths)},
                errors=[ctx.t("cli.watch_busy")],
            )
        current_task = asyncio.current_task()
        if current_task is not None:
            current_task.add_done_callback(lambda _task: host.archive_registry.release(lease_owner))

    config = load_request_config(ctx.cwd)
    config_overrides = apply_runtime_config_overrides(config, args, base_dir=ctx.cwd)
    try:
        passwords = await collect_cli_passwords_async(
            args,
            ctx,
            prompt_text=ctx.t("cli.password_prompt"),
            input_prompt=ctx.t("cli.password_input_prompt"),
        )
        clipboard_passwords = collect_clipboard_passwords(config)
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={"paths": list(args.paths)}, summary={}, errors=[ctx.t("cli.operation_failed", error=exc)])

    common_root = resolve_common_root(target_paths)
    config.setdefault("output", {})["common_root"] = common_root

    if len(target_paths) == 1:
        reporter.info(ctx.t("cli.extract.single_target", path=target_paths[0]))
    else:
        reporter.info(ctx.t("cli.extract.target_paths", count=len(target_paths)))
        for path in target_paths:
            reporter.detail(ctx.t("cli.detail_item_path", path=path))
    reporter.detail(ctx.t("cli.extract.common_root", root=common_root))

    attempts = []
    retry_count = 0
    current_targets = list(target_paths)
    latest_target_results: dict[str, object] = {}
    all_processed_keys: list[str] = []
    all_recovered_outputs: list[dict] = []
    cleanup_results_by_path = {}
    initial_password_summary = build_password_summary(
        passwords,
        use_builtin_passwords=not args.no_builtin_passwords,
        clipboard_passwords=clipboard_passwords,
    )
    run_config = _extract_run_config(
        config,
        initial_password_summary,
        quiet=bool(getattr(reporter, "quiet", False) or getattr(reporter, "json_mode", False)),
        verbose=bool(getattr(reporter, "verbose", False)),
    )
    deep_detect = bool(getattr(args, "deep_detect", False))
    engine_context = pipeline_engine(run_config)
    async with engine_context as engine:
        while True:
            password_summary = build_password_summary(
                passwords,
                use_builtin_passwords=not args.no_builtin_passwords,
                clipboard_passwords=clipboard_passwords,
            )
            run_config["user_passwords"] = dedupe_passwords(
                password_summary.user_passwords + password_summary.clipboard_passwords
            )
            run_config["builtin_passwords"] = list(password_summary.builtin_passwords)
            response = await engine.run(
                current_targets,
                direct=bool(getattr(args, "direct_file", False)),
                request_config=run_config,
                stdout=ctx.stderr if args.json else ctx.stdout,
                stderr=ctx.stderr,
                origin="foreground",
                detection_options=EmbeddedOptions(force_scan=deep_detect),
            )
            summary = response.summary
            failed_tasks = list(summary.failed_tasks)
            failures = list(summary.failures)
            processed_keys = list(summary.processed_keys)
            merge_latest_results(latest_target_results, summary)
            all_processed_keys.extend(processed_keys)
            for item in list(getattr(summary, "recovered_outputs", []) or []):
                if item not in all_recovered_outputs:
                    all_recovered_outputs.append(item)
            for item in list(getattr(summary, "cleanup_results", []) or []):
                cleanup_results_by_path[os.path.normcase(os.path.abspath(item.path))] = item
            retry_targets = [path for path in password_retry_paths(summary) if os.path.exists(path)]
            attempts.append({
                "success_count": summary.success_count,
                "failed_count": len(failed_tasks),
                "processed_count": len(set(processed_keys)),
                "partial_success_count": getattr(summary, "partial_success_count", 0),
                "recovered_outputs": list(getattr(summary, "recovered_outputs", []) or []),
                "wrong_password_failure": has_password_failure(failures),
                "failures": [failure.to_dict() for failure in failures],
            })
            if not _should_retry_password_failure(args, retry_targets):
                break
            if not await _confirm_password_retry(ctx):
                break
            try:
                new_passwords = await prompt_for_passwords_async(
                    ctx,
                    prompt_text=ctx.t("cli.password_prompt"),
                    input_prompt=ctx.t("cli.password_input_prompt"),
                )
            except (EOFError, KeyboardInterrupt):
                break
            if not new_passwords:
                reporter.info(ctx.t("cli.extract.retry_no_passwords"))
                break
            passwords = _dedupe([*passwords, *new_passwords])
            current_targets = retry_targets
            retry_count += 1
            reporter.info(ctx.t("cli.extract.retry_round"))
        recent_passwords = engine.recent_passwords

    password_summary = build_password_summary(
        passwords,
        use_builtin_passwords=not args.no_builtin_passwords,
        recent_passwords=recent_passwords,
        clipboard_passwords=clipboard_passwords,
    )

    if latest_target_results:
        final_results = list(latest_target_results.values())
        success_count = sum(
            result_outcome(item) == OutcomeKind.COMPLETE_SUCCESS
            for item in final_results
        )
        partial_success_count = sum(
            result_outcome(item) == OutcomeKind.PARTIAL_SUCCESS
            for item in final_results
        )
        failed_tasks = [
            _target_result_error(item)
            for item in final_results
            if result_outcome(item) == OutcomeKind.FAILURE
        ]
        processed_keys = all_processed_keys
        recovered_outputs = all_recovered_outputs
        cleanup_results = list(cleanup_results_by_path.values())
    else:
        success_count = summary.success_count
        partial_success_count = getattr(summary, "partial_success_count", 0)
        recovered_outputs = list(getattr(summary, "recovered_outputs", []) or [])
        cleanup_results = list(getattr(summary, "cleanup_results", []) or [])

    result = CliCommandResult(
        command=COMMAND,
        inputs={
            "paths": target_paths,
            "common_root": common_root,
            "json": args.json,
            "quiet": args.quiet,
            "verbose": args.verbose,
            "config_overrides": config_overrides,
            "direct_file": bool(getattr(args, "direct_file", False)),
            "deep_detect": deep_detect,
        },
        summary={
            "success_count": success_count,
            "failed_count": len(failed_tasks),
            "processed_count": len(set(processed_keys)),
            "partial_success_count": partial_success_count,
            "recovered_outputs": recovered_outputs,
            "use_builtin_passwords": not args.no_builtin_passwords,
            "password_retry_count": retry_count,
            "cleanup_retry_count": sum(
                max(0, item.attempts - 1) for item in cleanup_results
            ),
            "cleanup_results": [
                {
                    "path": item.path,
                    "mode": item.mode,
                    "status": item.status,
                    "attempts": item.attempts,
                    "error_code": item.error_code,
                    "message": item.message,
                }
                for item in cleanup_results
            ],
        },
        errors=failed_tasks,
        items=[password_summary_item(password_summary)],
        tasks=attempts,
    )
    if failed_tasks:
        return EXIT_TASK_FAILED, result
    return 0, result



def _target_result_error(item) -> str:
    path = result_path(item)
    failure = result_failure(item)
    message = result_error(item) or (getattr(failure, "message", "") if failure is not None else "")
    name = os.path.basename(path) if path else ""
    if name and message:
        return f"{name} [{message}]"
    return message or name

def _extract_run_config(
    config: dict,
    password_summary,
    *,
    quiet: bool = False,
    verbose: bool = False,
) -> dict:
    run_config = dict(config)
    run_config["cli"] = {
        **(config.get("cli", {}) if isinstance(config.get("cli"), dict) else {}),
        "quiet": quiet,
        "verbose": verbose,
    }
    run_config["extraction"] = {
        **(config.get("extraction", {}) if isinstance(config.get("extraction"), dict) else {}),
        "quiet": not verbose,
    }
    run_config["user_passwords"] = dedupe_passwords(
        password_summary.user_passwords + password_summary.clipboard_passwords
    )
    run_config["builtin_passwords"] = password_summary.builtin_passwords
    return run_config


def has_password_failure(failures: list[FailureInfo]) -> bool:
    return any(failure.is_password_failure for failure in failures)


def _should_retry_password_failure(args, retry_targets: list[str]) -> bool:
    return bool(retry_targets) and not getattr(args, "json", False) and not getattr(args, "quiet", False)


async def _confirm_password_retry(ctx) -> bool:
    while True:
        try:
            answer = (await ctx.readline(ctx.t("cli.password_retry_prompt"))).strip().lower()
        except EOFError:
            return False
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no", ""}:
            return False
        print(ctx.t("cli.answer_yes_no"), file=ctx.stdout, flush=True)


_dedupe = dedupe_values
