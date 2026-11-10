from sunpack.core.support.path_keys import case_key
from sunpack.runtime.cli.cli_aliases import COMMAND_ALIASES
from sunpack.runtime.cli.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from sunpack.runtime.cli.cli_parsers import (
    build_common_parser,
    build_detection_parser,
    build_extract_config_override_parser,
    build_password_parser,
)
from sunpack.runtime.cli.cli_runtime import (
    apply_runtime_config_overrides,
    build_password_store,
    collect_clipboard_passwords,
    collect_cli_passwords_async,
    interrupted_result,
    password_summary_item,
    prompt_for_passwords_async,
    resolve_common_root,
    resolve_target_paths,
)
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.cli.persistent_runtime import load_request_config, pipeline_engine
from sunpack.core.contracts.failures import FailureInfo
from sunpack.core.contracts.retry_targets import (
    merge_latest_results,
    password_retry_paths,
    password_retry_results,
    password_retry_failures,
)
from sunpack.core.contracts.results import RunSummary
from sunpack.core.contracts.run_state import RunState
from sunpack.core.passwords import dedupe_passwords
from sunpack.core.support.filesystem_scan_errors import is_filesystem_scan_failure
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
        parents=[build_common_parser(ctx), build_detection_parser(ctx), build_password_parser(ctx), build_extract_config_override_parser(ctx)],
        help=ctx.t("cli.extract.help"),
    )
    parser.set_defaults(command=COMMAND)
    parser.add_argument("--direct-file", "--direct", dest="direct_file", action="store_true", help=ctx.t("cli.extract.direct_file"))
    parser.add_argument("paths", nargs="+", help=ctx.t("cli.extract.paths"))


async def handle(args, ctx, *, operation="extract"):
    is_scan = operation == "scan"
    reporter = ctx.reporter
    target_paths = resolve_target_paths(args.paths, base_dir=ctx.cwd)

    from sunpack.runtime.cli.cli import command_work_broker
    from sunpack.runtime.cli.runtime_state import runtime_host

    host = runtime_host()
    lease_owner = uuid.uuid4().hex
    if host is not None:
        conflict = host.archive_registry.reserve(lease_owner, "foreground", target_paths)
        if conflict is not None:
            watch_busy = conflict.origin == "watch"
            message = ctx.t("cli.watch_busy" if watch_busy else "cli.archive_busy")
            async with command_work_broker(ctx) as broker:
                await broker.run("cli_output", "", reporter.error, message)
            return EXIT_TASK_FAILED, CliCommandResult(
                command=operation,
                inputs={"paths": target_paths},
                summary={"status": "watch_busy" if watch_busy else "busy", "conflicts": list(conflict.paths)},
                errors=[message],
            )
        current_task = asyncio.current_task()
        if current_task is not None:
            current_task.add_done_callback(lambda _task: host.archive_registry.release(lease_owner))

    config = load_request_config(ctx.cwd)
    config_overrides = apply_runtime_config_overrides(config, args, base_dir=ctx.cwd)
    try:
        passwords = await collect_cli_passwords_async(args, ctx)
        clipboard_passwords = collect_clipboard_passwords(config)
    except Exception as exc:
        message = ctx.t("cli.operation_failed", error=exc)
        async with command_work_broker(ctx) as broker:
            await broker.run("cli_output", "", reporter.error, message)
        return EXIT_USAGE, CliCommandResult(command=operation, inputs={"paths": list(args.paths)}, summary={}, errors=[message])

    common_root = resolve_common_root(target_paths)
    config.setdefault("output", {})["common_root"] = common_root

    def report_targets():
        if len(target_paths) == 1:
            reporter.info(ctx.t("cli.extract.single_target", path=target_paths[0]))
        else:
            reporter.info(ctx.t("cli.extract.target_paths", count=len(target_paths)))
            if reporter.verbose:
                for path in target_paths:
                    reporter.detail(ctx.t("cli.detail_item_path", path=path))
        if reporter.verbose:
            reporter.detail(ctx.t("cli.extract.common_root", root=common_root))

    if not is_scan and not reporter.json_mode:
        async with command_work_broker(ctx) as broker:
            await broker.run("cli_output", "", report_targets)

    current_targets = target_paths
    if not is_scan:
        attempts = []
        retry_count = 0
        latest_target_results = {}
        all_processed_keys: set[str] = set()
        scan_report = RunState()
        all_recovered_outputs: list[dict] = []
        cleanup_results_by_path = {}
    initial_password_store = build_password_store(
        passwords,
        use_builtin_passwords=not args.no_builtin_passwords,
        clipboard_passwords=clipboard_passwords,
    )
    run_config = _extract_run_config(
        config,
        initial_password_store,
        verbose=bool(getattr(reporter, "verbose", False)),
        json_mode=bool(args.json),
    )
    deep_detect = bool(getattr(args, "deep_detect", False))
    run_config["extraction"]["operation"] = operation
    engine_context = pipeline_engine(config)
    if not args.json and getattr(ctx.stdout, "isatty", lambda: False)():
        reporter.info(ctx.t("interrupt.hint"))
    async with engine_context as engine:
        while True:
            response = await engine.run(
                current_targets,
                direct=bool(getattr(args, "direct_file", False)),
                recursive=args.recursive,
                request_config=run_config,
                stdout=ctx.stderr if args.json else ctx.stdout,
                stderr=ctx.stderr,
                input_reader=ctx.readline,
                origin="foreground",
                detection_options=EmbeddedOptions(force_scan=deep_detect),
            )
            summary = response.summary
            if response.interrupted:
                return interrupted_result(ctx, operation, {"paths": target_paths}, response.interruption_cleanup_errors)
            # Scan reports the facts from this whole pass, including unknown
            # passwords. Only extraction offers interactive retry rounds.
            if is_scan:
                break
            failures = summary.failures
            scan_report.record_failures(summary.scan_failures, ctx.language)
            processed_keys = summary.processed_keys
            merge_latest_results(latest_target_results, summary)
            all_processed_keys.update(processed_keys)
            recovered_outputs = summary.recovered_outputs
            for item in recovered_outputs:
                if item not in all_recovered_outputs:
                    all_recovered_outputs.append(item)
            for item in summary.cleanup_results:
                cleanup_results_by_path[case_key(os.path.abspath(item.path))] = item
            retry_targets = [path for path in password_retry_paths(summary) if os.path.exists(path)]
            attempts.append({
                "success_count": summary.success_count,
                "failed_count": summary.failed_count,
                "scan_error_count": summary.scan_error_count,
                "input_error_count": summary.input_error_count,
                "processed_count": len(processed_keys),
                "partial_success_count": summary.partial_success_count,
                "recovered_outputs": recovered_outputs,
                "wrong_password_failure": has_password_failure(failures),
                "failures": [failure.to_dict() for failure in failures if not is_filesystem_scan_failure(failure)],
            })
            if not _should_retry_password_failure(args, retry_targets):
                break
            if not await _confirm_password_retry(ctx):
                break
            try:
                new_passwords = await prompt_for_passwords_async(ctx)
            except (EOFError, KeyboardInterrupt):
                break
            if not new_passwords:
                reporter.info(ctx.t("cli.extract.retry_no_passwords"))
                break
            passwords = dedupe_passwords([*passwords, *new_passwords])
            run_config["user_passwords"] = passwords
            # Only promoted nested retries should be deleted under keep mode.
            # This immutable, request-local set is replaced on each retry round.
            run_config["promoted_nested_retry_paths"] = frozenset(
                case_key(os.path.abspath(item.input_path))
                for item in password_retry_results(summary)
                if item.failure.details.get("promoted_nested_input") is True
            )
            current_targets = retry_targets
            run_config["password_retry_failures"] = password_retry_failures(summary)
            retry_count += 1
        if not is_scan:
            recent_passwords = engine.recent_passwords

    if is_scan:
        from sunpack.runtime.cli.commands.scan import command_result
        async with command_work_broker(ctx) as broker:
            return await broker.run("cli_output", "", command_result, args, ctx, target_paths, summary)

    password_store = build_password_store(
        passwords,
        use_builtin_passwords=not args.no_builtin_passwords,
        recent_passwords=recent_passwords,
        clipboard_passwords=clipboard_passwords,
        password_snapshot=initial_password_store.snapshot,
    )

    final_summary = RunSummary(
        target_results=tuple(latest_target_results.values()), scan_failures=tuple(scan_report.scan_failures),
    )
    failed_tasks = final_summary.failed_tasks
    result = CliCommandResult(
        command=operation,
        inputs={
            "paths": target_paths,
            "common_root": common_root,
            "json": args.json,
            "verbose": args.verbose,
            "config_overrides": config_overrides,
            "direct_file": bool(getattr(args, "direct_file", False)),
            "deep_detect": deep_detect,
        },
        summary={
            "success_count": final_summary.success_count,
            "failed_count": final_summary.failed_count,
            "scan_error_count": final_summary.scan_error_count,
            "scan_failures": [failure.to_dict() for failure in final_summary.scan_failures if is_filesystem_scan_failure(failure)],
            "input_error_count": final_summary.input_error_count,
            "processed_count": len(all_processed_keys),
            "partial_success_count": final_summary.partial_success_count,
            "recovered_outputs": all_recovered_outputs,
            "use_builtin_passwords": not args.no_builtin_passwords,
            "password_retry_count": retry_count,
            "cleanup_results": [
                {
                    "path": item.path,
                    "mode": item.mode,
                    "status": item.status,
                    "error_code": item.error_code,
                    "message": item.message,
                }
                for item in cleanup_results_by_path.values()
            ],
        },
        errors=failed_tasks,
        items=[password_summary_item(password_store, use_builtin_passwords=not args.no_builtin_passwords)],
        tasks=attempts,
    )
    if failed_tasks:
        return EXIT_TASK_FAILED, result
    return 0, result



def _extract_run_config(
    config: dict,
    password_store,
    *,
    verbose: bool = False,
    json_mode: bool = False,
) -> dict:
    run_config = dict(config)
    run_config["cli"] = {
        **(config.get("cli", {}) if isinstance(config.get("cli"), dict) else {}),
        "verbose": verbose,
        "json": json_mode,
    }
    run_config["extraction"] = {
        **(config.get("extraction", {}) if isinstance(config.get("extraction"), dict) else {}),
    }
    run_config["user_passwords"] = password_store.user_passwords
    run_config["clipboard_passwords"] = password_store.clipboard_passwords
    run_config["password_snapshot"] = password_store.snapshot
    return run_config


def has_password_failure(failures: list[FailureInfo]) -> bool:
    return any(failure.is_password_failure for failure in failures)


def _should_retry_password_failure(args, retry_targets: list[str]) -> bool:
    return bool(retry_targets) and not getattr(args, "json", False)


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
