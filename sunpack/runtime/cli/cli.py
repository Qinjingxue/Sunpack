import argparse
import asyncio
import contextvars
import inspect
import os
import sys
from contextlib import asynccontextmanager
from types import ModuleType

from sunpack.runtime.cli.cli_aliases import canonical_command
from sunpack.runtime.cli.cli_commands import command_map, discover_command_modules
from sunpack.runtime.cli.cli_constants import EXIT_OK, EXIT_RUNTIME, EXIT_USAGE
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.core.config.cli_settings import load_cli_language_from_config
from sunpack.runtime.cli.cli_parsers import localize_parser
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.cli.persistent_process import (
    SERVER_ARG,
    SHUTDOWN_ARG,
    configure_stdio_encoding,
    should_submit_to_persistent_server as _should_submit_to_persistent_server,
)
from sunpack.core.support.resources import resource_path_resolution_scope

_PARSER_CACHE: dict[tuple[str, str | None], tuple[argparse.ArgumentParser, dict[str, ModuleType]]] = {}
_PARSER_STDOUT: contextvars.ContextVar = contextvars.ContextVar("sunpack_parser_stdout", default=None)
_PARSER_STDERR: contextvars.ContextVar = contextvars.ContextVar("sunpack_parser_stderr", default=None)


class _ContextArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def _print_message(self, message, file=None):
        if file is sys.stderr:
            file = _PARSER_STDERR.get() or file
        elif file is None or file is sys.stdout:
            file = _PARSER_STDOUT.get() or file
        super()._print_message(message, file)


def preprocess_sys_argv(argv: list[str]) -> list[str]:
    # sys.argv and persistent requests already contain parsed argument values.
    # Generic quote/backslash repair corrupts legitimate passwords and other
    # non-path values, so preserve the transport payload exactly.
    return list(argv)


def build_cli_parser(ctx: CliContext | None = None, command: str | None = None) -> argparse.ArgumentParser:
    ctx = ctx or CliContext()
    modules = discover_command_modules(command)
    ctx.commands = command_map(modules)

    parser = _ContextArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=_ContextArgumentParser)
    for module in modules:
        module.register(subparsers, ctx)
    localize_parser(parser, ctx)
    return parser


def cached_cli_parser(ctx: CliContext, command: str | None = None) -> argparse.ArgumentParser:
    cache_key = ctx.language, command
    cached = _PARSER_CACHE.get(cache_key)
    if cached is None:
        parser = build_cli_parser(ctx, command=command)
        assert ctx.commands is not None
        _PARSER_CACHE[cache_key] = parser, ctx.commands
        return parser
    parser, commands = cached
    if ctx.commands is None:
        ctx.commands = commands
    return parser


async def dispatch_command(args, ctx: CliContext) -> tuple[int, CliCommandResult]:
    if ctx.commands is None:
        ctx.commands = command_map()
    module = ctx.commands.get(getattr(args, "command", None))
    if module is None:
        command = getattr(args, "command", "")
        return EXIT_USAGE, CliCommandResult(
            command="",
            inputs={},
            summary={},
            errors=[ctx.t("cli.unknown_command", command=command)],
        )
    if inspect.iscoroutinefunction(module.handle):
        return await module.handle(args, ctx)
    async with command_work_broker(ctx) as broker:
        result = await broker.run("cli", getattr(args, "command", ""), module.handle, args, ctx)
    return await result if inspect.isawaitable(result) else result


@asynccontextmanager
async def command_work_broker(ctx: CliContext):
    """Reuse pipeline admission; own a broker only for standalone CLI work."""
    from sunpack.runtime.cli.persistent_runtime import (
        current_pipeline_engine, shared_command_work_broker, server_runtime_active,
    )
    from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker

    engine = current_pipeline_engine()
    broker = ctx.work_broker or (engine.work_broker if engine is not None else None)
    if broker is None and server_runtime_active():
        broker = shared_command_work_broker()
    owned = broker is None
    if owned:
        broker = AsyncWorkBroker()
    previous, ctx.work_broker = ctx.work_broker, broker
    try:
        yield broker
    finally:
        ctx.work_broker = previous
        if owned:
            await broker.close(graceful=True)


async def maybe_pause(args, ctx: CliContext, exit_code: int, result: CliCommandResult):
    successful_extract = (
        getattr(args, "command", "") == "extract"
        and exit_code == EXIT_OK
        and not result.errors
    )
    if getattr(args, "pause_on_exit", False) and not successful_extract and exit_code != 130:
        await ctx.readline(ctx.t("cli.pause_prompt"))


def main(argv=None):
    return asyncio.run(async_main(argv))


async def async_main(
    argv=None,
    *,
    cwd: str | None = None,
    stdin=None,
    stdout=None,
    stderr=None,
    input_reader=None,
):
    if argv is None:
        argv = sys.argv[1:]
    if stdout is None and stderr is None:
        configure_stdio_encoding()
    if argv and argv[0] in {SERVER_ARG, SHUTDOWN_ARG}:
        from sunpack.runtime.cli.persistent_process import run_server, submit_request

        return await run_server() if argv[0] == SERVER_ARG else submit_request([], shutdown=True)
    if _should_submit_to_persistent_server(argv):
        from sunpack.runtime.cli.persistent_process import submit_request

        return submit_request(list(argv))

    with resource_path_resolution_scope(
        enabled=bool(argv) and canonical_command(argv[0]) in {"extract", "scan"},
    ):
        argv = preprocess_sys_argv(argv)
        request_cwd = os.path.abspath(cwd or os.getcwd())
        ctx = CliContext(
            language=load_cli_language_from_config(request_cwd),
            cwd=request_cwd,
            stdin=stdin if stdin is not None else sys.stdin,
            stdout=stdout if stdout is not None else sys.stdout,
            stderr=stderr if stderr is not None else sys.stderr,
            input_reader=input_reader,
        )
        # Extract and scan are latency-sensitive paths. Other commands retain full
        # discovery because some command registrations are imported by companion
        # command modules today.
        requested_command = canonical_command(argv[0]) if argv else None
        selected_command = requested_command if requested_command in {"extract", "scan"} else None
        parser = cached_cli_parser(ctx, command=selected_command)
        stdout_token = _PARSER_STDOUT.set(ctx.stdout)
        stderr_token = _PARSER_STDERR.set(ctx.stderr)
        try:
            if not argv:
                parser.print_help()
                return EXIT_OK
            try:
                args = parser.parse_args(argv)
            except SystemExit as exc:
                return int(exc.code)
        finally:
            _PARSER_STDOUT.reset(stdout_token)
            _PARSER_STDERR.reset(stderr_token)

        args.json = bool(getattr(args, "json", False) or "-j" in argv or "--json" in argv)
        args.quiet = bool(getattr(args, "quiet", False) or "-q" in argv or "--quiet" in argv)
        args.verbose = bool(getattr(args, "verbose", False) or "-v" in argv or "--verbose" in argv)
        args.pause_on_exit = bool(getattr(args, "pause_on_exit", False) or "--pause" in argv)
        if args.command in {"extract", "scan"}:
            from sunpack.runtime.cli.runtime_state import runtime_host

            host = runtime_host()
            if host is not None:
                await host.set_cli_process_mode_override("high")
        reporter = CliReporter(
            json_mode=args.json,
            quiet=args.quiet,
            verbose=args.verbose,
            stdout=ctx.stdout,
            stderr=ctx.stderr,
        )
        ctx.reporter = reporter
        if args.json and getattr(args, "prompt_passwords", False):
            result = CliCommandResult(
                command=getattr(args, "command", ""),
                inputs={"argv": argv},
                summary={},
                errors=[ctx.t("cli.json_password_prompt_unavailable")],
            )
            async with command_work_broker(ctx) as broker:
                await broker.run("cli_output", "", reporter.emit_result, result)
            return EXIT_USAGE
        if args.json:
            args.pause_on_exit = False
        async with command_work_broker(ctx) as broker:
            try:
                exit_code, result = await dispatch_command(args, ctx)
            except asyncio.CancelledError:
                from sunpack.pipeline.coordinator.async_work import CURRENT_CANCELLATION
                from sunpack.runtime.cli.cli_runtime import interrupted_result

                cancellation = CURRENT_CANCELLATION.get()
                if cancellation is None or not cancellation.cancelled:
                    raise
                exit_code, result = interrupted_result(ctx, getattr(args, "command", ""), {"argv": argv})
            except Exception as exc:
                await broker.run("cli_output", "", reporter.error, ctx.t("cli.runtime_failure", error=exc))
                result = CliCommandResult(
                    command=getattr(args, "command", ""),
                    inputs={"argv": argv},
                    summary={},
                    errors=[ctx.t("cli.runtime_failure", error=exc)],
                )
                await broker.run("cli_output", "", reporter.emit_result, result)
                await maybe_pause(args, ctx, EXIT_RUNTIME, result)
                return EXIT_RUNTIME

            await broker.run("cli_output", "", reporter.emit_result, result)
            await maybe_pause(args, ctx, exit_code, result)
            return exit_code


if __name__ == "__main__":
    sys.exit(main())
