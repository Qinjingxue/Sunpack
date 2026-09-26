import argparse
import asyncio
import contextvars
import inspect
import os
import sys

from sunpack.runtime.cli.cli_aliases import canonical_command
from sunpack.runtime.cli.cli_commands import command_map, discover_command_modules
from sunpack.runtime.cli.cli_constants import EXIT_OK, EXIT_RUNTIME, EXIT_USAGE
from sunpack.runtime.cli.cli_context import (
    CliContext,
)
from sunpack.core.config.cli_settings import DEFAULT_CLI_LANG, load_cli_language_from_config
from sunpack.runtime.cli.cli_parsers import (
    CliHelpFormatter,
    localize_help_action,
)
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.core.support.runtime_identity import runtime_id_available

CURRENT_CLI_LANG = DEFAULT_CLI_LANG
_PARSER_CACHE: dict[str, argparse.ArgumentParser] = {}
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


def configure_stdio_encoding():
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass


def preprocess_sys_argv(argv: list[str]) -> list[str]:
    cleaned = []
    for arg in argv:
        if isinstance(arg, str) and arg.endswith('"'):
            path = arg[:-1]
            if path.endswith("\\"):
                path = path[:-1]
            cleaned.append(path)
        else:
            cleaned.append(arg)
    return cleaned


def build_cli_parser(ctx: CliContext | None = None, command: str | None = None) -> argparse.ArgumentParser:
    ctx = ctx or CliContext(language=CURRENT_CLI_LANG)
    CliHelpFormatter.language = ctx.language
    modules = discover_command_modules(command)
    ctx.commands = command_map(modules)

    parser = _ContextArgumentParser(
        description=ctx.t("cli.description"),
        usage=ctx.t("cli.usage"),
        epilog=(
            f"{ctx.t('cli.examples')}\n"
            '  sunpack x C:\\Archives -r "*" -c r\n'
            "  sunpack i .\\fixtures --analysis -j\n"
            "  sunpack pw -a\n"
            "  sunpack w add C:\\Downloads -s -i"
        ),
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=_ContextArgumentParser)
    for module in modules:
        module.register(subparsers, ctx)
    return parser


def cached_cli_parser(ctx: CliContext, command: str | None = None) -> argparse.ArgumentParser:
    cache_key = f"{ctx.language}:{command or '*'}"
    parser = _PARSER_CACHE.get(cache_key)
    if parser is None:
        parser = build_cli_parser(ctx, command=command)
        _PARSER_CACHE[cache_key] = parser
    elif ctx.commands is None:
        ctx.commands = command_map()
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
    result = module.handle(args, ctx)
    return await result if inspect.isawaitable(result) else result


async def maybe_pause(args, ctx: CliContext, exit_code: int, result: CliCommandResult):
    successful_extract = (
        getattr(args, "command", "") == "extract"
        and exit_code == EXIT_OK
        and not result.errors
    )
    if getattr(args, "pause_on_exit", False) and not successful_extract:
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
    global CURRENT_CLI_LANG
    if argv is None:
        argv = sys.argv[1:]
    if stdout is None and stderr is None:
        configure_stdio_encoding()
    if argv and argv[0] in {"--persistent-server", "--persistent-shutdown"}:
        from sunpack.runtime.cli.persistent_process import run_server, submit_request

        return await run_server() if argv[0] == "--persistent-server" else submit_request([], shutdown=True)
    if argv and _should_submit_to_persistent_server(argv):
        from sunpack.runtime.cli.runtime_state import server_runtime_active

        if not server_runtime_active():
            from sunpack.runtime.cli.persistent_process import submit_request

            return submit_request(list(argv))

    argv = preprocess_sys_argv(argv)
    request_cwd = os.path.abspath(cwd or os.getcwd())
    CURRENT_CLI_LANG = load_cli_language_from_config(request_cwd)
    ctx = CliContext(
        language=CURRENT_CLI_LANG,
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
    process_mode = getattr(args, "process_mode", None)
    if process_mode is not None:
        from sunpack.runtime.cli.runtime_state import runtime_host

        host = runtime_host()
        if host is not None:
            await host.set_cli_process_mode_override(process_mode)
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
        reporter.emit_result(result)
        return EXIT_USAGE
    if args.json:
        args.pause_on_exit = False
    try:
        exit_code, result = await dispatch_command(args, ctx)
    except Exception as exc:
        reporter.error(ctx.t("cli.runtime_failure", error=exc))
        result = CliCommandResult(
            command=getattr(args, "command", ""),
            inputs={"argv": argv},
            summary={},
            errors=[ctx.t("cli.runtime_failure", error=exc)],
        )
        reporter.emit_result(result)
        await maybe_pause(args, ctx, EXIT_RUNTIME, result)
        return EXIT_RUNTIME

    reporter.emit_result(result)
    await maybe_pause(args, ctx, exit_code, result)
    return exit_code


def _should_submit_to_persistent_server(argv: list[str]) -> bool:
    if not runtime_id_available() or not argv or any(item in {"-h", "--help"} for item in argv):
        return False
    return True


if __name__ == "__main__":
    sys.exit(main())
