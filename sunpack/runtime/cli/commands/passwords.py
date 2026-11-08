from sunpack.runtime.cli.cli_aliases import COMMAND_ALIASES
from sunpack.runtime.cli.cli_constants import EXIT_USAGE
from sunpack.runtime.cli.cli_parsers import build_json_parser, build_password_parser
from sunpack.runtime.cli.cli_runtime import (
    build_password_summary,
    collect_clipboard_passwords,
    collect_cli_passwords_async,
    password_summary_item,
)
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.cli.persistent_runtime import load_request_config

COMMAND = "passwords"
ORDER = 40


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        aliases=COMMAND_ALIASES[COMMAND],
        parents=[build_json_parser(ctx), build_password_parser(ctx)],
        help=ctx.t("cli.passwords.help"),
        usage="sunpack passwords [options]",
    )
    parser.set_defaults(command=COMMAND)


async def handle(args, ctx):
    from sunpack.runtime.cli.cli import command_work_broker

    def summarize(passwords):
        config = load_request_config(ctx.cwd)
        return build_password_summary(
            passwords,
            use_builtin_passwords=not args.no_builtin_passwords,
            clipboard_passwords=collect_clipboard_passwords(config),
        )

    try:
        async with command_work_broker(ctx) as broker:
            passwords = await collect_cli_passwords_async(args, ctx)
            password_summary = await broker.run("cli", COMMAND, summarize, passwords)
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[ctx.t("cli.operation_failed", error=exc)])

    if not args.json:
        reporter = ctx.reporter
        reporter.info(ctx.t("cli.passwords.summary"))
        reporter.info(ctx.t("cli.passwords.user_input", value=password_summary.user_passwords or []))
        reporter.info(ctx.t("cli.passwords.recent", value=password_summary.recent_passwords or []))
        reporter.info(ctx.t("cli.passwords.clipboard", value=password_summary.clipboard_passwords or []))
        reporter.info(ctx.t("cli.passwords.builtin", value=password_summary.builtin_passwords or []))
        reporter.info(ctx.t("cli.passwords.final_order", value=password_summary.combined_passwords or []))

    return 0, CliCommandResult(
        command=COMMAND,
        inputs={
            "json": args.json,
            "use_builtin_passwords": not args.no_builtin_passwords,
        },
        summary={
            "user_password_count": len(password_summary.user_passwords),
            "recent_password_count": len(password_summary.recent_passwords),
            "clipboard_password_count": len(password_summary.clipboard_passwords),
            "builtin_password_count": len(password_summary.builtin_passwords),
            "combined_password_count": len(password_summary.combined_passwords),
        },
        items=[password_summary_item(password_summary)],
    )
