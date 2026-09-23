from sunpack.runtime.cli.cli_constants import EXIT_USAGE
from sunpack.runtime.cli.cli_parsers import CliHelpFormatter, build_json_parser, build_password_parser, localize_help_action
from sunpack.runtime.cli.cli_runtime import build_password_summary, collect_clipboard_passwords, collect_cli_passwords, password_summary_item
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.cli.persistent_runtime import load_request_config

COMMAND = "passwords"
ORDER = 40


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_json_parser(ctx), build_password_parser(ctx)],
        help=ctx.t("cli.passwords.help"),
        usage="sunpack passwords [options]",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)


def handle(args, ctx):
    reporter = ctx.reporter
    try:
        passwords = collect_cli_passwords(
            args,
            prompt_text=ctx.t("cli.password_prompt"),
            input_prompt=ctx.t("cli.password_input_prompt"),
        )
        config = load_request_config(ctx.cwd)
        clipboard_passwords = collect_clipboard_passwords(config)
        password_summary = build_password_summary(
            passwords,
            use_builtin_passwords=not args.no_builtin_passwords,
            clipboard_passwords=clipboard_passwords,
        )
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[ctx.t("cli.operation_failed", error=exc)])

    if not args.json:
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
