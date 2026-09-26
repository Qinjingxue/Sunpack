from sunpack.runtime.cli.cli_aliases import COMMAND_ALIASES
from sunpack.runtime.cli.cli_constants import EXIT_USAGE
from sunpack.runtime.cli.cli_parsers import CliHelpFormatter, build_config_output_parser, localize_help_action
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.config_validation import validate_config_payload
from sunpack.runtime.cli.persistent_runtime import load_request_config_payload
from sunpack.core.support.json_format import to_json_text

COMMAND = "config"
ORDER = 50


def register(subparsers, ctx):
    common_parser = build_config_output_parser(ctx)
    config_parser = subparsers.add_parser(
        COMMAND,
        aliases=COMMAND_ALIASES[COMMAND],
        parents=[common_parser],
        help=ctx.t("cli.config.help"),
        usage="sunpack config [options] <show|validate>",
        formatter_class=CliHelpFormatter,
    )
    config_parser.set_defaults(command=COMMAND)
    localize_help_action(config_parser, ctx)
    config_subparsers = config_parser.add_subparsers(dest="config_action", required=True)
    config_subparsers.add_parser("show", parents=[common_parser], help=ctx.t("cli.config.show_help"), formatter_class=CliHelpFormatter)
    config_subparsers.add_parser(
        "validate",
        parents=[common_parser],
        help=ctx.t("cli.config.validate_help"),
        formatter_class=CliHelpFormatter,
    )


def handle(args, ctx):
    reporter = ctx.reporter
    try:
        config_path, payload = load_request_config_payload(ctx.cwd)
        item = payload
        if args.config_action == "show":
            if not args.json and not args.quiet:
                print(to_json_text(payload), file=ctx.stdout, flush=True)
        elif args.config_action == "validate":
            item = validate_config_payload(payload)
            if not item["ok"]:
                localized_errors = [ctx.t("cli.config.validation_error", error=error) for error in item["errors"]]
                for error in localized_errors:
                    reporter.error(error)
                return EXIT_USAGE, CliCommandResult(
                    command=COMMAND,
                    inputs={"action": args.config_action},
                    summary={"config_path": str(config_path), "changed": False, "valid": False},
                    errors=localized_errors,
                    items=[item],
                )
            reporter.info(ctx.t("cli.config.valid_config"))
        else:
            return EXIT_USAGE, CliCommandResult(
                command=COMMAND,
                inputs={},
                summary={},
                errors=[ctx.t("cli.config.unknown_config_command", action=args.config_action)],
            )
    except Exception as exc:
        return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[ctx.t("cli.operation_failed", error=exc)])

    return 0, CliCommandResult(
        command=COMMAND,
        inputs={
            "action": args.config_action,
        },
        summary={"config_path": str(config_path), "changed": False},
        items=[item],
    )
