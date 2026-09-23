from sunpack.runtime.cli.cli_parsers import CliHelpFormatter, localize_help_action
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.core.support.process_executable import current_process_executable


COMMAND = "version"
ORDER = 70


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        help=ctx.t("cli.version.help"),
        usage="sunpack version",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)


def handle(args, ctx):
    version_file = current_process_executable().with_name("VERSION.txt")
    version = next(
        line.split("=", 1)[1]
        for line in version_file.read_text(encoding="utf-8").splitlines()
        if line.startswith("version=")
    )
    ctx.reporter.info(version)
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={},
        summary={"version": version},
    )
