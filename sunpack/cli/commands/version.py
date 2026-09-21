from sunpack.cli.cli_types import CliCommandResult
from sunpack.support.process_executable import current_process_executable


COMMAND = "version"
ORDER = 70


def register(subparsers, ctx):
    subparsers.add_parser(
        COMMAND,
        help="Print the installed SunPack version.",
        usage="sunpack version",
    )


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
