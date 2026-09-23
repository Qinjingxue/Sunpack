import sys
from dataclasses import asdict

from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.core.support.json_format import to_json_text


class CliReporter:
    def __init__(
        self,
        json_mode: bool = False,
        quiet: bool = False,
        verbose: bool = False,
        *,
        stdout=None,
        stderr=None,
    ):
        self.json_mode = json_mode
        self.quiet = quiet
        self.verbose = verbose
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr
        self.logs: list[str] = []

    def info(self, message: str):
        if not self.json_mode and not self.quiet:
            print(message, file=self.stdout, flush=True)

    def detail(self, message: str):
        if not self.json_mode and self.verbose and not self.quiet:
            print(message, file=self.stdout, flush=True)

    def error(self, message: str):
        if not self.json_mode:
            print(message, file=self.stderr, flush=True)

    def emit_result(self, result: CliCommandResult):
        if self.json_mode:
            print(to_json_text(asdict(result)), file=self.stdout, flush=True)
