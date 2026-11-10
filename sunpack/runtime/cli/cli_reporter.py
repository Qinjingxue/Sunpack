import sys
from dataclasses import fields
from sunpack_native import stream_json

from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.core.support.json_format import json_safe


def _write_json_result(payload, output):
    stream_json(json_safe(payload), output, pretty=True)
    output.write("\n")
    output.flush()


class CliReporter:
    def __init__(
        self,
        json_mode: bool = False,
        verbose: bool = False,
        *,
        stdout=None,
        stderr=None,
    ):
        self.json_mode = json_mode
        self.verbose = verbose
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr

    def info(self, message: str):
        if not self.json_mode:
            print(message, file=self.stdout, flush=True)

    def detail(self, message: str):
        if not self.json_mode and self.verbose:
            print(message, file=self.stdout, flush=True)

    def error(self, message: str):
        if not self.json_mode:
            print(message, file=self.stderr, flush=True)

    def emit_result(self, result: CliCommandResult):
        if self.json_mode:
            payload = {field.name: getattr(result, field.name) for field in fields(result)}
            _write_json_result(payload, self.stdout)
