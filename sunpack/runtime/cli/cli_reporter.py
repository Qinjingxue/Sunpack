import json
import sys
from dataclasses import fields

from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.core.support.json_format import json_safe


_JSON_WRITE_CHARS = 64 * 1024


def _write_json_result(payload, output):
    chunks = []
    buffered_chars = 0
    encoder = json.JSONEncoder(ensure_ascii=False, indent=2)
    for token in encoder.iterencode(json_safe(payload)):
        token_size = len(token)
        if token_size >= _JSON_WRITE_CHARS:
            if chunks:
                output.write("".join(chunks))
                chunks.clear()
                buffered_chars = 0
            output.write(token)
        else:
            chunks.append(token)
            buffered_chars += token_size
            if buffered_chars >= _JSON_WRITE_CHARS:
                output.write("".join(chunks))
                chunks.clear()
                buffered_chars = 0
    chunks.append("\n")
    output.write("".join(chunks))
    output.flush()


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
            payload = {field.name: getattr(result, field.name) for field in fields(result)}
            _write_json_result(payload, self.stdout)
