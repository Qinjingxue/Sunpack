import json
import sys
from dataclasses import fields

from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.core.support.json_format import to_json_text


_JSON_RECORD_CHUNK = 128
_JSON_WRITE_CHARS = 64 * 1024


def _write_large_json_result(payload, output):
    chunks = []
    buffered_chars = 0

    def push(text):
        nonlocal buffered_chars
        chunks.append(text)
        buffered_chars += len(text)
        if buffered_chars >= _JSON_WRITE_CHARS:
            output.write("".join(chunks))
            chunks.clear()
            buffered_chars = 0

    push("{\n")
    fields_and_values = tuple(payload.items())
    for field_index, (name, value) in enumerate(fields_and_values):
        push("  " + json.dumps(name, ensure_ascii=False) + ": ")
        if type(value) is list and value:
            push("[\n")
            for offset in range(0, len(value), _JSON_RECORD_CHUNK):
                rendered = to_json_text(value[offset:offset + _JSON_RECORD_CHUNK])
                # Drop the chunk's outer brackets and indent its records as field values.
                push("  " + rendered[2:-2].replace("\n", "\n  "))
                push(",\n" if offset + _JSON_RECORD_CHUNK < len(value) else "\n")
            push("  ]")
        else:
            push(to_json_text(value).replace("\n", "\n  "))
        push(",\n" if field_index + 1 < len(fields_and_values) else "\n")
    push("}\n")
    if chunks:
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
            large_result = any(type(value) is list and len(value) >= 128 for value in payload.values())
            if large_result:
                _write_large_json_result(payload, self.stdout)
            else:
                print(to_json_text(payload), file=self.stdout, flush=True)
