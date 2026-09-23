from dataclasses import dataclass, field
import inspect
import os
import sys
from types import ModuleType
from typing import Any, Callable, TextIO

from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.core.config.cli_settings import DEFAULT_CLI_LANG
from sunpack.core.i18n import I18nContext


@dataclass
class CliContext:
    language: str = DEFAULT_CLI_LANG
    reporter: CliReporter | None = None
    commands: dict[str, ModuleType] | None = None
    cwd: str = field(default_factory=os.getcwd)
    stdin: TextIO = field(default_factory=lambda: sys.stdin)
    stdout: TextIO = field(default_factory=lambda: sys.stdout)
    stderr: TextIO = field(default_factory=lambda: sys.stderr)
    input_reader: Callable[[str], Any] | None = None
    i18n: I18nContext = field(init=False)

    def __post_init__(self) -> None:
        self.i18n = I18nContext(self.language)
        self.language = self.i18n.language

    def t(self, key: str, **params) -> str:
        return self.i18n.t(key, **params)

    async def readline(self, prompt: str = "") -> str:
        if self.input_reader is not None:
            value = self.input_reader(prompt)
            if inspect.isawaitable(value):
                value = await value
            return str(value)
        return input(prompt)
