from collections.abc import Awaitable, Callable
from typing import TextIO

from sunpack.core.i18n import I18nContext


class RecursionController:
    def __init__(self, mode: str, max_depth: int = 1, language: str = "en"):
        self.mode = mode # "fixed", "prompt", "infinite"
        self.max_depth = max_depth if mode == "fixed" else None
        self.i18n = I18nContext(language)

    def allows_children(self, depth: int) -> bool:
        if self.mode == "fixed":
            return depth < int(self.max_depth or 0)
        return True

    async def prompt_continue(
        self,
        depth: int,
        *,
        readline: Callable[[str], Awaitable[str]] | None,
        stdout: TextIO | None = None,
    ) -> bool:
        if readline is None:
            self._write(stdout, self.i18n.t("recursion.no_input"))
            return False
        while True:
            try:
                ans = (await readline(self.i18n.t("recursion.prompt", round=depth))).strip().lower()
            except EOFError:
                self._write(stdout, self.i18n.t("recursion.no_input"))
                return False
            except KeyboardInterrupt:
                self._write(stdout, self.i18n.t("recursion.cancelled"))
                return False
            if ans in {"y", "yes"}:
                return True
            if ans in {"n", "no", ""}:
                return False
            self._write(stdout, self.i18n.t("recursion.enter_yes_no"))

    @staticmethod
    def _write(stdout: TextIO | None, message: str) -> None:
        if stdout is not None:
            print(message, file=stdout, flush=True)
