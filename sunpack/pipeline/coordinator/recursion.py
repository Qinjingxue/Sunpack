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

    def prompt_continue(self, depth: int) -> bool:
        while True:
            try:
                ans = input(self.i18n.t("recursion.prompt", round=depth)).strip().lower()
            except EOFError:
                print(self.i18n.t("recursion.no_input"), flush=True)
                return False
            except KeyboardInterrupt:
                print(self.i18n.t("recursion.cancelled"), flush=True)
                return False
            if ans in {"y", "yes"}:
                return True
            if ans in {"n", "no", ""}:
                return False
            print(self.i18n.t("recursion.enter_yes_no"), flush=True)
