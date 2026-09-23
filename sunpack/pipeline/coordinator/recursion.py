from sunpack.core.i18n import I18nContext


class RecursionController:
    def __init__(self, mode: str, max_rounds: int = 1, language: str = "en"):
        self.mode = mode # "fixed", "prompt", "infinite"
        self.max_rounds = max_rounds if mode == "fixed" else None
        self.i18n = I18nContext(language)

    def should_continue(self, round_index: int, new_roots_found: bool) -> bool:
        if not new_roots_found:
            return False
            
        if self.mode == "fixed":
            return round_index < self.max_rounds
            
        if self.mode == "prompt":
            return True
                    
        return True # infinite

    def prompt_continue(self, round_index: int) -> bool:
        while True:
            try:
                ans = input(self.i18n.t("recursion.prompt", round=round_index)).strip().lower()
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
