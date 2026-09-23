from sunpack_native import flatten_single_branch_directories as _native_flatten_single_branch_directories
from sunpack.core.i18n import I18nContext


class DirectoryFlattener:
    def __init__(self, language: str = "en", *, stdout=None):
        self.i18n = I18nContext(language)
        self.stdout = stdout if stdout is not None else sys.stdout

    def flatten_dirs(self, base: str, *, announce: bool = True):
        if announce:
            print(self.i18n.t("cleanup.flatten"), file=self.stdout, flush=True)
        result = _native_flatten_single_branch_directories(str(base))
        if isinstance(result, dict):
            for error in result.get("errors") or []:
                print(self.i18n.t("cleanup.flatten_failed", error=str(error)), file=self.stdout, flush=True)
        return result
import sys
