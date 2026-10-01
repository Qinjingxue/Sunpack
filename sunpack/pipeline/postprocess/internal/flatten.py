from sunpack_native import flatten_single_branch_directories as _native_flatten_single_branch_directories
from sunpack.core.i18n import I18nContext
from sunpack.core.contracts.results import DirectoryFlattenResult


class DirectoryFlattener:
    def __init__(self, language: str = "en", *, stdout=None):
        self.i18n = I18nContext(language)
        self.stdout = stdout if stdout is not None else sys.stdout

    def flatten_dirs(self, base: str, *, announce: bool = True):
        if announce:
            print(self.i18n.t("cleanup.flatten"), file=self.stdout, flush=True)
        result = _native_flatten_single_branch_directories(str(base))
        errors = tuple(str(error) for error in result["errors"])
        for error in errors:
            print(self.i18n.t("cleanup.flatten_failed", error=error), file=self.stdout, flush=True)
        return DirectoryFlattenResult(
            path=str(base),
            output_dir=str(result["output_dir"]),
            source_dir=str(result["source_dir"]),
            moved=int(result["moved"]),
            removed_dirs=int(result["removed_dirs"]),
            errors=errors,
        )
import sys
