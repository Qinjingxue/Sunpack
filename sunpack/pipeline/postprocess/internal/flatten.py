from sunpack_native import flatten_single_branch_directories as _native_flatten_single_branch_directories
from sunpack.core.i18n import I18nContext
from sunpack.core.contracts.results import DirectoryFlattenResult


class DirectoryFlattener:
    def __init__(self, language: str = "en", *, stdout=None, quiet: bool = False):
        self.i18n = I18nContext(language)
        self.stdout = stdout if stdout is not None else sys.stdout
        self.quiet = quiet

    def flatten_dirs(self, base: str, *, announce: bool = True, work_path: str | None = None):
        if announce and not self.quiet:
            print(self.i18n.t("cleanup.flatten"), file=self.stdout, flush=True)
        result = (_native_flatten_single_branch_directories(str(base), work_path=work_path)
                  if work_path is not None else _native_flatten_single_branch_directories(str(base)))
        errors = tuple(str(error) for error in result["errors"])
        return DirectoryFlattenResult(
            path=str(base),
            output_dir=str(result["output_dir"]),
            source_dir=str(result["source_dir"]),
            moved=int(result["moved"]),
            removed_dirs=int(result["removed_dirs"]),
            errors=errors,
        )
import sys
