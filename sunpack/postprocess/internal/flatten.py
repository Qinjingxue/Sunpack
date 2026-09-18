from sunpack_native import flatten_single_branch_directories as _native_flatten_single_branch_directories
from sunpack_native import recover_pending_flatten_transactions as _native_recover_flatten_transactions
from sunpack.i18n import I18nContext
from sunpack.support.resources import writable_data_dir


def flatten_state_dir() -> str:
    """Recovery metadata lives in SunPack's own data directory, never in output roots."""
    return str(writable_data_dir() / "flatten")


def recover_pending_flatten_transactions() -> int:
    """Finish flatten transactions an earlier process left behind."""
    return int(_native_recover_flatten_transactions(flatten_state_dir()))


class DirectoryFlattener:
    def __init__(self, language: str = "en", *, stdout=None):
        self.i18n = I18nContext(language)
        self.stdout = stdout if stdout is not None else sys.stdout

    def flatten_dirs(self, base: str, *, announce: bool = True):
        if announce:
            print(self.i18n.t("cleanup.flatten"), file=self.stdout, flush=True)
        result = _native_flatten_single_branch_directories(str(base), flatten_state_dir())
        if isinstance(result, dict):
            for error in result.get("errors") or []:
                print(self.i18n.t("cleanup.flatten_failed", error=str(error)), file=self.stdout, flush=True)
        return result
import sys
