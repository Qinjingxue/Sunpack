from collections.abc import Iterable
from sunpack_native import DIRECTORY_ERROR_REPORT_LIMIT

from sunpack.core.contracts.failures import FailureInfo, FailureKind
from sunpack.core.i18n import I18nContext
from sunpack.core.support.path_keys import absolute_path_key


def directory_error_count(error: tuple[str, str, str]) -> int:
    return int(error[2]) if error[0] in {"omitted", "report_omitted", "output_scan"} else 1


def directory_error_key(error: tuple[str, str, str]) -> tuple[str, str, str]:
    operation, path, detail = error
    return operation, absolute_path_key(path) if path else "", detail


class DirectoryErrorReport:
    """Bound pending raw diagnostics before their single coordinator handoff."""

    def __init__(self):
        self._errors: dict[tuple[str, str, str], tuple[str, str, str]] = {}
        self._omitted = 0

    def extend(self, errors: Iterable[tuple[str, str, str]]) -> None:
        for error in errors:
            if error[0] == "report_omitted":
                self._omitted += directory_error_count(error)
                continue
            key = directory_error_key(error)
            if key in self._errors:
                continue
            if len(self._errors) < DIRECTORY_ERROR_REPORT_LIMIT:
                self._errors[key] = error
            else:
                self._omitted += directory_error_count(error)

    def take(self) -> list[tuple[str, str, str]]:
        errors = list(self._errors.values())
        if self._omitted:
            errors.append(("report_omitted", "", str(self._omitted)))
        self._errors.clear()
        self._omitted = 0
        return errors

    def __bool__(self) -> bool:
        return bool(self._errors or self._omitted)


def filesystem_scan_failure(error: tuple[str, str, str], language: str) -> FailureInfo:
    operation, path, detail = error
    key = f"filesystem_scan.{operation}"
    params = {"path": path, "error": detail}
    return FailureInfo(
        kind=FailureKind.FILESYSTEM_ERROR,
        stage="filesystem_scan",
        message=I18nContext(language).t(key, **params),
        message_key=key,
        message_params=params,
        details={
            "path": path,
            "operation": operation,
            "count": directory_error_count(error),
        },
    )


def is_filesystem_scan_failure(failure: FailureInfo) -> bool:
    return failure.kind == FailureKind.FILESYSTEM_ERROR and failure.stage == "filesystem_scan"


def filesystem_scan_error_count(failures: Iterable[FailureInfo]) -> int:
    return sum(failure.details.get("count", 1) for failure in failures if is_filesystem_scan_failure(failure))
