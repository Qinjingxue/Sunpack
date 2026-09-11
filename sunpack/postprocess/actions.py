import os
import sys
from typing import Any, Dict, Iterable

from sunpack.contracts.results import ArchiveCleanupResult
from sunpack.postprocess.internal.cleanup import ArchiveCleanup
from sunpack.postprocess.internal.flatten import DirectoryFlattener
from sunpack.i18n import I18nContext


class PostProcessActions:
    def __init__(
        self,
        config: Dict[str, Any],
        language: str | None = None,
        *,
        stdout=None,
    ):
        self.config = config
        cli_config = config.get("cli") if isinstance(config.get("cli"), dict) else {}
        self.i18n = I18nContext(language if language is not None else cli_config.get("language"))
        self.language = self.i18n.language
        self.cleanup_mode = config.get("post_extract", {}).get("archive_cleanup_mode", "recycle")
        if self.cleanup_mode not in {"keep", "recycle", "delete"}:
            raise ValueError("archive_cleanup_mode must be normalized before PostProcessActions starts")
        self.stdout = stdout if stdout is not None else sys.stdout
        self.cleanup = ArchiveCleanup(mode=self.cleanup_mode, language=self.language, stdout=self.stdout)
        self.flattener = DirectoryFlattener(language=self.language, stdout=self.stdout)

    def apply(
        self,
        cleanup_archives: bool = True,
        flatten_outputs: bool | None = None,
        archives_to_clean: Iterable[Iterable[str]] | None = None,
        flatten_targets: Iterable[str] | None = None,
        previous_cleanup: dict[str, ArchiveCleanupResult] | None = None,
    ) -> list[ArchiveCleanupResult]:
        results: list[ArchiveCleanupResult] = []
        if cleanup_archives:
            results = self.cleanup.cleanup_success_archives(
                [list(parts) for parts in (archives_to_clean or [])],
                previous_cleanup,
            )

        if flatten_outputs is None:
            flatten_outputs = self.config.get("post_extract", {}).get("flatten_single_directory", True)
        if flatten_outputs:
            for index, target in enumerate(self._consume_flatten_targets(flatten_targets)):
                self.flattener.flatten_dirs(target, announce=index == 0)
        return results

    def t(self, key: str, **params) -> str:
        return self.i18n.t(key, **params)

    def _consume_flatten_targets(self, flatten_targets: Iterable[str] | None) -> list[str]:
        unique: dict[str, str] = {}
        for target in flatten_targets or ():
            value = str(target)
            unique.setdefault(os.path.normcase(os.path.abspath(value)), value)
        return sorted(unique.values(), key=lambda item: item.count(os.sep))
