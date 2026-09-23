import time

from sunpack.pipeline.extraction.internal.workflow.errors import should_retry_extract_failure
from sunpack.core.i18n import I18nContext


class ExtractRetryPolicy:
    def __init__(self, max_retries: int = 3):
        self.max_retries = max(1, int(max_retries or 1))

    def can_retry(self, run_result, err_text: str, retry_count: int, archive: str, is_split_archive: bool) -> bool:
        if not run_result or retry_count + 1 >= self.max_retries:
            return False
        return should_retry_extract_failure(
            run_result,
            err_text,
            archive=archive,
            is_split_archive=is_split_archive,
        )

    def backoff(self, retry_count: int) -> None:
        time.sleep(min(2.0, 0.5 * (2 ** max(0, retry_count - 1))))

    def append_retry_count(self, error_msg: str, retry_count: int, i18n: I18nContext | None = None) -> str:
        if retry_count <= 0:
            return error_msg
        if i18n is None:
            i18n = I18nContext()
        return f"{error_msg}{i18n.t('retry.suffix', count=retry_count)}"
