from sunpack.pipeline.extraction.internal.workflow.errors import should_retry_extract_failure
from sunpack.core.i18n import I18nContext


class ExtractRetryPolicy:
    """Retries are decided by evidence, not by an attempt-count ceiling."""

    def __init__(self, max_retries: int | None = None):
        # Keep legacy constructor compatibility. No attempt limit is enforced.
        pass

    def can_retry(self, run_result, err_text: str, retry_count: int, archive: str, is_split_archive: bool) -> bool:
        return bool(run_result) and should_retry_extract_failure(
            run_result, err_text, archive=archive, is_split_archive=is_split_archive,
        )

    @staticmethod
    def retry_delay_seconds(retry_count: int) -> float:
        # Backoff prevents resource exhaustion and rapid process respawn; it
        # never turns elapsed time or an attempt count into a failure.
        return min(30.0, 0.1 * (2 ** min(max(0, retry_count - 1), 9)))

    def append_retry_count(self, error_msg: str, retry_count: int, i18n: I18nContext | None = None) -> str:
        if retry_count <= 0:
            return error_msg
        if i18n is None:
            i18n = I18nContext()
        return f"{error_msg}{i18n.t('retry.suffix', count=retry_count)}"
