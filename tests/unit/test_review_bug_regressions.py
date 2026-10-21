import asyncio
from datetime import datetime

from sunpack.pipeline.discovery.filesystem.filters.modules.mtime_range import (
    MtimeRangeScanFilter,
    utc_minute_ns,
)
from sunpack.pipeline.extraction.internal.workflow.single_archive_extractor import (
    SingleArchiveExtractor,
)


class _InlineBroker:
    async def run(self, _stage, _file_id, func, *args, **kwargs):
        kwargs.pop("request_id", None)
        kwargs.pop("cancellation", None)
        return func(*args, **kwargs)


class _FailingRunner:
    async def submit_attempt_asyncio(self, **_request):
        raise RuntimeError("worker disconnected")

    def failed_process_for_exception(self, exc, request):
        assert isinstance(exc, RuntimeError)
        assert request == {"archive": "sample.zip"}
        return "failed-process"


def test_async_worker_failure_reaches_failed_process_fallback():
    runner = _FailingRunner()
    extractor = SingleArchiveExtractor(
        password_store=None,
        password_resolver=None,
        metadata_scanner=None,
        retry_policy=None,
        sevenzip_runner=runner,
    )

    def state():
        sent = yield {"archive": "sample.zip"}
        return sent

    extractor._extract_state_machine = lambda *_args, **_kwargs: state()

    result = asyncio.run(
        extractor.extract_asyncio(
            _InlineBroker(),
            object(),
            "out",
            request_id="request",
            file_id="file",
            cancellation=None,
        )
    )

    assert result == "failed-process"


def test_time_filter_only_accepts_utc_minutes():
    import pytest
    from datetime import timezone
    expected = int(datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    configured = MtimeRangeScanFilter.from_config({"start_utc": "2024-01-01T00:00Z"})
    assert configured.value_range.gte == expected
    for value in ("20240101", "2024-01-01T00:00:00Z", "2024-01-01T00:00+08:00", expected):
        with pytest.raises(ValueError):
            utc_minute_ns(value)


def test_async_retry_resubmits_without_timed_backoff(monkeypatch):
    import sunpack.pipeline.extraction.internal.workflow.single_archive_extractor as module

    events = []

    class _RecordingBroker(_InlineBroker):
        async def run(self, stage, file_id, func, *args, **kwargs):
            events.append(("broker", stage))
            return await super().run(stage, file_id, func, *args, **kwargs)

    class _Runner:
        async def submit_attempt_asyncio(self, **request):
            events.append(("submit", request))
            return "done"

    async def unexpected_sleep(_delay):
        raise AssertionError("extraction retries are resubmitted, never delayed by a timer")

    monkeypatch.setattr(module.asyncio, "sleep", unexpected_sleep)
    extractor = SingleArchiveExtractor(
        password_store=None,
        password_resolver=None,
        metadata_scanner=None,
        retry_policy=None,
        sevenzip_runner=_Runner(),
    )

    def state():
        sent = yield {"archive": "sample.zip"}
        return sent

    extractor._extract_state_machine = lambda *_args, **_kwargs: state()

    result = asyncio.run(
        extractor.extract_asyncio(
            _RecordingBroker(),
            object(),
            "out",
            request_id="request",
            file_id="file",
            cancellation=None,
        )
    )

    assert result == "done"
    assert events == [
        ("broker", "extract_prepare"),
        ("submit", {"archive": "sample.zip"}),
        ("broker", "extract_continue"),
    ]
