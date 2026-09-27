import asyncio
from datetime import datetime

from sunpack.pipeline.discovery.filesystem.filters.modules.mtime_range import (
    MtimeRangeScanFilter,
    _mtime_or_none,
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


def test_compact_yyyymmdd_is_parsed_as_a_date_before_numeric_timestamp():
    expected = int(datetime.strptime("20240101", "%Y%m%d").timestamp() * 1_000_000_000)

    assert _mtime_or_none("20240101") == expected

    configured = MtimeRangeScanFilter.from_config({"since": "20240101"})
    assert configured.value_range.gte == expected


def test_async_retry_backoff_runs_outside_broker_slot(monkeypatch):
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

    async def fake_sleep(delay):
        events.append(("sleep", delay))

    def blocking_sleep(_delay):
        raise AssertionError("retry backoff must not block a broker thread")

    monkeypatch.setattr(module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(module.time, "sleep", blocking_sleep)
    extractor = SingleArchiveExtractor(
        password_store=None,
        password_resolver=None,
        metadata_scanner=None,
        retry_policy=None,
        sevenzip_runner=_Runner(),
    )

    def state():
        sent = yield {"archive": "sample.zip", "retry_delay_seconds": 0.5}
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
        ("sleep", 0.5),
        ("submit", {"archive": "sample.zip"}),
        ("broker", "extract_continue"),
    ]
