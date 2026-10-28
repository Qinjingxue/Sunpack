from __future__ import annotations

import asyncio

from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileModifiedEvent, FileMovedEvent

from sunpack.runtime.watch.config_observer import ConfigFileObserver


class FakeObserver:
    def __init__(self):
        self.handler = None
        self.path = None
        self.recursive = None
        self.started = False
        self.stopped = False
        self.join_timeout = None

    def schedule(self, handler, path, *, recursive):
        self.handler = handler
        self.path = path
        self.recursive = recursive

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def join(self, timeout=None):
        self.join_timeout = timeout


def test_config_observer_watches_program_directory_non_recursively(tmp_path):
    async def scenario():
        observer = ConfigFileObserver(
            tmp_path, ("sunpack_config.json",), lambda: None,
            observer_factory=FakeObserver, loop=asyncio.get_running_loop(),
        )
        observer.start()
        observer.stop()
        return observer
    observer = asyncio.run(scenario())

    assert observer._observer.path == str(tmp_path.resolve())
    assert observer._observer.recursive is False
    assert observer._observer.started is True
    assert observer._observer.stopped is True
    assert observer._observer.join_timeout is None


def test_config_observer_filters_files_and_debounces_event_burst(tmp_path):
    async def scenario():
        emitted = asyncio.Event(); calls = []
        observer = ConfigFileObserver(
            tmp_path,
            ("sunpack_config.json", "sunpack_advanced_config.json", "sunpack_watch_roots.txt"),
            lambda: (calls.append("reload"), emitted.set()), debounce_seconds=0.02,
            observer_factory=FakeObserver, loop=asyncio.get_running_loop(),
        )
        observer.start(); handler = observer._observer.handler
        handler.on_modified(FileModifiedEvent(str(tmp_path / "unrelated.txt")))
        handler.on_created(FileCreatedEvent(str(tmp_path / "SUNPACK_CONFIG.JSON")))
        handler.on_modified(FileModifiedEvent(str(tmp_path / "sunpack_advanced_config.json")))
        handler.on_deleted(FileDeletedEvent(str(tmp_path / "sunpack_watch_roots.txt")))
        await asyncio.wait_for(emitted.wait(), 1.0)
        observer.stop()
        return calls
    assert asyncio.run(scenario()) == ["reload"]


def test_config_observer_handles_atomic_replace_destination(tmp_path):
    async def scenario():
        emitted = asyncio.Event()
        observer = ConfigFileObserver(
            tmp_path, ("sunpack_config.json",), emitted.set, debounce_seconds=0.0,
            observer_factory=FakeObserver, loop=asyncio.get_running_loop(),
        )
        observer.start()
        observer._observer.handler.on_moved(FileMovedEvent(
            str(tmp_path / ".sunpack_config.json.tmp"), str(tmp_path / "sunpack_config.json")
        ))
        await asyncio.wait_for(emitted.wait(), 1.0)
        observer.stop()
    asyncio.run(scenario())


def test_config_observer_cancels_pending_reload_when_stopped(tmp_path):
    async def scenario():
        emitted = asyncio.Event()
        observer = ConfigFileObserver(
            tmp_path, ("sunpack_config.json",), emitted.set, debounce_seconds=0.1,
            observer_factory=FakeObserver, loop=asyncio.get_running_loop(),
        )
        observer.start(); observer.notify_path_changed(str(tmp_path / "sunpack_config.json"))
        await asyncio.sleep(0)
        observer.stop(); await asyncio.sleep(0.2)
        return emitted.is_set()
    assert not asyncio.run(scenario())


def test_real_watchdog_observer_detects_config_change(tmp_path):
    async def scenario():
        emitted = asyncio.Event()
        observer = ConfigFileObserver(
            tmp_path, ("sunpack_config.json",), emitted.set, debounce_seconds=0.02,
            loop=asyncio.get_running_loop(),
        )
        observer.start()
        try:
            (tmp_path / "sunpack_config.json").write_text("{}", encoding="utf-8")
            await asyncio.wait_for(emitted.wait(), 3.0)
        finally:
            observer.stop()
    asyncio.run(scenario())


def test_config_directory_handle_is_tracked_without_blocking_promotion(tmp_path):
    from sunpack.core.support.resource_lifecycle import promotion_barrier
    from sunpack_native import (
        NativeArchiveSession,
        NativeConfigChanges,
        native_resource_snapshot,
        native_wait_for_resources,
        release_reader_resources_under_roots,
    )

    archive = tmp_path / "example.zip"
    archive.write_bytes(b"archive")
    listener = NativeConfigChanges(str(tmp_path))
    try:
        resources = [dict(item) for item in native_resource_snapshot([str(archive)])]
        assert any(
            item["kind"] == "config_directory" and item["promotion_blocking"] is False
            for item in resources
        )
        assert list(native_wait_for_resources([str(archive)], 0.0)) == []

        # A passive listener can be opened while an archive's promotion gate
        # is held; neither the existing nor the new listener blocks it.
        with promotion_barrier((archive,), timeout=0, quiesce=False):
            second = NativeConfigChanges(str(tmp_path))
            try:
                resources = [dict(item) for item in native_resource_snapshot([str(archive)])]
                assert sum(item["kind"] == "config_directory" for item in resources) == 2
            finally:
                second.close()

        # Ordinary file handles still participate in the promotion barrier.
        session = NativeArchiveSession(str(archive))
        try:
            blockers = [dict(item) for item in native_wait_for_resources([str(archive)], 0.0)]
            assert any(
                item["kind"] == "reader_file" and item["promotion_blocking"] is True
                for item in blockers
            )
        finally:
            session.close()
            release_reader_resources_under_roots([str(archive)])
    finally:
        listener.close()
    assert list(native_resource_snapshot([str(archive)])) == []
