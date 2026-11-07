from __future__ import annotations

import asyncio
import gc
import weakref

import pytest

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


@pytest.mark.parametrize("started", [False, True])
def test_stopped_config_observer_releases_owners_without_cyclic_gc(tmp_path, started):
    # Event-delivery tests miss callback retention and owner/handler cycles.
    # One idle listener checks both lifetimes without timing or RSS sampling.
    class Owner:
        def changed(self):
            pass

    async def scenario():
        owner = Owner()
        observer = ConfigFileObserver(
            tmp_path, ("config.json",), owner.changed,
            observer_factory=FakeObserver, loop=asyncio.get_running_loop(),
        )
        if started:
            observer.start()
        # Stopping before the loop dispatches a queued event must cancel that
        # handle too; otherwise the ready queue still owns the retired listener.
        observer.notify_path_changed(str(tmp_path / "config.json"))
        owner_ref = weakref.ref(owner)
        del owner
        observer.stop()
        assert owner_ref() is None
        handler = observer._handler
        observer_ref = weakref.ref(observer)
        del observer
        assert observer_ref() is None
        # A saved handler must also be harmless after its listener has gone.
        handler.dispatch(FileModifiedEvent(str(tmp_path / "config.json")))

    enabled = gc.isenabled()
    gc.disable()
    try:
        asyncio.run(scenario())
    finally:
        if enabled:
            gc.enable()


def test_config_observer_failed_start_stops_already_started_emitters(tmp_path, monkeypatch):
    # A dispatcher that never starts can still own earlier native listeners.
    # Normal shutdown tests cannot exercise this partial-start resource leak.
    from sunpack.runtime.watch.config_observer import _ConfigEmitter
    from sunpack_native import native_resource_snapshot

    directories = [tmp_path / name for name in ("first", "second")]
    for directory in directories:
        directory.mkdir()
    original = _ConfigEmitter.on_thread_start
    starts = 0

    def start(emitter):
        nonlocal starts
        starts += 1
        if starts == 2:
            raise OSError("second config listener failed")
        original(emitter)

    monkeypatch.setattr(_ConfigEmitter, "on_thread_start", start)

    async def scenario():
        observer = ConfigFileObserver(
            directories[0], ("config.json",), lambda: None,
            additional_files=[(directories[1], ("config.json",), lambda: None)],
            loop=asyncio.get_running_loop(),
        )
        try:
            with pytest.raises(OSError, match="second config listener failed"):
                observer.start()
            assert not observer._observer.emitters
            assert not list(native_resource_snapshot([str(tmp_path)]))
        finally:
            observer._observer.stop()
            observer.stop()

    asyncio.run(scenario())


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


def test_config_observer_filters_files_and_coalesces_event_burst(tmp_path, monkeypatch):
    async def scenario():
        emitted = asyncio.Event(); calls = []
        loop = asyncio.get_running_loop()
        schedule = loop.call_soon_threadsafe
        queued = []

        def record_schedule(callback, *args, **kwargs):
            queued.append(callback.__name__)
            return schedule(callback, *args, **kwargs)

        monkeypatch.setattr(loop, "call_soon_threadsafe", record_schedule)
        observer = ConfigFileObserver(
            tmp_path,
            ("sunpack_config.json", "sunpack_advanced_config.json", "sunpack_watch_roots.txt"),
            lambda: (calls.append("reload"), emitted.set()),
            observer_factory=FakeObserver, loop=asyncio.get_running_loop(),
        )
        observer.start(); handler = observer._observer.handler
        handler.dispatch(FileModifiedEvent(str(tmp_path / "unrelated.txt")))
        handler.dispatch(FileCreatedEvent(str(tmp_path / "SUNPACK_CONFIG.JSON")))
        for _ in range(256):
            handler.dispatch(FileModifiedEvent(str(tmp_path / "sunpack_advanced_config.json")))
        handler.dispatch(FileDeletedEvent(str(tmp_path / "sunpack_watch_roots.txt")))
        # Coalescing reloads alone still permits an event-sized ready queue.
        assert queued == ["_emit"]
        await asyncio.wait_for(emitted.wait(), 1.0)
        observer.stop()
        return calls
    assert asyncio.run(scenario()) == ["reload"]


def test_shared_callbacks_dispatch_immediately_and_reentrant_events_are_not_lost(tmp_path, monkeypatch):
    # A shared observer must deliver every source without a timer, including
    # events raised inside a callback, while retaining only one pending wake.
    async def scenario():
        loop = asyncio.get_running_loop()
        def unexpected_timer(*args, **kwargs):
            raise AssertionError("configuration dispatch must not use timers")
        monkeypatch.setattr(loop, "call_later", unexpected_timer)
        calls = []
        def password_changed():
            calls.append("password")
        def config_changed():
            calls.append("config")
            if calls.count("config") == 1:
                for _ in range(256):
                    observer.notify_path_changed(str(tmp_path / "config.json"))
        observer = ConfigFileObserver(
            tmp_path, ("passwords.json",), password_changed,
            additional_files=[(tmp_path, ("config.json",), config_changed)],
            observer_factory=FakeObserver, loop=loop,
        )
        observer.start()
        try:
            for _ in range(256):
                observer.notify_path_changed(str(tmp_path / "config.json"))
                observer.notify_path_changed(str(tmp_path / "passwords.json"))
            await asyncio.sleep(0)
            assert sorted(calls) == ["config", "password"]
            await asyncio.sleep(0)
            assert calls.count("config") == 2 and calls.count("password") == 1
        finally:
            observer.stop()
    asyncio.run(scenario())


def test_config_observer_handles_atomic_replace_destination(tmp_path):
    async def scenario():
        emitted = asyncio.Event()
        observer = ConfigFileObserver(
            tmp_path, ("sunpack_config.json",), emitted.set,
            observer_factory=FakeObserver, loop=asyncio.get_running_loop(),
        )
        observer.start()
        observer._observer.handler.dispatch(FileMovedEvent(
            str(tmp_path / ".sunpack_config.json.tmp"), str(tmp_path / "sunpack_config.json")
        ))
        await asyncio.wait_for(emitted.wait(), 1.0)
        observer.stop()
    asyncio.run(scenario())


def test_config_observer_cancels_pending_reload_when_stopped(tmp_path):
    async def scenario():
        emitted = asyncio.Event()
        observer = ConfigFileObserver(
            tmp_path, ("sunpack_config.json",), emitted.set,
            observer_factory=FakeObserver, loop=asyncio.get_running_loop(),
        )
        observer.start(); observer.notify_path_changed(str(tmp_path / "sunpack_config.json"))
        observer.stop(); await asyncio.sleep(0)
        return emitted.is_set()
    assert not asyncio.run(scenario())


def test_real_watchdog_observer_detects_config_change(tmp_path):
    async def scenario():
        emitted = asyncio.Event()
        observer = ConfigFileObserver(
            tmp_path, ("sunpack_config.json",), emitted.set,
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
