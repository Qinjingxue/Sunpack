from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace

from sunpack.cli.runtime_host import RuntimeHost
from sunpack.coordinator.archive_registry import ActiveArchiveRegistry


def test_archive_registry_detects_watch_owner_by_file_identity(tmp_path):
    archive = tmp_path / "archive.zip"
    alias = tmp_path / "alias.zip"
    archive.write_bytes(b"zip")
    os.link(archive, alias)
    registry = ActiveArchiveRegistry()

    assert registry.reserve("watch-job", "watch", [str(archive)]) is None
    conflict = registry.reserve("cli-job", "foreground", [str(alias)])

    assert conflict is not None
    assert conflict.origin == "watch"
    registry.release("watch-job")
    assert registry.reserve("cli-job", "foreground", [str(alias)]) is None


def test_extract_reports_watch_busy_without_starting_another_task(tmp_path):
    from sunpack.cli.commands import extract
    from sunpack.cli.runtime_state import set_runtime_host

    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"zip")
    registry = ActiveArchiveRegistry()
    assert registry.reserve("watch-job", "watch", [str(archive)]) is None
    set_runtime_host(SimpleNamespace(archive_registry=registry))
    try:
        code, result = asyncio.run(
            extract.handle(
                SimpleNamespace(paths=[str(archive)]),
                SimpleNamespace(
                    cwd=str(tmp_path),
                    reporter=None,
                    t=lambda key, **_kwargs: "该任务已由 watch 处理，请等待" if key == "cli.watch_busy" else key,
                ),
            )
        )
    finally:
        set_runtime_host(None)

    assert code != 0
    assert result.summary["status"] == "watch_busy"
    assert result.errors == ["该任务已由 watch 处理，请等待"]


def test_runtime_host_uses_cli_override_until_idle_expiry(monkeypatch):
    import sunpack.cli.runtime_host as runtime_host_module
    import sunpack.cli.persistent_runtime as persistent_runtime
    import sunpack.platform.windows.process_qos as process_qos

    events = []

    class FakeEngine:
        async def set_process_mode(self, *, mode):
            events.append(("worker_mode", mode))
            return {"applied": True}

    engine = FakeEngine()

    class FakeScheduler:
        async def set_external_activity(self, active):
            events.append(("activity", active))

    class FakeService:
        def __init__(self, *, pipeline_engine, config_applied_callback=None, **_kwargs):
            assert pipeline_engine is engine
            self.scheduler = FakeScheduler()
            self.config = {"runtime": {"process_mode": "background"}}
            self._config_applied_callback = config_applied_callback
            self._stop = asyncio.Event()

        async def run(self, *, initial_scan=False, initial_scan_roots=None):
            events.append(("watch_started", initial_scan, initial_scan_roots))
            await self._stop.wait()
            return 0

        async def wait_ready(self):
            while not any(event[0] == "watch_started" for event in events):
                await asyncio.sleep(0)

        def request_stop(self):
            self._stop.set()

        async def reload(self):
            self.config = {"runtime": {"process_mode": "normal"}}
            await self._config_applied_callback(self.config)
            return True

        async def add_roots(self, paths, *, output_dir=None, initial_scan=True):
            return {"roots_path": "roots.txt", "added": list(paths), "applied": True}

        async def remove_roots(self, paths):
            return {"roots_path": "roots.txt", "removed": list(paths), "applied": True}

    async def shared_engine(_config):
        return engine

    monkeypatch.setattr(
        runtime_host_module,
        "load_config",
        lambda: {"runtime": {"process_mode": "background"}},
    )
    monkeypatch.setattr(runtime_host_module, "shared_pipeline_engine", shared_engine)
    monkeypatch.setattr(runtime_host_module, "WatchService", FakeService)
    monkeypatch.setattr(persistent_runtime, "current_pipeline_engine", lambda: engine)
    monkeypatch.setattr(
        process_qos,
        "set_processing_mode",
        lambda *, mode: events.append(("host_mode", mode)),
    )

    async def scenario():
        host = RuntimeHost()
        await host.start_watch(tray_enabled=False)
        assert host.process_mode == "background"

        await host.set_cli_process_mode_override("high")
        assert host.process_mode == "high"

        assert (await host.reload_watch())["reloaded"] is True
        assert host._configured_process_mode == "normal"
        assert host.process_mode == "high"

        qos_before_foreground = [
            event for event in events if event[0] in {"worker_mode", "host_mode"}
        ]
        await host.foreground_started()
        await host.foreground_finished()
        assert [
            event for event in events if event[0] in {"worker_mode", "host_mode"}
        ] == qos_before_foreground
        assert [event for event in events if event[0] == "activity"] == [
            ("activity", True),
            ("activity", False),
        ]

        assert await host.expire_cli_process_mode_override() is True
        assert host.process_mode == "normal"
        assert await host.expire_cli_process_mode_override() is False

        await host.stop_watch()
        assert host.process_mode == "normal"

    asyncio.run(scenario())
    assert [event for event in events if event[0] == "worker_mode"] == [
        ("worker_mode", "background"),
        ("worker_mode", "high"),
        ("worker_mode", "normal"),
    ]
    assert [event for event in events if event[0] == "host_mode"] == [
        ("host_mode", "background"),
        ("host_mode", "high"),
        ("host_mode", "normal"),
    ]

def test_runtime_host_without_watch_scheduler_expires_cli_override_on_foreground_finish(monkeypatch):
    import sunpack.cli.persistent_runtime as persistent_runtime
    import sunpack.platform.windows.process_qos as process_qos

    modes = []

    class FakeEngine:
        async def set_process_mode(self, *, mode):
            modes.append(("worker", mode))
            return {"applied": True}

    engine = FakeEngine()
    monkeypatch.setattr(persistent_runtime, "current_pipeline_engine", lambda: engine)
    monkeypatch.setattr(
        process_qos,
        "set_processing_mode",
        lambda *, mode: modes.append(("host", mode)),
    )

    async def scenario():
        host = RuntimeHost()
        host._watch_service = SimpleNamespace(scheduler=None)
        host._watch_task = SimpleNamespace(done=lambda: False)
        await host._set_configured_process_mode({"runtime": {"process_mode": "normal"}})
        await host.set_cli_process_mode_override("high")
        assert host.process_mode == "high"

        await host.foreground_started()
        await host.foreground_finished()

        assert host._cli_process_mode_override is None
        assert host.process_mode == "normal"

    asyncio.run(scenario())
    assert modes == [
        ("worker", "high"),
        ("host", "high"),
        ("worker", "normal"),
        ("host", "normal"),
    ]


def test_runtime_host_brackets_overlapping_foreground_activity():
    activity = []

    class FakeScheduler:
        async def set_external_activity(self, active):
            activity.append(active)

    host = RuntimeHost()
    host._watch_service = SimpleNamespace(scheduler=FakeScheduler())
    host._watch_task = SimpleNamespace(done=lambda: False)

    async def scenario():
        await host.foreground_started()
        await host.foreground_started()
        assert activity == [True]

        await host.foreground_finished()
        assert activity == [True]

        await host.foreground_finished()
        assert activity == [True, False]

    asyncio.run(scenario())


def test_runtime_host_does_not_bypass_a_waiting_first_foreground():
    activity = []

    class FakeScheduler:
        def __init__(self):
            self.started = asyncio.Event()
            self.release = asyncio.Event()

        async def set_external_activity(self, active):
            activity.append(active)
            if active:
                self.started.set()
                await self.release.wait()

    async def scenario():
        scheduler = FakeScheduler()
        host = RuntimeHost()
        host._watch_service = SimpleNamespace(scheduler=scheduler)
        host._watch_task = SimpleNamespace(done=lambda: False)

        first = asyncio.create_task(host.foreground_started())
        await scheduler.started.wait()
        second = asyncio.create_task(host.foreground_started())
        await asyncio.sleep(0)
        assert not second.done()
        assert host._foreground_requests == 0

        scheduler.release.set()
        await asyncio.gather(first, second)
        assert host._foreground_requests == 2
        assert activity == [True]

        await host.foreground_finished()
        await host.foreground_finished()
        assert activity == [True, False]

    asyncio.run(scenario())


def test_runtime_host_creates_toast_only_for_continuous_watch(monkeypatch, tmp_path):
    import sunpack.cli.runtime_host as module
    import sunpack.platform.windows.toast_host as toast

    managers = []
    services = []

    class FakeManager:
        def __init__(self, **kwargs):
            managers.append(kwargs)

    class FakeService:
        def __init__(self, *, toast_manager_factory=None, **_kwargs):
            services.append(self)
            self.toast_factory = toast_manager_factory
            self.scheduler = None
            self.stop = asyncio.Event()
            self.ready = asyncio.Event()

        async def run(self, *, once=False, initial_scan=False, initial_scan_roots=None):
            if once:
                assert self.toast_factory is None
                return 0
            self.toast_factory({"watch": {"toast_update_interval_ms": 123}}, str(tmp_path), None)
            self.ready.set()
            await self.stop.wait()
            return 0

        async def wait_ready(self):
            await self.ready.wait()

        def request_stop(self):
            self.stop.set()

    async def engine(_config):
        return object()

    monkeypatch.setattr(module, "load_config", lambda: {})
    monkeypatch.setattr(module, "shared_pipeline_engine", engine)
    monkeypatch.setattr(module, "WatchService", FakeService)
    monkeypatch.setattr(toast, "ToastManager", FakeManager)

    async def run():
        host = RuntimeHost()
        await host.foreground_started()
        await host.foreground_finished()
        assert managers == []
        assert await host.run_watch_once() == 0
        assert managers == []
        await host.start_watch(tray_enabled=False)
        assert len(managers) == 1
        await host.foreground_started()
        await host.foreground_finished()
        await host.start_watch(tray_enabled=False)
        assert len(managers) == 1
        await host.close()

    asyncio.run(run())
    assert managers[0]["update_interval_ms"] == 123
