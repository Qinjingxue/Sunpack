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


def test_runtime_host_owns_watch_and_switches_host_and_worker_qos(monkeypatch):
    import sunpack.cli.runtime_host as runtime_host_module
    import sunpack.cli.persistent_runtime as persistent_runtime
    import sunpack.platform.windows.process_qos as process_qos

    events = []

    class FakeEngine:
        async def set_process_mode(self, *, background):
            events.append(("worker_qos", background))

    engine = FakeEngine()

    class FakeService:
        def __init__(self, *, pipeline_engine, **_kwargs):
            assert pipeline_engine is engine
            self.scheduler = None
            self._stop = asyncio.Event()
            self.reloads = 0

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
            self.reloads += 1
            return True

        async def add_roots(self, paths, *, initial_scan=True):
            return {"roots_path": "roots.txt", "added": list(paths), "applied": True}

        async def remove_roots(self, paths):
            return {"roots_path": "roots.txt", "removed": list(paths), "applied": True}

    async def shared_engine(_config):
        return engine

    monkeypatch.setattr(runtime_host_module, "load_config", lambda: {})
    monkeypatch.setattr(runtime_host_module, "shared_pipeline_engine", shared_engine)
    monkeypatch.setattr(runtime_host_module, "WatchService", FakeService)
    monkeypatch.setattr(persistent_runtime, "current_pipeline_engine", lambda: engine)
    monkeypatch.setattr(process_qos, "set_processing_mode", lambda *, background: events.append(("host_qos", background)))

    async def scenario():
        state_changes = []
        host = RuntimeHost(state_changed=lambda: state_changes.append(host.watch_enabled))
        started = await host.start_watch(tray_enabled=False, initial_scan=True)
        assert started["started"] is True
        assert host.watch_enabled is True
        assert (await host.reload_watch())["reloaded"] is True
        assert (await host.add_watch_roots(["C:/second"], initial_scan=True))["added"] == ["C:/second"]
        assert (await host.remove_watch_roots(["C:/second"]))["removed"] == ["C:/second"]
        await host._set_process_mode(background=True)
        await host.foreground_started()
        await host.foreground_finished()
        stopped = await host.stop_watch()
        assert stopped["stopped"] is True
        assert host.watch_enabled is False
        await host.close()
        assert True in state_changes
        assert state_changes[-1] is False

    asyncio.run(scenario())
    assert ("worker_qos", True) in events
    assert ("host_qos", True) in events
    assert ("worker_qos", False) in events
    assert ("host_qos", False) in events


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
        # Foreground requests coexist without creating another notification owner.
        await host.foreground_started()
        await host.foreground_finished()
        await host.start_watch(tray_enabled=False)
        assert len(managers) == 1
        await host.close()

    asyncio.run(run())
    assert managers[0]["update_interval_ms"] == 123
