from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

import sunpack.filesystem.watcher.service as service_module
import sunpack.coordinator.watch_runtime as watch_runtime
import sunpack.cli.commands.watch as watch_command
from sunpack.filesystem.watcher.service import (
    CONTROL_SCHEDULER_WAKEUP,
    CONTROL_STOP,
    WatchService,
)
from tests.helpers.fake_pipeline_engine import FakePipelineEngine


class FakeRunner:
    pass


_TEST_LOOP = asyncio.new_event_loop()


@pytest.fixture(autouse=True)
def _stub_watch_broker(monkeypatch):
    monkeypatch.setattr(service_module, "_acquire_watch_broker", lambda: None)
    monkeypatch.setattr(service_module, "_release_watch_broker", lambda: None)


def _await(awaitable):
    return _TEST_LOOP.run_until_complete(awaitable)


def test_watch_service_forces_complete_content_policy_for_pipeline_engine(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "extraction": {"content_requirement": "allow_partial"},
            "watch": {
                "state_dir": str(tmp_path / "state"),
                "roots": [str(tmp_path)],
                "tray_enabled": False,
                "clipboard_monitor_enabled": False,
            },
        },
    )
    monkeypatch.setattr(service_module, "read_watch_root_entries", lambda: ([str(tmp_path)], {}))

    class Engine:
        async def __aenter__(self):
            return self

        async def aclose(self, graceful=True):
            pass

    class Scheduler:
        def __init__(self, *_args, **_kwargs):
            pass

        async def start(self):
            pass

        async def stop(self):
            pass

    monkeypatch.setattr(service_module, "WatchScheduler", Scheduler)

    def engine_factory(config):
        captured["config"] = config
        return Engine()

    service = WatchService(engine_factory=engine_factory)
    _await(service._start_scheduler())

    assert captured["config"]["extraction"]["content_requirement"] == "complete"
    assert service.config["extraction"]["content_requirement"] == "allow_partial"


@pytest.mark.parametrize("enabled", [True, False])
def test_watch_service_attaches_and_releases_toast_with_watch_lifecycle(tmp_path, monkeypatch, enabled):
    config = {
        "extraction": {"content_requirement": "complete"},
        "watch": {
            "state_dir": str(tmp_path / "state"),
            "roots": [str(tmp_path)],
            "tray_enabled": False,
            "clipboard_monitor_enabled": False,
            "toast_enabled": enabled,
        },
    }
    monkeypatch.setattr(service_module, "load_config", lambda: config)
    monkeypatch.setattr(service_module, "read_watch_root_entries", lambda: ([str(tmp_path)], {}))
    captured = {}

    class Engine:
        async def __aenter__(self):
            return self

        async def aclose(self, graceful=True):
            pass

    class Scheduler:
        def __init__(self, *_args, **kwargs):
            captured["sink"] = kwargs.get("notification_sink")

        async def start(self):
            pass

        async def stop(self):
            pass

    class Host:
        def __init__(self):
            self.started = False
            self.stopped = False
            self.cleared = 0

        def start(self):
            self.started = True

        def stop(self):
            self.stopped = True

        def publish(self, _snapshot):
            pass

        def clear(self):
            self.cleared += 1

    host = Host()
    monkeypatch.setattr(service_module, "WatchScheduler", Scheduler)
    service = WatchService(
        engine_factory=lambda _config: Engine(),
        toast_manager_factory=lambda _config, _state_dir, _log: host,
    )

    _await(service._start_scheduler())
    assert host.started is enabled
    assert captured["sink"] is service.toast_coordinator
    assert (captured["sink"] is not None) is enabled

    _await(service._stop_scheduler())
    assert host.cleared == int(enabled)
    assert host.stopped is False
    service._stop_toast_host()
    assert host.stopped is enabled


def test_scheduler_restart_keeps_unchanged_toast_manager(tmp_path, monkeypatch):
    config = {
        "watch": {
            "state_dir": str(tmp_path / "state"),
            "tray_enabled": False,
            "toast_enabled": True,
            "toast_update_interval_ms": 50,
        }
    }
    monkeypatch.setattr(service_module, "load_config", lambda: config)
    monkeypatch.setattr(service_module, "read_watch_root_entries", lambda: ([str(tmp_path)], {}))

    class Scheduler:
        def __init__(self, *_args, **_kwargs):
            pass

        async def start(self):
            pass

        async def stop(self):
            pass

    class Host:
        def __init__(self):
            self.starts = 0
            self.stops = 0

        def start(self):
            self.starts += 1

        def stop(self):
            self.stops += 1

        def publish(self, _snapshot):
            pass

        def clear(self):
            pass

    hosts = []

    def make_host(*_args):
        host = Host()
        hosts.append(host)
        return host

    monkeypatch.setattr(service_module, "WatchScheduler", Scheduler)
    service = WatchService(
        engine_factory=lambda _config: FakePipelineEngine(FakeRunner),
        toast_manager_factory=make_host,
    )

    _await(service._start_scheduler())
    _await(service._start_scheduler())

    assert len(hosts) == 1
    assert hosts[0].starts == 1
    assert hosts[0].stops == 0


def test_watch_runtime_does_not_change_process_cwd(tmp_path, monkeypatch):
    caller = tmp_path / "caller"
    caller.mkdir()
    observed = {}
    monkeypatch.chdir(caller)

    class FakeHost:
        async def run_watch_once(self, *, initial_scan=False):
            observed["run"] = (__import__("os").getcwd(), initial_scan)
            return 7

    from sunpack.cli import runtime_state

    monkeypatch.setattr(runtime_state, "require_runtime_host", lambda: FakeHost())

    assert _await(watch_runtime.run_watch_service(tray_enabled=False, once=True)) == 7
    assert observed == {"run": (str(caller), False)}
    assert __import__("os").getcwd() == str(caller)


def test_watch_runtime_delegates_start_to_runtime_host(monkeypatch):
    captured = {}

    class FakeHost:
        async def start_watch(self, *, tray_enabled=True, initial_scan=False):
            captured.update(tray_enabled=tray_enabled, initial_scan=initial_scan)

    from sunpack.cli import runtime_state

    monkeypatch.setattr(runtime_state, "require_runtime_host", lambda: FakeHost())

    assert _await(watch_runtime.run_watch_service(tray_enabled=False, initial_scan=True)) == 0
    assert captured == {"tray_enabled": False, "initial_scan": True}


def test_watch_add_reports_start_request_without_creating_watch_process(tmp_path, monkeypatch):
    monkeypatch.setattr(watch_command, "add_watch_roots", lambda paths, outputs=None: (tmp_path / "roots.txt", paths))

    class FakeHost:
        watch_enabled = False

        async def start_watch(self, *, initial_scan_roots=None):
            assert initial_scan_roots == ["C:/downloads"]
            return {"started": True, "running": True}

    from sunpack.cli import runtime_state

    monkeypatch.setattr(runtime_state, "require_runtime_host", lambda: FakeHost())

    code, result = _await(watch_command._handle_add(
        SimpleNamespace(paths=["C:/downloads"], start=True, initial_scan=True),
        SimpleNamespace(cwd=str(tmp_path)),
    ))

    assert code == 0
    assert result.summary["start_requested"] is True
    assert result.summary["start"] == {"started": True, "running": True}


def test_watch_add_applies_directly_to_running_service(tmp_path, monkeypatch):
    requested = ["C:/downloads/new"]
    calls = []

    class FakeHost:
        watch_enabled = True

        async def add_watch_roots(self, paths, *, outputs=None, initial_scan=True):
            calls.append((list(paths), initial_scan))
            return {
                "roots_path": str(tmp_path / "roots.txt"),
                "added": requested,
                "applied": True,
                "running": True,
            }

    from sunpack.cli import runtime_state

    monkeypatch.setattr(runtime_state, "require_runtime_host", lambda: FakeHost())
    monkeypatch.setattr(
        watch_command,
        "add_watch_roots",
        lambda _paths: (_ for _ in ()).throw(AssertionError("CLI must not persist before direct apply")),
    )

    code, result = _await(
        watch_command._handle_add(
            SimpleNamespace(paths=requested, start=True, initial_scan=True),
            SimpleNamespace(cwd=str(tmp_path)),
        )
    )

    assert code == 0
    assert calls == [(requested, True)]
    assert result.summary["added"] == requested
    assert result.summary["apply"]["applied"] is True
    assert result.summary["start"] is None


def test_watch_config_observer_wakes_runtime_host_queue():
    service = WatchService(pipeline_engine=FakePipelineEngine(FakeRunner))

    async def scenario():
        service._loop = asyncio.get_running_loop()
        service._control_queue = asyncio.Queue()
        service._wake_config_reload()
        return await service._control_queue.get()

    assert asyncio.run(scenario()) == service_module.CONTROL_RELOAD


def test_running_watch_service_adds_roots_and_scans_only_new_roots(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    roots_path.write_text(str(first_root), encoding="utf-8")
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(tmp_path / ".sunpack_watch"), "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    starts = []

    async def start_scheduler(*, initial_scan=False, initial_scan_roots=None):
        starts.append((initial_scan, initial_scan_roots, list(service.roots)))

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)

    result = _await(service.add_roots([str(second_root), str(second_root)], initial_scan=True))
    observer_reload_applied = _await(service.reload())

    normalized_second = str(second_root.resolve())
    assert result == {
        "roots_path": str(roots_path),
        "added": [normalized_second],
        "applied": True,
    }
    assert roots_path.read_text(encoding="utf-8").splitlines() == [
        str(first_root.resolve()),
        normalized_second,
    ]
    assert starts == [(False, [normalized_second], [str(first_root.resolve()), normalized_second])]
    assert observer_reload_applied is False


def test_running_watch_service_duplicate_add_is_a_noop(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    root = tmp_path / "watched"
    root.mkdir()
    roots_path.write_text(str(root), encoding="utf-8")
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(tmp_path / ".sunpack_watch"), "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    starts = []
    monkeypatch.setattr(
        service_module,
        "_write_watch_roots_unlocked",
        lambda *_args: (_ for _ in ()).throw(AssertionError("duplicate add must not rewrite roots")),
    )

    async def start_scheduler(**kwargs):
        starts.append(kwargs)

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)

    result = _await(service.add_roots([str(root)], initial_scan=True))

    assert result["added"] == []
    assert result["applied"] is False
    assert starts == []


def test_running_watch_service_removes_root_directly(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    roots_path.write_text(f"{first_root}\n{second_root}\n", encoding="utf-8")
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(tmp_path / ".sunpack_watch"), "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    starts = []

    async def start_scheduler(*, initial_scan=False, initial_scan_roots=None):
        starts.append((initial_scan_roots, list(service.roots)))

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)

    result = _await(service.remove_roots([str(second_root)]))

    assert result["removed"] == [str(second_root.resolve())]
    assert result["applied"] is True
    assert starts == [(None, [str(first_root.resolve())])]
    assert roots_path.read_text(encoding="utf-8").splitlines() == [str(first_root.resolve())]


def test_watch_service_releases_named_mutex_after_exit(tmp_path, monkeypatch):
    lifecycle = []
    monkeypatch.setattr(service_module, "_acquire_watch_broker", lambda: lifecycle.append("broker_acquire"))
    monkeypatch.setattr(service_module, "_release_watch_broker", lambda: lifecycle.append("broker_release"))
    state_dir = tmp_path / ".sunpack_watch"
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(state_dir),
                "roots": [],
                "tray_enabled": False,
                "clipboard_monitor_enabled": False,
            }
        },
    )

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))

    original_stop_scheduler = service._stop_scheduler

    async def stop_scheduler():
        lifecycle.append("scheduler_stop")
        await original_stop_scheduler()

    monkeypatch.setattr(service, "_stop_scheduler", stop_scheduler)

    assert _await(service.run(once=True)) == 0
    assert lifecycle == ["broker_acquire", "scheduler_stop", "scheduler_stop", "broker_release"]
    assert not (state_dir / "watch.lock").exists()


def test_watch_service_cleans_up_when_broker_cannot_start(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(state_dir),
                "roots": [],
                "tray_enabled": False,
                "clipboard_monitor_enabled": False,
            }
        },
    )
    released = []
    monkeypatch.setattr(
        service_module,
        "_acquire_watch_broker",
        lambda: (_ for _ in ()).throw(RuntimeError("broker unavailable")),
    )
    monkeypatch.setattr(service_module, "_release_watch_broker", lambda: released.append(True))
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))

    with pytest.raises(RuntimeError, match="broker unavailable"):
        _await(service.run(once=True))

    assert released == []
    assert service._broker_acquired is False
    assert not (state_dir / "watch.lock").exists()


def test_request_stop_wakes_service_blocked_without_scheduler(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(state_dir),
                "roots": [],
                "tray_enabled": False,
            }
        },
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    waiting = threading.Event()

    async def no_scheduler(*, initial_scan=False, initial_scan_roots=None):
        service.scheduler = None
        waiting.set()

    monkeypatch.setattr(service, "_start_scheduler", no_scheduler)
    monkeypatch.setattr(service, "_stop_scheduler", no_scheduler)
    monkeypatch.setattr(service, "_start_tray", lambda: None)
    monkeypatch.setattr(service, "_stop_tray", lambda: None)
    results = []
    thread = threading.Thread(target=lambda: results.append(asyncio.run(service.run())))
    thread.start()
    assert waiting.wait(timeout=1.0)

    service.request_stop()
    thread.join(timeout=1.0)

    assert not thread.is_alive()
    assert results == [0]


def test_watch_service_config_observer_targets_program_files(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    state_dir = tmp_path / ".sunpack_watch"
    captured = {}

    class FakeConfigObserver:
        def __init__(self, directory, filenames, callback, *, debounce_seconds, loop):
            captured.update(
                directory=directory,
                filenames=set(filenames),
                callback=callback,
                debounce_seconds=debounce_seconds,
                loop=loop,
            )

        def start(self):
            captured["started"] = True

        def stop(self):
            captured["stopped"] = True

    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "ConfigFileObserver", FakeConfigObserver)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    service._loop = _TEST_LOOP
    service._control_queue = asyncio.Queue()

    service._start_config_observer()
    captured["callback"]()
    _await(asyncio.sleep(0))
    service._stop_config_observer()

    assert captured["directory"] == tmp_path.resolve()
    assert captured["filenames"] == {
        "sunpack_config.json",
        "sunpack_advanced_config.json",
        "sunpack_watch_roots.txt",
    }
    assert captured["debounce_seconds"] == 0.5
    assert captured["started"] is True
    assert captured["stopped"] is True
    assert service._control_queue.get_nowait() == service_module.CONTROL_RELOAD


def test_watch_service_invalid_config_reload_preserves_running_service(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    initial_config = {"watch": {"state_dir": str(state_dir), "tray_enabled": False}}
    monkeypatch.setattr(service_module, "load_config", lambda: initial_config)
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    original_config = service.config
    original_service_config = service.service_config
    original_log = service.log
    scheduler_restarts = []
    written = []
    service.log.write = lambda event, **payload: written.append((event, payload))
    monkeypatch.setattr(service_module, "load_config", lambda: (_ for _ in ()).throw(ValueError("invalid json")))
    async def start_scheduler(*, initial_scan=False, initial_scan_roots=None):
        scheduler_restarts.append(True)

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)

    _await(service._reload_config())

    assert service.config is original_config
    assert service.service_config is original_service_config
    assert service.log is original_log
    assert scheduler_restarts == []
    assert written == [
        (
            "config_reload_failed",
            {"error": "invalid json", "error_type": "ValueError", "phase": "load"},
        )
    ]


def test_watch_service_reload_applies_new_roots_without_restarting_tray(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    roots_path.write_text(str(first_root), encoding="utf-8")
    state_dir = tmp_path / ".sunpack_watch"
    configs = iter(
        [
            {"watch": {"state_dir": str(state_dir), "tray_enabled": True}, "revision": 1},
            {"watch": {"state_dir": str(state_dir), "tray_enabled": True}, "revision": 2},
        ]
    )
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "load_config", lambda: next(configs))
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    starts = []
    tray_events = []

    async def start_scheduler(*, initial_scan=False, initial_scan_roots=None):
        starts.append((service.config["revision"], service.roots))

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)
    tray = SimpleNamespace(refresh=lambda: tray_events.append("refreshed"))
    service.tray_factory = lambda _service: None
    service.tray = tray
    roots_path.write_text(str(second_root), encoding="utf-8")

    _await(service._reload_config())

    assert service.config["revision"] == 2
    assert service.roots == [str(second_root.resolve())]
    assert starts == [(2, [str(second_root.resolve())])]
    assert tray_events == []
    assert service.tray is tray


def test_watch_service_tray_only_reload_does_not_restart_scheduler(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    root = tmp_path / "watched"
    root.mkdir()
    roots_path.write_text(str(root), encoding="utf-8")
    state_dir = tmp_path / ".sunpack_watch"
    configs = iter(
        [
            {"watch": {"state_dir": str(state_dir), "tray_enabled": False}},
            {"watch": {"state_dir": str(state_dir), "tray_enabled": True}},
        ]
    )
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "load_config", lambda: next(configs))
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    scheduler_starts = []
    tray_events = []

    async def start_scheduler(**kwargs):
        scheduler_starts.append(kwargs)

    class Tray:
        def start(self):
            tray_events.append("start")

        def stop(self):
            tray_events.append("stop")

    service.tray_factory = lambda _service: Tray()
    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)

    assert _await(service.reload()) is True
    assert scheduler_starts == []
    assert tray_events == ["start"]


def test_watch_service_language_reload_refreshes_existing_tray(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    root = tmp_path / "watched"
    root.mkdir()
    roots_path.write_text(str(root), encoding="utf-8")
    state_dir = tmp_path / ".sunpack_watch"
    configs = iter(
        [
            {"cli": {"language": "en"}, "watch": {"state_dir": str(state_dir), "tray_enabled": True}},
            {"cli": {"language": "zh"}, "watch": {"state_dir": str(state_dir), "tray_enabled": True}},
        ]
    )
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "load_config", lambda: next(configs))
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    scheduler_starts = []
    tray_events = []

    async def start_scheduler(**kwargs):
        scheduler_starts.append(kwargs)

    tray = SimpleNamespace(refresh=lambda: tray_events.append("refresh"))
    service.tray_factory = lambda _service: None
    service.tray = tray
    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)

    assert _await(service.reload()) is True
    assert len(scheduler_starts) == 1
    assert tray_events == ["refresh"]
    assert service.tray is tray


def test_watch_service_reload_skips_unchanged_state(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    root = tmp_path / "watched"
    root.mkdir()
    roots_path.write_text(str(root), encoding="utf-8")
    config = {"watch": {"state_dir": str(tmp_path / ".sunpack_watch"), "tray_enabled": False}}
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "load_config", lambda: config)
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    starts = []
    events = []
    service.log.write = lambda event, **payload: events.append((event, payload))

    async def start_scheduler(**kwargs):
        starts.append(kwargs)

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)

    assert _await(service.reload()) is False
    assert starts == []
    assert events == [("service_reload_skipped", {"reason": "no_semantic_change"})]


def test_watch_service_apply_failure_rolls_back_previous_config(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    watch_root = tmp_path / "watched"
    watch_root.mkdir()
    roots_path.write_text(str(watch_root), encoding="utf-8")
    state_dir = tmp_path / ".sunpack_watch"
    configs = iter(
        [
            {"watch": {"state_dir": str(state_dir), "tray_enabled": False}, "revision": 1},
            {"watch": {"state_dir": str(state_dir), "tray_enabled": False}, "revision": 2},
        ]
    )
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "load_config", lambda: next(configs))
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    starts = []

    async def start_scheduler(*, initial_scan=False, initial_scan_roots=None):
        starts.append(service.config["revision"])
        if service.config["revision"] == 2:
            raise RuntimeError("new runtime failed")

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)

    _await(service._reload_config())

    assert service.config["revision"] == 1
    assert starts == [2, 1]


def test_watch_roots_are_stored_in_program_txt(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    path, added = service_module.add_watch_roots([str(first), str(second), str(first)])
    listed_path, roots = service_module.list_watch_roots()
    _, removed = service_module.remove_watch_roots([str(first)])

    assert path == roots_path
    assert listed_path == roots_path
    assert added == [str(first.resolve()), str(second.resolve())]
    assert roots == [str(first.resolve()), str(second.resolve())]
    assert removed == [str(first.resolve())]
    assert roots_path.read_text(encoding="utf-8").splitlines() == [str(second.resolve())]


def test_remove_watch_root_cleans_service_owned_artifacts(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    watched = tmp_path / "watched"
    other_root = tmp_path / "other"
    watched.mkdir()
    other_root.mkdir()
    (watched / ".sunpack-passwords.txt").write_text("watch-password\n", encoding="utf-8")
    (other_root / ".sunpack-passwords.txt").write_text("keep-me\n", encoding="utf-8")
    (watched / ".sunpack_watch_probes" / "probe" / "work").mkdir(parents=True)
    (other_root / ".sunpack_watch_probes" / "probe").mkdir(parents=True)
    roots_path.write_text(f"{watched}\n{other_root}\n", encoding="utf-8")
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    _, removed = service_module.remove_watch_roots([str(watched)])

    assert removed == [str(watched.resolve())]
    assert not (watched / ".sunpack-passwords.txt").exists()
    assert not (watched / ".sunpack_watch_probes").exists()
    assert (other_root / ".sunpack-passwords.txt").read_text(encoding="utf-8") == "keep-me\n"
    assert (other_root / ".sunpack_watch_probes").exists()


def test_watch_roots_file_records_an_output_root_per_input_root(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first = tmp_path / "downloads"
    second = tmp_path / "archives"
    other_drive = tmp_path / "elsewhere"
    first.mkdir()
    second.mkdir()
    other_drive.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    service_module.add_watch_roots([str(first)], {str(first): str(other_drive)})
    service_module.add_watch_roots([str(second)], {str(second): "."})

    roots, root_outputs = service_module.read_watch_root_entries()
    assert roots == [str(first.resolve()), str(second.resolve())]
    assert root_outputs == {
        service_module.path_key(str(first.resolve())): str(other_drive.resolve()),
        service_module.path_key(str(second.resolve())): str(second.resolve()),
    }
    assert "|" in roots_path.read_text(encoding="utf-8")


def test_watch_roots_file_resolves_relative_output_against_its_input_root(tmp_path, monkeypatch):
    program_dir = tmp_path / "program"
    working_dir = tmp_path / "windows-system-directory"
    program_dir.mkdir()
    working_dir.mkdir()
    roots_path = program_dir / "sunpack_watch_roots.txt"
    watch_root = tmp_path / "downloads"
    nested_root = watch_root / "nested"
    nested_root.mkdir(parents=True)
    roots_path.write_text(
        f"{watch_root} | extracted\n{nested_root} | D:\\Out\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(working_dir)
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    roots, root_outputs = service_module.read_watch_root_entries()

    assert roots == [str(watch_root.resolve()), str(nested_root.resolve())]
    assert root_outputs[service_module.path_key(str(watch_root.resolve()))] == str(
        (watch_root / "extracted").resolve()
    )
    assert root_outputs[service_module.path_key(str(nested_root.resolve()))] == "D:\\Out"


def test_add_watch_root_is_idempotent_without_output_and_still_sets_output_otherwise(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    _, added = service_module.add_watch_roots([str(watch_root), str(watch_root)])
    _, readded = service_module.add_watch_roots([str(watch_root)])
    _, updated = service_module.add_watch_roots([str(watch_root)], {str(watch_root): "extracted"})

    assert added == [str(watch_root.resolve())]
    assert readded == []
    assert updated == []
    _, root_outputs = service_module.read_watch_root_entries()
    assert root_outputs[service_module.path_key(str(watch_root.resolve()))] == str(
        (watch_root / "extracted").resolve()
    )


def test_removing_watch_root_drops_only_its_output_root(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first = tmp_path / "downloads"
    second = tmp_path / "archives"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    service_module.add_watch_roots([str(first)], {str(first): str(tmp_path / "out-first")})
    service_module.add_watch_roots([str(second)], {str(second): str(tmp_path / "out-second")})

    service_module.remove_watch_roots([str(first)])

    roots, root_outputs = service_module.read_watch_root_entries()
    assert roots == [str(second.resolve())]
    assert list(root_outputs) == [service_module.path_key(str(second.resolve()))]


def test_watch_roots_lines_without_output_keep_the_configured_out_dir(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    roots_path.write_text(f"# comment\n\n{watch_root}\n", encoding="utf-8")
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    roots, root_outputs = service_module.read_watch_root_entries()

    assert roots == [str(watch_root.resolve())]
    assert root_outputs == {}


def test_watch_service_scheduler_receives_root_outputs(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    roots_path.write_text(f"{watch_root} | D:\\Extracted\n", encoding="utf-8")
    state_dir = tmp_path / ".sunpack_watch"
    captured = {}

    class FakeScheduler:
        def __init__(self, config, roots, **kwargs):
            captured["roots"] = roots
            captured["kwargs"] = kwargs

        async def start(self):
            pass

        async def stop(self):
            pass

    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "out_dir": ".", "tray_enabled": False}},
    )
    monkeypatch.setattr(service_module, "WatchScheduler", FakeScheduler)

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    _await(service._start_scheduler())

    assert captured["roots"] == [str(watch_root.resolve())]
    assert captured["kwargs"]["output_roots"] == {
        service_module.path_key(str(watch_root.resolve())): "D:\\Extracted"
    }


def test_remove_unmonitored_root_skips_artifact_cleanup(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    target = tmp_path / "not-watched"
    target.mkdir()
    password_file = target / ".sunpack-passwords.txt"
    password_file.write_text("", encoding="utf-8")
    (target / ".sunpack_watch_probes" / "probe").mkdir(parents=True)
    roots_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    _, removed = service_module.remove_watch_roots([str(target)])

    assert removed == []
    assert password_file.exists()
    assert (target / ".sunpack_watch_probes").exists()


def test_relative_watch_state_path_uses_program_directory_not_process_working_directory(tmp_path, monkeypatch):
    program_dir = tmp_path / "program"
    working_dir = tmp_path / "windows-system-directory"
    roots_path = program_dir / "sunpack_watch_roots.txt"
    program_dir.mkdir()
    working_dir.mkdir()
    watch_root = tmp_path / "watched"
    watch_root.mkdir()
    roots_path.write_text(str(watch_root), encoding="utf-8")
    monkeypatch.chdir(working_dir)
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    config = {"watch": {"out_dir": ".", "state_dir": "runtime/state"}}

    assert service_module.service_state_dir(config) == str((program_dir / "runtime" / "state").resolve())


def test_default_watch_state_uses_program_directory_and_output_stays_relative(tmp_path, monkeypatch):
    program_dir = tmp_path / "program"
    working_dir = tmp_path / "windows-system-directory"
    watch_root = tmp_path / "watched"
    roots_path = program_dir / "sunpack_watch_roots.txt"
    program_dir.mkdir()
    working_dir.mkdir()
    watch_root.mkdir()
    roots_path.write_text(str(watch_root), encoding="utf-8")
    monkeypatch.chdir(working_dir)
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"out_dir": ".", "state_dir": "", "tray_enabled": False}},
    )
    captured = {}

    class FakeScheduler:
        def __init__(self, config, roots, **kwargs):
            captured["out_dir"] = kwargs["out_dir"]
            captured["state_path"] = kwargs["state_path"]

        async def start(self):
            pass

        async def stop(self):
            pass

    monkeypatch.setattr(service_module, "WatchScheduler", FakeScheduler)

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    _await(service._start_scheduler())

    assert service.state_dir == str((program_dir / ".sunpack_watch").resolve())
    assert captured["out_dir"] == "."
    assert captured["state_path"] == str((program_dir / ".sunpack_watch" / "state.json").resolve())


def test_watch_state_falls_back_to_program_directory_without_existing_roots(tmp_path, monkeypatch):
    program_dir = tmp_path / "program"
    roots_path = program_dir / "sunpack_watch_roots.txt"
    program_dir.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    assert service_module.service_state_dir({"watch": {"out_dir": ".", "state_dir": ""}}) == str(
        (program_dir / ".sunpack_watch").resolve()
    )


def test_watch_roots_add_is_serialized_across_concurrent_callers(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    original_write = service_module._write_watch_roots_unlocked

    def slow_write(roots, path, **kwargs):
        time.sleep(0.05)
        return original_write(roots, path, **kwargs)

    monkeypatch.setattr(service_module, "_write_watch_roots_unlocked", slow_write)
    threads = [
        threading.Thread(target=service_module.add_watch_roots, args=([str(first)],)),
        threading.Thread(target=service_module.add_watch_roots, args=([str(second)],)),
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2.0)

    assert not any(thread.is_alive() for thread in threads)
    assert set(roots_path.read_text(encoding="utf-8").splitlines()) == {str(first.resolve()), str(second.resolve())}


def test_watch_service_reads_roots_from_txt_not_config(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    txt_root = tmp_path / "txt-root"
    config_root = tmp_path / "config-root"
    txt_root.mkdir()
    config_root.mkdir()
    roots_path.write_text(str(txt_root), encoding="utf-8")
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(tmp_path / ".sunpack_watch"),
                "roots": [str(config_root)],
                "tray_enabled": False,
            }
        },
    )

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))

    assert service.roots == [str(txt_root.resolve())]


def test_watch_service_scheduler_never_recurses(tmp_path, monkeypatch):
    roots_path = tmp_path / "sunpack_watch_roots.txt"
    watch_root = tmp_path / "watch-root"
    watch_root.mkdir()
    roots_path.write_text(str(watch_root), encoding="utf-8")
    state_dir = tmp_path / ".sunpack_watch"
    captured = {}
    original_scheduler = service_module.WatchScheduler

    class FakeScheduler:
        def __init__(self, config, roots, **kwargs):
            captured["config"] = config
            captured["roots"] = roots
            captured["kwargs"] = kwargs
            self.recursive = original_scheduler(config, roots, **kwargs).recursive

        async def start(self):
            captured["started"] = True

        async def stop(self):
            pass

    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "WatchScheduler", FakeScheduler)
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "filesystem": {"directory_scan_mode": "recursive", "scan_filters": []},
            "watch": {
                "state_dir": str(state_dir),
                "recursive": True,
                "tray_enabled": False,
            },
        },
    )

    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    _await(service._start_scheduler())

    assert captured["roots"] == [str(watch_root.resolve())]
    assert "recursive" not in captured["kwargs"]
    assert captured["kwargs"]["quiet_seconds"] == 0.0
    assert service.scheduler.recursive is False
    assert captured["started"] is True


def test_watch_service_passes_direct_scan_roots_to_scheduler(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    watch_root = tmp_path / "watch-root"
    watch_root.mkdir()
    requested_root = watch_root / "new-root"
    requested_root.mkdir()
    captured = {}

    class Engine:
        async def __aenter__(self):
            return self

        async def aclose(self, graceful=True):
            pass

    class FakeScheduler:
        def __init__(self, config, roots, **kwargs):
            captured["roots"] = roots
            captured["kwargs"] = kwargs

        async def start(self):
            pass

        async def stop(self):
            pass

    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(state_dir),
                "roots": [str(watch_root)],
                "tray_enabled": False,
            }
        },
    )
    monkeypatch.setattr(service_module, "read_watch_root_entries", lambda: ([str(watch_root)], {}))
    monkeypatch.setattr(service_module, "WatchScheduler", FakeScheduler)
    service = WatchService(engine_factory=lambda _config: Engine())
    _await(service._start_scheduler(initial_scan_roots=[str(requested_root)]))

    assert captured["roots"] == [str(watch_root.resolve())]
    assert captured["kwargs"]["initial_scan"] is False
    assert captured["kwargs"]["initial_scan_roots"] == [str(requested_root.resolve())]


def test_watch_service_waits_indefinitely_when_scheduler_is_idle(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    state_dir.mkdir()
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {
            "watch": {
                "state_dir": str(state_dir),
                "roots": [],
                "tray_enabled": False,
            }
        },
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    scheduler_runs = []

    class FakeScheduler:
        async def run_once(self):
            scheduler_runs.append(len(scheduler_runs))
            return SimpleNamespace(processed=0, succeeded=0, failed=0, pending=0, errors=[])

    async def start_scheduler(*, initial_scan=False, initial_scan_roots=None):
        service.scheduler = FakeScheduler()

    async def stop_scheduler():
        service.scheduler = None

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)
    monkeypatch.setattr(service, "_stop_scheduler", stop_scheduler)
    monkeypatch.setattr(service, "_start_tray", lambda: None)
    monkeypatch.setattr(service, "_stop_tray", lambda: None)
    service._control_queue = asyncio.Queue()
    service._control_queue.put_nowait(CONTROL_STOP)
    assert _await(service.run()) == 0
    assert len(scheduler_runs) == 1


def test_watch_add_pins_the_requested_output_dir_and_list_shows_it(tmp_path, monkeypatch):
    from sunpack.cli.cli import build_cli_parser
    from sunpack.cli.cli_context import CliContext
    from sunpack.cli import runtime_state

    roots_path = tmp_path / "sunpack_watch_roots.txt"
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    class FakeHost:
        watch_enabled = False

    monkeypatch.setattr(runtime_state, "require_runtime_host", lambda: FakeHost())
    args = build_cli_parser(CliContext(language="en")).parse_args(
        ["watch", "add", str(watch_root), "--output-dir", "extracted"]
    )

    code, result = _await(watch_command._handle_add(args, SimpleNamespace(cwd=str(tmp_path), t=lambda key, **_: key)))

    assert code == 0
    assert result.summary["added"] == [str(watch_root.resolve())]
    assert roots_path.read_text(encoding="utf-8").splitlines() == [f"{watch_root.resolve()} | extracted"]
    _, _, root_outputs = service_module.list_watch_root_entries()
    assert root_outputs == {
        service_module.path_key(str(watch_root.resolve())): str((watch_root / "extracted").resolve())
    }

    list_code, listed = watch_command._handle_list()

    assert list_code == 0
    assert listed.items == [
        f"{watch_root.resolve()} | {watch_root / 'extracted'}"
    ]


def test_watch_add_rejects_one_output_dir_for_several_roots(tmp_path, monkeypatch):
    from sunpack.cli.cli import build_cli_parser
    from sunpack.cli.cli_context import CliContext
    from sunpack.cli import runtime_state

    roots_path = tmp_path / "sunpack_watch_roots.txt"
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)

    class FakeHost:
        watch_enabled = False

    monkeypatch.setattr(runtime_state, "require_runtime_host", lambda: FakeHost())
    args = build_cli_parser(CliContext(language="en")).parse_args(
        ["watch", "add", "C:/one", "C:/two", "--output-dir", "extracted"]
    )

    code, result = _await(watch_command._handle_add(args, SimpleNamespace(cwd=str(tmp_path), t=lambda key, **_: key)))

    assert code != 0
    assert result.errors == ["cli.watch.output_dir_single_path"]
    assert not roots_path.exists()


def test_watch_service_recalculates_deadline_after_scheduler_wakeup(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    state_dir.mkdir()
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "roots": [], "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    scheduler_runs = []

    class FakeScheduler:
        def __init__(self):
            self.delay = 120.0

        async def run_once(self):
            scheduler_runs.append(len(scheduler_runs))
            if len(scheduler_runs) == 2:
                self.delay = 5.0
            return SimpleNamespace(processed=0, succeeded=0, failed=0, pending=1, errors=[])

        def next_delay_seconds(self):
            return self.delay

    scheduler = FakeScheduler()

    async def start_scheduler(*, initial_scan=False, initial_scan_roots=None):
        service.scheduler = scheduler

    async def stop_scheduler():
        service.scheduler = None

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)
    monkeypatch.setattr(service, "_stop_scheduler", stop_scheduler)
    monkeypatch.setattr(service, "_start_tray", lambda: None)
    monkeypatch.setattr(service, "_stop_tray", lambda: None)
    service._control_queue = asyncio.Queue()
    service._control_queue.put_nowait(CONTROL_SCHEDULER_WAKEUP)
    service._control_queue.put_nowait(CONTROL_STOP)
    assert _await(service.run()) == 0
    assert len(scheduler_runs) == 2


def test_watch_service_runs_scheduler_when_wakeup_has_no_schedulable_delay(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    state_dir.mkdir()
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "roots": [], "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    scheduler_runs = []

    class FakeScheduler:
        def __init__(self):
            self.delay = 120.0

        async def run_once(self):
            scheduler_runs.append(len(scheduler_runs))
            return SimpleNamespace(processed=0, succeeded=0, failed=0, pending=1, errors=[])

        def next_delay_seconds(self):
            return self.delay

    scheduler = FakeScheduler()

    async def start_scheduler(*, initial_scan=False, initial_scan_roots=None):
        service.scheduler = scheduler

    async def stop_scheduler():
        service.scheduler = None

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)
    monkeypatch.setattr(service, "_stop_scheduler", stop_scheduler)
    monkeypatch.setattr(service, "_start_tray", lambda: None)
    monkeypatch.setattr(service, "_stop_tray", lambda: None)
    service._control_queue = asyncio.Queue()
    service._control_queue.put_nowait(CONTROL_SCHEDULER_WAKEUP)
    service._control_queue.put_nowait(CONTROL_STOP)

    assert _await(service.run()) == 0
    assert len(scheduler_runs) == 2


def test_watch_service_deduplicates_unchanged_pending_ticks(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sunpack_watch"
    state_dir.mkdir()
    monkeypatch.setattr(
        service_module,
        "load_config",
        lambda: {"watch": {"state_dir": str(state_dir), "roots": [], "tray_enabled": False}},
    )
    service = WatchService(engine_factory=lambda _config: FakePipelineEngine(FakeRunner))
    written = []

    class FakeLog:
        def write(self, event, **payload):
            written.append((event, payload))

    class FakeScheduler:
        def __init__(self):
            self.results = iter([
                SimpleNamespace(processed=0, succeeded=0, failed=0, pending=1, errors=[]),
                SimpleNamespace(processed=0, succeeded=0, failed=0, pending=1, errors=[]),
                SimpleNamespace(processed=1, succeeded=1, failed=0, pending=0, errors=[]),
                SimpleNamespace(processed=0, succeeded=0, failed=0, pending=1, errors=[]),
            ])

        async def run_once(self):
            return next(self.results)

        def next_delay_seconds(self):
            return 5.0

    async def start_scheduler(*, initial_scan=False, initial_scan_roots=None):
        service.scheduler = FakeScheduler()

    async def stop_scheduler():
        service.scheduler = None

    monkeypatch.setattr(service, "_start_scheduler", start_scheduler)
    monkeypatch.setattr(service, "_stop_scheduler", stop_scheduler)
    monkeypatch.setattr(service, "_start_tray", lambda: None)
    monkeypatch.setattr(service, "_stop_tray", lambda: None)
    service._control_queue = asyncio.Queue()
    for event in (
        CONTROL_SCHEDULER_WAKEUP,
        CONTROL_SCHEDULER_WAKEUP,
        CONTROL_SCHEDULER_WAKEUP,
        CONTROL_STOP,
    ):
        service._control_queue.put_nowait(event)
    service.log = FakeLog()
    assert _await(service.run()) == 0

    tick_payloads = [payload for event, payload in written if event == "scheduler_tick"]
    assert tick_payloads == [
        {"processed": 0, "succeeded": 0, "failed": 0, "pending": 1, "errors": []},
        {"processed": 1, "succeeded": 1, "failed": 0, "pending": 0, "errors": []},
        {"processed": 0, "succeeded": 0, "failed": 0, "pending": 1, "errors": []},
    ]
