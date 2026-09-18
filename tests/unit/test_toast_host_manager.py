import os
import threading
import time

import pytest

from sunpack.platform.windows import toast_host as module
from sunpack.platform.windows.toast_host import ToastManager
from sunpack.platform.windows.toast_protocol import ToastSnapshot, ToastSnapshotKind


def snapshot(kind=ToastSnapshotKind.SUCCESS, *, title='done', ttl_ms=0):
    return ToastSnapshot(kind, 'batch', title, ttl_ms=ttl_ms)


class Recorder:
    def __init__(self):
        self.events = []
        self.condition = threading.Condition()

    def record(self, name, *values):
        with self.condition:
            self.events.append((name, threading.get_ident(), os.getpid(), *values))
            self.condition.notify_all()

    def wait(self, name, count=1):
        with self.condition:
            assert self.condition.wait_for(
                lambda: sum(e[0] == name for e in self.events) >= count, timeout=3,
            ), self.events

    def factory(self, **kwargs):
        self.record('create', kwargs)
        recorder = self

        class Presenter:
            def show(self, payload, sequence):
                recorder.record('show', payload, sequence)

            def clear(self):
                recorder.record('clear')

            def close(self):
                recorder.record('close')

        return Presenter()


def test_lifecycle_owns_native_objects_on_one_main_process_thread(tmp_path):
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory, diagnostic_log_path=str(tmp_path / 'events.jsonl'))
    manager.publish(snapshot())
    assert recorder.events == []
    try:
        manager.start()
        manager.start()
        recorder.wait('show')
        manager.clear()
        recorder.wait('clear')
    finally:
        manager.stop()
    assert len({e[1] for e in recorder.events}) == 1
    assert recorder.events[0][1] != threading.get_ident()
    assert {e[2] for e in recorder.events} == {os.getpid()}
    assert recorder.events[-1][0] == 'close'
    assert sum(e[0] == 'create' for e in recorder.events) == 1
    assert recorder.events[0][3]['diagnostic_log_path'] == str(tmp_path / 'events.jsonl')
    manager.publish(snapshot())
    assert manager._snapshot is None
    manager.stop()


def test_ttl_starts_after_show_returns():
    recorder = Recorder()
    entered, release = threading.Event(), threading.Event()

    def factory(**kwargs):
        presenter = recorder.factory(**kwargs)
        show = presenter.show

        def delayed_show(payload, sequence):
            entered.set()
            assert release.wait(3)
            show(payload, sequence)

        presenter.show = delayed_show
        return presenter

    manager = ToastManager(presenter_factory=factory)
    manager.publish(snapshot(ttl_ms=100))
    try:
        manager.start()
        assert entered.wait(3)
        time.sleep(.15)
        assert not any(e[0] == 'clear' for e in recorder.events)
        released_at = time.monotonic()
        release.set()
        recorder.wait('clear')
        assert time.monotonic() - released_at >= .09
    finally:
        release.set()
        manager.stop()


def test_idle_thread_does_not_poll(monkeypatch):
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory)
    waits = []

    def wait_for(predicate, timeout=None):
        waits.append(timeout)
        manager._stopping = True
        return predicate()

    monkeypatch.setattr(manager._condition, 'wait_for', wait_for)
    manager._run()
    assert waits == [None]


def test_progress_coalesces_but_terminal_bypasses_throttle():
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory, update_interval_ms=1000)
    manager.publish(snapshot(ToastSnapshotKind.PROGRESS, title='first'))
    try:
        manager.start()
        recorder.wait('show')
        for i in range(10):
            manager.publish(snapshot(ToastSnapshotKind.PROGRESS, title=f'pending-{i}'))
        manager.publish(snapshot(title='terminal'))
        recorder.wait('show', 2)
        shown = [e for e in recorder.events if e[0] == 'show']
        assert len(shown) == 2
        assert b'terminal' in shown[1][3]
        assert shown[1][4] > shown[0][4]
    finally:
        manager.stop()


def test_latest_progress_is_sent_after_throttle_deadline():
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory, update_interval_ms=100)
    manager.publish(snapshot(ToastSnapshotKind.PROGRESS, title='first'))
    try:
        manager.start()
        recorder.wait('show')
        manager.publish(snapshot(ToastSnapshotKind.PROGRESS, title='latest'))
        recorder.wait('show', 2)
        assert b'latest' in [e for e in recorder.events if e[0] == 'show'][-1][3]
    finally:
        manager.stop()


def test_bad_snapshot_is_rejected_without_killing_thread():
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory)
    manager.publish(snapshot(title='x' * 65536))
    try:
        manager.start()
        recorder.wait('clear')
        manager.publish(snapshot())
        recorder.wait('show')
        assert manager._thread.is_alive()
    finally:
        manager.stop()


def test_native_start_failure_retries_latest_snapshot(monkeypatch):
    recorder = Recorder()
    attempts = []

    def factory(**kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError('unavailable')
        return recorder.factory(**kwargs)

    manager = ToastManager(presenter_factory=factory)
    manager.publish(snapshot(title='old'))
    monkeypatch.setattr(manager, '_wait_for_stop', lambda _seconds: manager.publish(snapshot(title='latest')))
    try:
        manager.start()
        recorder.wait('show')
        assert b'latest' in [e for e in recorder.events if e[0] == 'show'][0][3]
    finally:
        manager.stop()


def test_stop_interrupts_native_retry_backoff():
    entered = threading.Event()

    def factory(**_kwargs):
        entered.set()
        raise OSError('unavailable')

    manager = ToastManager(presenter_factory=factory)
    manager.start()
    assert entered.wait(3)
    manager.stop()
    assert manager._thread is None


def test_restart_does_not_replay_previous_watch_snapshot():
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory)
    manager.publish(snapshot())
    manager.start()
    recorder.wait('show')
    manager.stop()
    try:
        manager.start()
        recorder.wait('clear')
        assert sum(e[0] == 'show' for e in recorder.events) == 1
    finally:
        manager.stop()


def test_cli_bootstrap_does_not_load_toast_library(monkeypatch):
    monkeypatch.setattr(module, '_load_library', lambda: pytest.fail('CLI loaded toast DLL'))
    for argv in ([], ['extract', 'archive.zip'], ['scan', '.'], ['watch', 'status']):
        assert module.handle_toast_argv(argv) is None


def test_native_wrapper_passes_snapshot_and_closes_once(monkeypatch):
    calls = []

    class Library:
        def sunpack_toast_create(self, executable, arguments, log, output):
            calls.append(('create', executable, arguments, log))
            output._obj.value = 123
            return 0

        def sunpack_toast_show(self, context, payload, size, sequence):
            calls.append(('show', context.value, payload, size, sequence))
            return 0

        def sunpack_toast_destroy(self, context):
            calls.append(('destroy', context.value))
            return 0

    monkeypatch.setattr(module, '_load_library', lambda _path: Library())
    monkeypatch.setattr(module, '_activation_command', lambda: ('main.exe', '--toast-activated'))
    presenter = module._NativeToastPresenter(diagnostic_log_path='events.jsonl')
    presenter.show(b'a\0b', 7)
    presenter.close()
    presenter.close()
    assert calls == [('create', 'main.exe', '--toast-activated', 'events.jsonl'),
                     ('show', 123, b'a\0b', 3, 7), ('destroy', 123)]


def test_show_failure_recreates_presenter_on_owner_thread(monkeypatch):
    recorder = Recorder()
    attempts = []

    def factory(**kwargs):
        presenter = recorder.factory(**kwargs)
        attempts.append(1)
        if len(attempts) == 1:
            def fail(_payload, _sequence):
                raise OSError('Show failed')
            presenter.show = fail
        return presenter

    manager = ToastManager(presenter_factory=factory)
    manager.publish(snapshot())
    monkeypatch.setattr(manager, '_wait_for_stop', lambda _seconds: None)
    try:
        manager.start()
        recorder.wait('show')
    finally:
        manager.stop()
    assert [e[0] for e in recorder.events] == ['create', 'close', 'create', 'show', 'close']
    assert len({e[1] for e in recorder.events}) == 1


@pytest.mark.parametrize('argument, native_method', [
    ('--register-toast', 'register'), ('--toast-activated', 'activate'),
])
def test_main_runtime_handles_toast_bootstrap_without_starting_engine(monkeypatch, argument, native_method):
    import sys
    from types import SimpleNamespace
    from sunpack.support import entrypoint
    from sunpack.support import runtime_identity

    calls = []
    library = SimpleNamespace(**{
        'sunpack_toast_' + name: (lambda *args, name=name: calls.append((name, args)) or 0)
        for name in ('register', 'unregister', 'activate')
    })
    monkeypatch.setattr(module, '_load_library', lambda: library)
    monkeypatch.setattr(module, '_activation_command', lambda: ('main.exe', '--toast-activated'))
    monkeypatch.setattr(sys, 'argv', ['sunpack-runtime.exe', argument])
    monkeypatch.setattr(runtime_identity, 'consume_runtime_id', lambda _argv: pytest.fail('entered normal runtime'))
    assert entrypoint.main() == 0
    assert calls == [(native_method, ('main.exe', '--toast-activated') if native_method == 'register' else ())]


def test_unregister_toast_unelevated_removes_current_user_identity_without_native(monkeypatch):
    from sunpack.platform.windows import elevation

    calls = []
    monkeypatch.setattr(elevation, 'is_process_elevated', lambda: False)
    monkeypatch.setattr(module, '_remove_current_user_toast_identity', lambda: calls.append('user'))
    monkeypatch.setattr(module, '_load_library', lambda: pytest.fail('unelevated cleanup loaded native Toast DLL'))

    assert module.handle_toast_argv(['--unregister-toast']) == 0
    assert calls == ['user']


def test_unregister_toast_elevated_removes_machine_registration_then_delegates_user_cleanup(
    tmp_path, monkeypatch,
):
    from types import SimpleNamespace
    from sunpack.platform.windows import elevation, process_launch

    calls = []
    library = SimpleNamespace(
        sunpack_toast_unregister=lambda: calls.append('machine') or 0,
    )

    class Process:
        def wait(self, timeout=None):
            calls.append(('wait', timeout))
            return 0

        def close(self):
            calls.append('close')

    monkeypatch.setattr(elevation, 'is_process_elevated', lambda: True)
    monkeypatch.setattr(module, '_load_library', lambda: library)
    monkeypatch.setattr(module, '_runtime_argv', lambda argument: ['runtime.exe', argument])
    monkeypatch.setattr(module, 'current_process_executable', lambda: tmp_path / 'runtime.exe')

    def launch(argv, *, cwd=None, env=None):
        calls.append(('launch', argv, cwd))
        return Process()

    monkeypatch.setattr(process_launch, 'launch_unelevated', launch)

    assert module.handle_toast_argv(['--unregister-toast']) == 0
    assert calls == [
        'machine',
        ('launch', ['runtime.exe', '--unregister-toast'], str(tmp_path)),
        ('wait', 30.0),
        'close',
    ]


def test_current_user_toast_identity_cleanup_targets_hkcu(monkeypatch):
    import sys
    from types import SimpleNamespace

    calls = []
    fake_winreg = SimpleNamespace(
        HKEY_CURRENT_USER=object(),
        DeleteKey=lambda root, path: calls.append((root, path)),
    )
    monkeypatch.setitem(sys.modules, 'winreg', fake_winreg)

    module._remove_current_user_toast_identity()

    assert calls == [
        (fake_winreg.HKEY_CURRENT_USER, r'Software\Classes\AppUserModelId\SunPack.Watch.Toast'),
    ]


def test_resource_lookup_selects_current_architecture(tmp_path, monkeypatch):
    from sunpack.support import resources

    for arch in ('x64', 'arm64'):
        directory = tmp_path / 'native' / 'toast_host' / f'build-{arch}' / 'Release'
        directory.mkdir(parents=True)
        (directory / 'sunpack_toast.dll').write_bytes(b'')
    monkeypatch.setattr(resources, 'candidate_resource_roots', lambda: [tmp_path])
    monkeypatch.setattr(resources.platform, 'machine', lambda: 'ARM64')
    assert 'build-arm64' in resources.get_toast_library_path()
    monkeypatch.setattr(resources.platform, 'machine', lambda: 'AMD64')
    assert 'build-x64' in resources.get_toast_library_path()
