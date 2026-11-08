import os
import threading
import weakref

import pytest

from sunpack.core.platform.windows import toast_host as module
from sunpack.core.platform.windows.toast_host import ToastManager
from sunpack.core.platform.windows.toast_protocol import ToastSnapshot, ToastSnapshotKind


def snapshot(kind=ToastSnapshotKind.SUCCESS, *, title='done'):
    return ToastSnapshot(kind, 'batch', title)


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


def test_terminal_releases_snapshot_without_clearing_presented_notification(monkeypatch):
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory)
    item = snapshot()
    retained = weakref.ref(item)
    manager.publish(item)
    del item
    original_wait = manager._condition.wait_for

    def wait_for(predicate, timeout=None):
        recorder.record('waiting', timeout)
        return original_wait(predicate, timeout)

    monkeypatch.setattr(manager._condition, 'wait_for', wait_for)
    try:
        manager.start()
        recorder.wait('waiting')
        assert retained() is None
        assert [e[0] for e in recorder.events] == ['create', 'show', 'waiting']
        assert recorder.events[-1][3] is None  # No expiration deadline.
    finally:
        manager.stop()
    assert not any(e[0] == 'clear' for e in recorder.events)


def test_stopping_manager_clears_active_progress_only():
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory)
    manager.publish(snapshot(ToastSnapshotKind.PROGRESS))
    manager.start()
    recorder.wait('show')
    manager.stop()
    assert [e[0] for e in recorder.events][-2:] == ['clear', 'close']


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
    assert waits == [None] and not recorder.events


def test_progress_coalesces_but_terminal_bypasses_throttle():
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory)
    manager._update_interval = 1.0
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
    manager = ToastManager(presenter_factory=recorder.factory)
    manager._update_interval = 0.1
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
    manager.publish(snapshot(ToastSnapshotKind.PROGRESS))
    try:
        manager.start()
        recorder.wait('show')
        manager.publish(snapshot(title='x' * 65536))
        recorder.wait('clear')
        manager.publish(snapshot())
        recorder.wait('show', 2)
        assert manager._thread.is_alive()
    finally:
        manager.stop()


def test_native_start_failure_stays_unavailable_until_lifecycle_restart():
    # Other lifecycle tests never fail initialization. This catches retries on
    # new snapshots and verifies restart recovery with two cheap thread runs.
    recorder = Recorder()
    attempts = []

    def factory(**kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError('unavailable')
        return recorder.factory(**kwargs)

    manager = ToastManager(presenter_factory=factory)
    manager.publish(snapshot(title='old'))
    manager.start()
    manager._thread.join(3)
    assert not manager._thread.is_alive()
    manager.publish(snapshot(title='ignored'))
    manager.clear()
    manager.start()
    assert attempts == [1] and manager._snapshot is None
    manager.stop()
    try:
        manager.start()
        manager.publish(snapshot(title='fresh'))
        recorder.wait('show')
        assert len(attempts) == 2
        assert b'fresh' in [e for e in recorder.events if e[0] == 'show'][0][3]
    finally:
        manager.stop()


def test_restart_stays_idle_until_a_new_snapshot(monkeypatch):
    recorder = Recorder()
    manager = ToastManager(presenter_factory=recorder.factory)
    original_wait = manager._condition.wait_for

    def wait_for(predicate, timeout=None):
        recorder.record('waiting')
        return original_wait(predicate, timeout)

    monkeypatch.setattr(manager._condition, 'wait_for', wait_for)
    manager.publish(snapshot())
    manager.start()
    recorder.wait('waiting')
    manager.stop()
    try:
        manager.start()
        recorder.wait('waiting', 2)
        manager.clear()
        recorder.wait('waiting', 3)
        assert sum(e[0] == 'create' for e in recorder.events) == 1
        assert sum(e[0] == 'show' for e in recorder.events) == 1
        manager.publish(snapshot(title='fresh'))
        recorder.wait('show', 2)
    finally:
        manager.stop()


def test_cli_bootstrap_does_not_load_toast_library(monkeypatch):
    from sunpack.runtime.cli import cli
    from sunpack.runtime import entrypoint

    monkeypatch.setattr(module, '_load_library', lambda: pytest.fail('CLI loaded toast DLL'))
    monkeypatch.setattr(cli, 'main', lambda: 0)
    for argv in ([], ['extract', 'archive.zip'], ['scan', '.'], ['watch', 'status']):
        monkeypatch.setattr(entrypoint.sys, 'argv', ['sunpack-runtime.exe', *argv])
        assert entrypoint.main() == 0


def test_native_wrapper_passes_snapshot_and_closes_once(monkeypatch):
    calls = []

    class Library:
        def sunpack_toast_create_presenter(self, executable, log, output):
            calls.append(('create', executable, log))
            output._obj.value = 123
            return 0

        def sunpack_toast_show(self, context, payload, size, sequence):
            calls.append(('show', context.value, payload, size, sequence))
            return 0

        def sunpack_toast_destroy(self, context):
            calls.append(('destroy', context.value))
            return 0

    monkeypatch.setattr(module, '_load_library', Library)
    monkeypatch.setattr(module, 'current_process_executable', lambda: 'main.exe')
    presenter = module._NativeToastPresenter(diagnostic_log_path='events.jsonl')
    presenter.show(b'a\0b', 7)
    presenter.close()
    presenter.close()
    assert calls == [('create', 'main.exe', 'events.jsonl'),
                     ('show', 123, b'a\0b', 3, 7), ('destroy', 123)]


def test_show_failure_discards_snapshot_and_only_new_publish_recreates_presenter(monkeypatch):
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
    waits = []
    original_wait = manager._condition.wait_for

    def wait_for(predicate, timeout=None):
        waits.append(timeout)
        recorder.record('waiting')
        return original_wait(predicate, timeout)

    monkeypatch.setattr(manager._condition, 'wait_for', wait_for)
    try:
        manager.start()
        recorder.wait('waiting')
        assert waits == [None] and len(attempts) == 1
        manager.publish(snapshot(title='fresh'))
        recorder.wait('show')
    finally:
        manager.stop()
    assert [e[0] for e in recorder.events if e[0] != 'waiting'] == ['create', 'close', 'create', 'show', 'close']
    assert b'fresh' in [e for e in recorder.events if e[0] == 'show'][0][3]
    assert len({e[1] for e in recorder.events}) == 1


def test_main_runtime_handles_toast_activation_without_starting_engine(monkeypatch):
    import sys
    from types import SimpleNamespace
    import sunpack.runtime.entrypoint as entrypoint
    from sunpack.core.support import runtime_identity

    calls = []
    library = SimpleNamespace(
        sunpack_toast_activate=lambda: calls.append(runtime_identity.runtime_id()) or 0,
        sunpack_toast_cancel_batch=lambda *_: 0,
    )
    monkeypatch.setattr(module, '_load_library', lambda: library)
    identity = 'v2-0123456789abcdef'
    monkeypatch.setattr(runtime_identity, '_runtime_id', None)
    monkeypatch.setattr(sys, 'argv', ['sunpack-runtime.exe', '--toast-activated', runtime_identity.runtime_id_argument(identity)])
    assert entrypoint.main() == 0
    assert calls == [identity]


@pytest.mark.parametrize('response, expected_code', [
    (None, 1), ({}, 1), ({'exit_code': 1}, 1), ({'exit_code': 2}, 2), ({'exit_code': 0}, 0),
])
def test_stop_activation_requires_acknowledgement_and_reports_failure(monkeypatch, response, expected_code):
    # Bootstrap tests activate no action; they cannot catch a lost or rejected
    # stop being reported as success by the hidden helper. No process is needed.
    from types import SimpleNamespace
    from sunpack.runtime.cli import persistent_process
    from sunpack.core.config import cli_settings

    batch_id = '0123456789abcdef0123456789abcdef'
    calls = []
    snapshots = []

    def cancel_batch(buffer, _capacity):
        buffer.value = batch_id
        return 0

    library = SimpleNamespace(sunpack_toast_activate=lambda: 0, sunpack_toast_cancel_batch=cancel_batch)
    monkeypatch.setattr(module, '_load_library', lambda: library)
    monkeypatch.setattr(cli_settings, 'load_cli_language_from_config', lambda: 'zh')

    def send(payload):
        calls.append(payload)
        return response

    monkeypatch.setattr(persistent_process, '_try_send', send)
    monkeypatch.setattr(persistent_process, '_send_or_start', lambda _payload: pytest.fail('stop started a new runtime'))
    original_encode = module.encode_snapshot

    def encode(snapshot):
        snapshots.append(snapshot)
        return original_encode(snapshot)

    monkeypatch.setattr(module, 'encode_snapshot', encode)
    recorder = Recorder()
    monkeypatch.setattr(module, '_NativeToastPresenter', recorder.factory)
    assert module.activate_toast() == expected_code
    assert calls == [{'argv': ['--cancel-watch-batch', batch_id], 'cwd': os.getcwd()}]
    if expected_code:
        failure, = snapshots
        assert failure.kind == ToastSnapshotKind.FAILURE
        assert failure.batch_id != batch_id  # Never remove live progress on uncertain delivery.
        assert failure.title == 'SunPack 未能确认停止'
        assert '未收到停止确认' in failure.body
        assert [event[0] for event in recorder.events] == ['create', 'show', 'close']
    else:
        assert not snapshots and not recorder.events


def test_resource_lookup_selects_current_architecture(tmp_path, monkeypatch):
    from sunpack.core.support import resources

    for arch in ('x64', 'arm64'):
        directory = tmp_path / 'native' / 'toast_host' / f'build-{arch}' / 'Release'
        directory.mkdir(parents=True)
        (directory / 'sunpack_toast.dll').write_bytes(b'')
    monkeypatch.setattr(resources, 'candidate_resource_roots', lambda: [tmp_path])
    monkeypatch.setattr(resources.platform, 'machine', lambda: 'ARM64')
    assert 'build-arm64' in resources.get_toast_library_path()
    monkeypatch.setattr(resources.platform, 'machine', lambda: 'AMD64')
    assert 'build-x64' in resources.get_toast_library_path()
