from watchdog.observers.api import EventQueue, ObservedWatch
from watchdog.observers.read_directory_changes import WindowsApiEmitter
from watchdog.observers.winapi import WinAPINativeEvent, FILE_ACTION_MODIFIED

from sunpack.runtime.watch.observer import _RecoveryEmitter


def test_notification_overflow_wakes_recovery_and_stop_does_not(tmp_path, monkeypatch):
    """Scheduler tests cannot observe watchdog swallowing empty/error completions.

    Without this, a completely dropped notification batch could leave Watch
    asleep indefinitely. Three fake completions cover that contract without IO.
    """
    queue = EventQueue()
    emitter = _RecoveryEmitter(queue, ObservedWatch(str(tmp_path), recursive=True))
    monkeypatch.setattr(WindowsApiEmitter, "_read_events", lambda self: [])
    emitter.queue_events(0)
    event, watch = queue.get_nowait()
    assert event.src_path == str(tmp_path) and event.is_directory and event.is_synthetic
    assert watch == emitter.watch

    def overflow(self):
        error = OSError("notification history lost")
        error.winerror = 1022
        raise error

    monkeypatch.setattr(WindowsApiEmitter, "_read_events", overflow)
    emitter.queue_events(0)
    event, _ = queue.get_nowait()
    assert event.is_synthetic
    monkeypatch.setattr(WindowsApiEmitter, "_read_events",
                        lambda self: [WinAPINativeEvent(FILE_ACTION_MODIFIED, "source.opaque")])
    emitter.queue_events(0)
    event, _ = queue.get_nowait()
    assert not event.is_synthetic and event.src_path.endswith("source.opaque")
    emitter.stop()
    monkeypatch.setattr(WindowsApiEmitter, "_read_events", lambda self: [])
    emitter.queue_events(0)
    assert queue.empty()
