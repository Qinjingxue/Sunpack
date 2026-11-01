from watchdog.events import DirModifiedEvent
from watchdog.observers.api import BaseObserver
from watchdog.observers.read_directory_changes import WindowsApiEmitter


class _RecoveryEmitter(WindowsApiEmitter):
    def _read_events(self):
        try:
            events = super()._read_events()
        except OSError as exc:
            if exc.winerror != 1022:  # ERROR_NOTIFY_ENUM_DIR: notification history lost.
                raise
            events = []
        # ReadDirectoryChangesW also reports overflow by completing with zero
        # bytes. watchdog otherwise drops that completion without waking Watch.
        if not events and self.should_keep_running():
            self.queue_event(DirModifiedEvent(self.watch.path, is_synthetic=True))
        return events


def Observer():
    return BaseObserver(_RecoveryEmitter)
