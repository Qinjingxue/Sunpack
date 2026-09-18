from __future__ import annotations

import sunpack.platform.windows.process_qos as process_qos


class _FakeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


def test_processing_mode_switches_background_and_normal_on_windows(monkeypatch):
    calls = []
    kernel32 = type(
        "Kernel32",
        (),
        {
            "GetCurrentProcess": _FakeFunction(lambda: 123),
            "SetPriorityClass": _FakeFunction(lambda process, priority: calls.append((process, priority)) or True),
        },
    )()
    monkeypatch.setattr(process_qos.sys, "platform", "win32")
    monkeypatch.setattr(process_qos.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setattr(process_qos, "_BACKGROUND", False)

    assert process_qos.set_processing_mode(background=True) == "background"
    assert process_qos.set_processing_mode(background=False) == "normal"
    assert calls == [
        (123, process_qos.PROCESS_MODE_BACKGROUND_BEGIN),
        (123, process_qos.PROCESS_MODE_BACKGROUND_END),
    ]


def test_processing_mode_falls_back_to_priority_classes(monkeypatch):
    calls = []
    kernel32 = type(
        "Kernel32",
        (),
        {
            "GetCurrentProcess": _FakeFunction(lambda: 123),
            "SetPriorityClass": _FakeFunction(
                lambda process, priority: calls.append((process, priority))
                or priority in {process_qos.BELOW_NORMAL_PRIORITY_CLASS, process_qos.NORMAL_PRIORITY_CLASS}
            ),
        },
    )()
    monkeypatch.setattr(process_qos.sys, "platform", "win32")
    monkeypatch.setattr(process_qos.ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setattr(process_qos, "_BACKGROUND", False)

    assert process_qos.set_processing_mode(background=True) == "below_normal"
    assert process_qos.set_processing_mode(background=False) == "normal"
    assert calls == [
        (123, process_qos.PROCESS_MODE_BACKGROUND_BEGIN),
        (123, process_qos.BELOW_NORMAL_PRIORITY_CLASS),
        (123, process_qos.PROCESS_MODE_BACKGROUND_END),
        (123, process_qos.NORMAL_PRIORITY_CLASS),
    ]


def test_processing_mode_is_noop_off_windows(monkeypatch):
    monkeypatch.setattr(process_qos.sys, "platform", "linux")

    assert process_qos.set_processing_mode(background=True) == "unsupported"

def test_trim_working_set_uses_current_process_on_windows(monkeypatch):
    calls = []
    kernel32 = type(
        "Kernel32",
        (),
        {"GetCurrentProcess": _FakeFunction(lambda: 123)},
    )()
    psapi = type(
        "Psapi",
        (),
        {"EmptyWorkingSet": _FakeFunction(lambda process: calls.append(process) or True)},
    )()

    monkeypatch.setattr(process_qos.sys, "platform", "win32")
    monkeypatch.setattr(
        process_qos.ctypes,
        "WinDLL",
        lambda name, **_kwargs: kernel32 if name == "kernel32" else psapi,
        raising=False,
    )

    assert process_qos.trim_working_set() is True
    assert calls == [123]


def test_trim_working_set_is_noop_off_windows(monkeypatch):
    monkeypatch.setattr(process_qos.sys, "platform", "linux")

    assert process_qos.trim_working_set() is False

