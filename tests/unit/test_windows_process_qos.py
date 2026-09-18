from __future__ import annotations

import pytest

import sunpack.platform.windows.process_qos as process_qos


class _FakeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


def _kernel32(calls, accepted=None):
    accepted = accepted or {
        process_qos.NORMAL_PRIORITY_CLASS,
        process_qos.HIGH_PRIORITY_CLASS,
        process_qos.PROCESS_MODE_BACKGROUND_BEGIN,
        process_qos.PROCESS_MODE_BACKGROUND_END,
        process_qos.BELOW_NORMAL_PRIORITY_CLASS,
    }
    return type(
        "Kernel32",
        (),
        {
            "GetCurrentProcess": _FakeFunction(lambda: 123),
            "SetPriorityClass": _FakeFunction(
                lambda process, priority: calls.append((process, priority)) or priority in accepted
            ),
        },
    )()


def test_processing_mode_supports_fixed_background_normal_and_high(monkeypatch):
    calls = []
    monkeypatch.setattr(process_qos.sys, "platform", "win32")
    monkeypatch.setattr(
        process_qos.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: _kernel32(calls),
        raising=False,
    )
    monkeypatch.setattr(process_qos, "_MODE", "normal")

    assert process_qos.set_processing_mode(mode="high") == "high"
    assert process_qos.set_processing_mode(mode="high") == "high"
    assert process_qos.set_processing_mode(mode="normal") == "normal"
    assert process_qos.set_processing_mode(mode="background") == "background"
    assert process_qos.set_processing_mode(mode="high") == "high"

    assert calls == [
        (123, process_qos.HIGH_PRIORITY_CLASS),
        (123, process_qos.NORMAL_PRIORITY_CLASS),
        (123, process_qos.PROCESS_MODE_BACKGROUND_BEGIN),
        (123, process_qos.PROCESS_MODE_BACKGROUND_END),
        (123, process_qos.HIGH_PRIORITY_CLASS),
    ]


def test_high_to_background_returns_to_normal_before_background_mode(monkeypatch):
    calls = []
    monkeypatch.setattr(process_qos.sys, "platform", "win32")
    monkeypatch.setattr(
        process_qos.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: _kernel32(calls),
        raising=False,
    )
    monkeypatch.setattr(process_qos, "_MODE", "high")

    assert process_qos.set_processing_mode(mode="background") == "background"
    assert calls == [
        (123, process_qos.NORMAL_PRIORITY_CLASS),
        (123, process_qos.PROCESS_MODE_BACKGROUND_BEGIN),
    ]


def test_background_mode_falls_back_to_below_normal(monkeypatch):
    calls = []
    monkeypatch.setattr(process_qos.sys, "platform", "win32")
    monkeypatch.setattr(
        process_qos.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: _kernel32(
            calls,
            accepted={
                process_qos.BELOW_NORMAL_PRIORITY_CLASS,
                process_qos.NORMAL_PRIORITY_CLASS,
            },
        ),
        raising=False,
    )
    monkeypatch.setattr(process_qos, "_MODE", "normal")

    assert process_qos.set_processing_mode(mode="background") == "below_normal"
    assert process_qos.set_processing_mode(mode="normal") == "normal"
    assert calls == [
        (123, process_qos.PROCESS_MODE_BACKGROUND_BEGIN),
        (123, process_qos.BELOW_NORMAL_PRIORITY_CLASS),
        (123, process_qos.PROCESS_MODE_BACKGROUND_END),
        (123, process_qos.NORMAL_PRIORITY_CLASS),
    ]


def test_processing_mode_rejects_unknown_mode():
    with pytest.raises(ValueError, match="unsupported process mode"):
        process_qos.set_processing_mode(mode="realtime")


def test_processing_mode_is_noop_off_windows(monkeypatch):
    monkeypatch.setattr(process_qos.sys, "platform", "linux")

    assert process_qos.set_processing_mode(mode="high") == "unsupported"
