from __future__ import annotations

from types import SimpleNamespace

import sunpack.core.passwords.internal.clipboard as clipboard_module


class _FakeFunction:
    def __init__(self, implementation):
        self._implementation = implementation
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self._implementation(*args)


def test_windows_clipboard_preserves_64_bit_handle_and_bounds_read(monkeypatch):
    handle = 0x1234567887654321
    pointer = 0x1234567812345678
    wchar_size = clipboard_module.ctypes.sizeof(clipboard_module.ctypes.c_wchar)
    calls = []

    get_clipboard_data = _FakeFunction(lambda _format: handle)
    global_size = _FakeFunction(lambda received: calls.append(("size", received)) or 14 * wchar_size)
    global_lock = _FakeFunction(lambda received: calls.append(("lock", received)) or pointer)
    global_unlock = _FakeFunction(lambda received: calls.append(("unlock", received)) or True)
    close_clipboard = _FakeFunction(lambda: calls.append(("close",)) or True)
    fake_windll = SimpleNamespace(
        user32=SimpleNamespace(
            IsClipboardFormatAvailable=_FakeFunction(lambda _format: True),
            OpenClipboard=_FakeFunction(lambda _owner: True),
            GetClipboardData=get_clipboard_data,
            CloseClipboard=close_clipboard,
        ),
        kernel32=SimpleNamespace(
            GlobalSize=global_size,
            GlobalLock=global_lock,
            GlobalUnlock=global_unlock,
        ),
    )
    monkeypatch.setattr(clipboard_module.ctypes, "windll", fake_windll, raising=False)
    monkeypatch.setattr(
        clipboard_module.ctypes,
        "wstring_at",
        lambda received_pointer, count: calls.append(("read", received_pointer, count)) or "clip-secret\0xx",
    )

    result = clipboard_module._read_windows_unicode_clipboard(max_chars=100)

    assert result == "clip-secret"
    assert get_clipboard_data.restype is clipboard_module.wintypes.HANDLE
    assert calls == [
        ("size", handle),
        ("lock", handle),
        ("read", pointer, 14),
        ("unlock", handle),
        ("close",),
    ]


def test_windows_clipboard_rejects_allocation_over_limit(monkeypatch):
    wchar_size = clipboard_module.ctypes.sizeof(clipboard_module.ctypes.c_wchar)
    global_lock = _FakeFunction(lambda _handle: 1)
    fake_windll = SimpleNamespace(
        user32=SimpleNamespace(
            IsClipboardFormatAvailable=_FakeFunction(lambda _format: True),
            OpenClipboard=_FakeFunction(lambda _owner: True),
            GetClipboardData=_FakeFunction(lambda _format: 123),
            CloseClipboard=_FakeFunction(lambda: True),
        ),
        kernel32=SimpleNamespace(
            GlobalSize=_FakeFunction(lambda _handle: 12 * wchar_size),
            GlobalLock=global_lock,
            GlobalUnlock=_FakeFunction(lambda _handle: True),
        ),
    )
    monkeypatch.setattr(clipboard_module.ctypes, "windll", fake_windll, raising=False)

    assert clipboard_module._read_windows_unicode_clipboard(max_chars=10) == ""
    assert global_lock.argtypes == [clipboard_module.wintypes.HANDLE]


def test_read_clipboard_passwords_single_line_mode_rejects_internal_line_breaks(monkeypatch):
    cases = [
        ("password", ["password"]),
        ("password\r\n", ["password"]),
        ("a\nb", []),
        ("a\r\nb", []),
        ("a\n\na", []),
    ]

    for text, expected in cases:
        monkeypatch.setattr(
            clipboard_module,
            "_read_windows_unicode_clipboard",
            lambda *, max_chars, text=text: text,
        )
        assert clipboard_module.read_clipboard_passwords(single_line=True) == expected


def test_read_clipboard_passwords_keeps_multiline_default_behavior(monkeypatch):
    monkeypatch.setattr(
        clipboard_module,
        "_read_windows_unicode_clipboard",
        lambda *, max_chars: "a\nb",
    )

    assert clipboard_module.read_clipboard_passwords() == ["a", "b"]


def test_read_clipboard_passwords_preserves_hash_prefix_and_surrounding_spaces(monkeypatch):
    monkeypatch.setattr(
        clipboard_module,
        "_read_windows_unicode_clipboard",
        lambda *, max_chars: "#secret\n password \n   ",
    )

    assert clipboard_module.read_clipboard_passwords() == ["#secret", " password ", "   "]
