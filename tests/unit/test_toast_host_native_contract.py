from sunpack.core.platform.windows.toast_host import _check_hresult, _load_library, self_test_toast


def test_toast_self_test_wrapper_checks_native_hresult(monkeypatch):
    calls = []

    class Library:
        def sunpack_toast_self_test(self):
            calls.append(True)
            return 0

    monkeypatch.setattr("sunpack.core.platform.windows.toast_host._load_library", lambda: Library())

    self_test_toast()

    assert calls == [True]


def test_built_toast_dll_self_test():
    # Executes real WinRT apartment, XML and payload validation in this process.
    library = _load_library()
    _check_hresult(library.sunpack_toast_self_test())
