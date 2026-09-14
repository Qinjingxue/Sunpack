from pathlib import Path

from sunpack.platform.windows.toast_host import _check_hresult, _load_library, self_test_toast


ROOT = Path(__file__).resolve().parents[2]


def test_toast_self_test_wrapper_checks_native_hresult(monkeypatch):
    calls = []

    class Library:
        def sunpack_toast_self_test(self):
            calls.append(True)
            return 0

    monkeypatch.setattr("sunpack.platform.windows.toast_host._load_library", lambda: Library())

    self_test_toast()

    assert calls == [True]


def test_built_toast_dll_self_test():
    # Executes real WinRT apartment, XML and payload validation in this process.
    library = _load_library()
    _check_hresult(library.sunpack_toast_self_test())


def test_native_context_releases_presenter_and_activation_before_apartment():
    source = (ROOT / "native/toast_host/src/main.cpp").read_text(encoding="utf-8")
    context = source[source.index("struct ToastContext"):source.index("template <typename Work>")]
    assert context.index("WinrtApartmentScope apartment") < context.index("ActivationRegistration activation")
    assert context.index("ActivationRegistration activation") < context.index("std::unique_ptr<ToastPresenter>")
    assert source.index("winrt::clear_factory_cache();") < source.index("winrt::uninit_apartment();")
    assert "CreateNamedPipeW" not in source
    assert "wWinMain" not in source


def test_build_produces_library_and_only_packages_library():
    cmake = (ROOT / "native/toast_host/CMakeLists.txt").read_text(encoding="utf-8")
    assert "SHARED src/main.cpp" in cmake
    for filename in ("scripts/build_windows.ps1", "scripts/setup_windows_dev.ps1", "scripts/verify_windows_package_arch.ps1"):
        script = (ROOT / filename).read_text(encoding="utf-8")
        assert "sunpack_toast.dll" in script
        assert "sunpack_toast_host.exe" not in script
