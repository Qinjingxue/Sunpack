from pathlib import Path

from sunpack.support import process_executable


def test_compiled_process_uses_invoked_binary_instead_of_nuitka_python_path(tmp_path, monkeypatch):
    runtime = tmp_path / "sunpack-runtime.exe"
    synthetic_python = tmp_path / "python.exe"
    monkeypatch.setattr(process_executable.sys, "frozen", True, raising=False)
    monkeypatch.setattr(process_executable.sys, "argv", [str(runtime)])
    monkeypatch.setattr(process_executable.sys, "executable", str(synthetic_python))

    assert process_executable.current_process_executable() == runtime.resolve()


def test_nuitka_compiled_process_is_packaged_without_sys_frozen(monkeypatch):
    monkeypatch.delattr(process_executable.sys, "frozen", raising=False)
    monkeypatch.setattr(process_executable, "__compiled__", object(), raising=False)

    assert process_executable.is_packaged_process() is True


def test_source_process_uses_interpreter(tmp_path, monkeypatch):
    interpreter = tmp_path / "python.exe"
    script = tmp_path / "sunpack.py"
    monkeypatch.delattr(process_executable.sys, "frozen", raising=False)
    monkeypatch.setattr(process_executable.sys, "argv", [str(script)])
    monkeypatch.setattr(process_executable.sys, "executable", str(interpreter))

    assert process_executable.current_process_executable() == Path(interpreter).resolve()
