import sunpack.runtime.watch.launcher as launcher_module
import pytest


@pytest.mark.parametrize("installed", [False, True])
def test_runtime_finds_launcher_for_both_package_layouts(tmp_path, monkeypatch, installed):
    runtime = tmp_path / "sunpack-runtime.exe"
    cli_executable = (tmp_path / "bin" if installed else tmp_path) / "sunpack.exe"
    cli_executable.parent.mkdir(exist_ok=True)
    cli_executable.touch()
    monkeypatch.setattr(launcher_module, "current_process_executable", lambda: runtime)

    assert launcher_module.watch_launch_argv(initial_scan=True) == [
        str(cli_executable), "watch", "start", "--initial-scan",
    ]


def test_packaged_watch_launcher_uses_public_cli_command(tmp_path, monkeypatch):
    cli_executable = tmp_path / "sunpack.exe"
    cli_executable.write_bytes(b"")
    monkeypatch.setattr(launcher_module, "current_process_executable", lambda: cli_executable.resolve())

    assert launcher_module.watch_launch_argv(once=True, no_tray=True) == [
        str(cli_executable.resolve()),
        "watch",
        "start",
        "--once",
        "--no-tray",
    ]


def test_source_watch_launcher_uses_public_cli_module(tmp_path, monkeypatch):
    python = tmp_path / "python.exe"
    monkeypatch.setattr(launcher_module, "current_process_executable", lambda: python.resolve())
    monkeypatch.setattr(launcher_module, "packaged_runtime_executable", lambda *_args, **_kwargs: None)

    assert launcher_module.watch_launch_argv(once=True) == [
        str(python.resolve()),
        "-m",
        "sunpack",
        "watch",
        "start",
        "--once",
    ]


def test_source_startup_prefers_pythonw(tmp_path, monkeypatch):
    python = tmp_path / "python.exe"
    pythonw = tmp_path / "pythonw.exe"
    pythonw.write_bytes(b"")
    monkeypatch.setattr(launcher_module, "current_process_executable", lambda: python.resolve())
    monkeypatch.setattr(launcher_module, "packaged_runtime_executable", lambda *_args, **_kwargs: None)

    assert launcher_module.watch_launch_argv(prefer_windowed_python=True) == [
        str(pythonw.resolve()),
        "-m",
        "sunpack",
        "watch",
        "start",
    ]


def test_watch_launcher_forwards_initial_scan(monkeypatch):
    monkeypatch.setattr(launcher_module, "packaged_runtime_executable", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        launcher_module,
        "current_process_executable",
        lambda: launcher_module.Path(r"C:\Python310\python.exe"),
    )

    assert launcher_module.watch_launch_argv(initial_scan=True) == [
        r"C:\Python310\python.exe",
        "-m",
        "sunpack",
        "watch",
        "start",
        "--initial-scan",
    ]
