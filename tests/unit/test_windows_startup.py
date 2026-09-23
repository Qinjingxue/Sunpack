import sunpack.runtime.watch.startup as startup_module


def test_startup_command_launches_packaged_runtime_with_runtime_identity(tmp_path, monkeypatch):
    executable = tmp_path / "SunPack Folder" / "sunpack-runtime.exe"
    runtime_id = "--_sunpack-runtime-id=v2-0123456789abcdef"
    monkeypatch.setattr(startup_module, "current_process_executable", lambda: executable)
    monkeypatch.setattr(startup_module, "runtime_id_available", lambda: True)
    monkeypatch.setattr(startup_module, "runtime_id_argument", lambda: runtime_id)

    def fail_watch_launch_argv(**_kwargs):
        raise AssertionError("source launcher should not be used")

    monkeypatch.setattr(
        startup_module,
        "watch_launch_argv",
        fail_watch_launch_argv,
    )

    command = startup_module.startup_command()

    assert command == f'"{executable}" {runtime_id} watch start'


def test_startup_command_uses_launcher_outside_packaged_runtime(tmp_path, monkeypatch):
    executable = tmp_path / "python.exe"
    expected = [str(executable), "-m", "sunpack", "watch", "start"]
    monkeypatch.setattr(startup_module, "current_process_executable", lambda: executable)
    monkeypatch.setattr(startup_module, "runtime_id_available", lambda: True)
    monkeypatch.setattr(
        startup_module,
        "watch_launch_argv",
        lambda **kwargs: expected if kwargs == {"prefer_windowed_python": True} else [],
    )

    command = startup_module.startup_command()

    assert command == startup_module.subprocess.list2cmdline(expected)
