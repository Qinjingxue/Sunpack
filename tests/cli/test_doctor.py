from io import StringIO
from types import SimpleNamespace

import sunpack.runtime.cli.commands.doctor as doctor
from sunpack.runtime.cli.cli_context import CliContext
from sunpack.runtime.cli.cli_reporter import CliReporter


def _context(tmp_path):
    stdout = StringIO()
    stderr = StringIO()
    return (
        CliContext(
            language="en",
            cwd=str(tmp_path),
            stdout=stdout,
            stderr=stderr,
            reporter=CliReporter(stdout=stdout, stderr=stderr),
        ),
        stdout,
        stderr,
    )


def test_doctor_reports_checks_and_missing_watch_roots_as_warnings(tmp_path, monkeypatch):
    missing = tmp_path / "offline-drive"
    monkeypatch.setattr(
        doctor,
        "load_request_config_payload",
        lambda _cwd: (tmp_path / "sunpack_config.json", {"watch": {"toast_enabled": False}}),
    )
    monkeypatch.setattr(doctor, "validate_config_payload", lambda _payload: {"ok": True, "errors": []})
    monkeypatch.setattr(doctor, "_native_check", lambda: {"name": "native", "status": "ok"})
    monkeypatch.setattr(doctor, "get_sevenzip_bridge_worker_path", lambda: str(tmp_path / "worker.exe"))
    monkeypatch.setattr(doctor, "list_watch_roots", lambda: (tmp_path / "roots.txt", [str(missing)]))
    monkeypatch.setattr(doctor, "is_packaged_process", lambda: False)

    ctx, stdout, stderr = _context(tmp_path)
    code, result = doctor.handle(SimpleNamespace(), ctx)

    assert code == 0
    # The 7z.dll resource check is gone: the 7-Zip backend is compiled into
    # the worker, so there is no separate backend DLL left on disk to verify.
    assert [check["status"] for check in result.items] == ["ok", "ok", "ok", "skip", "warn"]
    assert result.summary == {"checks": 5, "ok": 3, "warnings": 1, "skipped": 1, "failed": 0}
    assert "[WARN] Watch root" in stdout.getvalue()
    assert f"[WARN] Watch root {missing}: directory not found" in stdout.getvalue()
    assert f": {missing} - directory not found" not in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_doctor_returns_task_failed_when_a_check_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(
        doctor,
        "load_request_config_payload",
        lambda _cwd: (tmp_path / "sunpack_config.json", {"watch": {"toast_enabled": True}}),
    )
    monkeypatch.setattr(doctor, "validate_config_payload", lambda _payload: {"ok": True, "errors": []})
    monkeypatch.setattr(doctor, "_native_check", lambda: {"name": "native", "status": "fail", "detail": "load failed"})
    monkeypatch.setattr(doctor, "get_sevenzip_bridge_worker_path", lambda: str(tmp_path / "worker.exe"))
    monkeypatch.setattr(doctor, "_toast_check", lambda _config, _valid: {"name": "toast", "status": "ok"})
    monkeypatch.setattr(doctor, "list_watch_roots", lambda: (tmp_path / "roots.txt", []))
    monkeypatch.setattr(doctor, "is_packaged_process", lambda: False)

    ctx, _stdout, stderr = _context(tmp_path)
    code, result = doctor.handle(SimpleNamespace(), ctx)

    assert code == 1
    assert result.summary["failed"] == 1
    assert result.errors == ["load failed"]
    assert "[FAIL] Native module: load failed" in stderr.getvalue()


def test_installation_checks_accept_machine_toast_com_registration(tmp_path, monkeypatch):
    install_dir = tmp_path / "SunPack"
    runtime = install_dir / "sunpack-runtime.exe"
    launcher = install_dir / "sunpack.exe"
    broker = install_dir / "service" / "sunpack-watch-broker.exe"
    data_dir = tmp_path / "ProgramData" / "SunPack"
    data_dir.mkdir(parents=True)

    values = {
        (doctor.SERVICE_REGISTRY_KEY, "ImagePath"): f'"{broker}"',
        (doctor.TOAST_LOCAL_SERVER_KEY, ""): f'"{runtime}" --toast-activated',
        (doctor.SUNPACK_REGISTRY_KEY, doctor.PATH_MARKER_NAME): 1,
        (doctor.ENVIRONMENT_REGISTRY_KEY, "Path"): f"C:\\Windows;{install_dir}",
    }
    for command_key in doctor.CONTEXT_COMMAND_KEYS:
        values[(command_key, "")] = f'"{launcher}" extract "%1"'

    monkeypatch.setattr(doctor, "program_data_dir", lambda: data_dir)
    monkeypatch.setattr(doctor, "current_process_executable", lambda: runtime)
    monkeypatch.setattr(doctor, "_read_hklm_value", lambda path, name="": values.get((path, name)))
    monkeypatch.setattr(doctor, "_hklm_key_exists", lambda path: path in doctor.CONTEXT_PARENT_KEYS)
    startup = f'"{runtime}" --_sunpack-runtime-id=v2-0123456789abcdef watch start'
    monkeypatch.setattr(doctor, "_startup_registration", lambda: (True, startup, startup))

    checks = doctor._installation_checks()

    assert [check["name"] for check in checks] == [
        "data_dir",
        "broker_service",
        "toast_registration",
        "machine_path",
        "context_menu",
        "startup",
    ]
    assert [check["status"] for check in checks] == ["ok"] * 6


def test_optional_machine_integrations_are_skipped_when_not_enabled(monkeypatch):
    monkeypatch.setattr(doctor, "_read_hklm_value", lambda _path, _name="": None)
    monkeypatch.setattr(doctor, "_hklm_key_exists", lambda _path: False)
    monkeypatch.setattr(doctor, "_startup_registration", lambda: (False, "", ""))

    assert doctor._machine_path_check()["status"] == "skip"
    assert doctor._context_menu_check()["status"] == "skip"
    assert doctor._startup_check()["status"] == "skip"


def test_machine_path_marker_requires_current_install_directory(tmp_path, monkeypatch):
    runtime = tmp_path / "SunPack" / "sunpack-runtime.exe"

    def read_value(path, name=""):
        if (path, name) == (doctor.SUNPACK_REGISTRY_KEY, doctor.PATH_MARKER_NAME):
            return 1
        if (path, name) == (doctor.ENVIRONMENT_REGISTRY_KEY, "Path"):
            return r"C:\Windows;C:\OtherTool"
        return None

    monkeypatch.setattr(doctor, "current_process_executable", lambda: runtime)
    monkeypatch.setattr(doctor, "_read_hklm_value", read_value)

    check = doctor._machine_path_check()

    assert check["status"] == "fail"
    assert "install directory is missing" in check["detail"]
