from io import StringIO
from types import SimpleNamespace

import sunpack.cli.commands.doctor as doctor
from sunpack.cli.cli_context import CliContext
from sunpack.cli.cli_reporter import CliReporter


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
    monkeypatch.setattr(doctor, "get_7z_dll_path", lambda: str(tmp_path / "7z.dll"))
    monkeypatch.setattr(doctor, "get_sevenzip_bridge_worker_path", lambda: str(tmp_path / "worker.exe"))
    monkeypatch.setattr(doctor, "list_watch_roots", lambda: (tmp_path / "roots.txt", [str(missing)]))

    ctx, stdout, stderr = _context(tmp_path)
    code, result = doctor.handle(SimpleNamespace(), ctx)

    assert code == 0
    assert [check["status"] for check in result.items] == ["ok", "ok", "ok", "ok", "skip", "warn"]
    assert result.summary == {"checks": 6, "ok": 4, "warnings": 1, "failed": 0}
    assert "[WARN] Watch root" in stdout.getvalue()
    assert "directory not found" in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_doctor_returns_task_failed_when_a_check_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(
        doctor,
        "load_request_config_payload",
        lambda _cwd: (tmp_path / "sunpack_config.json", {"watch": {"toast_enabled": True}}),
    )
    monkeypatch.setattr(doctor, "validate_config_payload", lambda _payload: {"ok": True, "errors": []})
    monkeypatch.setattr(doctor, "_native_check", lambda: {"name": "native", "status": "fail", "detail": "load failed"})
    monkeypatch.setattr(doctor, "get_7z_dll_path", lambda: str(tmp_path / "7z.dll"))
    monkeypatch.setattr(doctor, "get_sevenzip_bridge_worker_path", lambda: str(tmp_path / "worker.exe"))
    monkeypatch.setattr(doctor, "_toast_check", lambda _config, _valid: {"name": "toast", "status": "ok"})
    monkeypatch.setattr(doctor, "list_watch_roots", lambda: (tmp_path / "roots.txt", []))

    ctx, _stdout, stderr = _context(tmp_path)
    code, result = doctor.handle(SimpleNamespace(), ctx)

    assert code == 1
    assert result.summary["failed"] == 1
    assert result.errors == ["load failed"]
    assert "[FAIL] Native module: load failed" in stderr.getvalue()
