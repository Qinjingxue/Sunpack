from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any

from sunpack_native import NativeWorkerResultAccumulator, parse_worker_transport_event

from sunpack.core.support.resources import get_sevenzip_bridge_worker_path


@dataclass(frozen=True)
class SevenZipDryRunResult:
    ok: bool
    returncode: int
    result: dict[str, Any] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    progress: list[dict[str, Any]] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    message: str = ""


def dry_run_archive(
    archive_path: str,
    *,
    format_hint: str = "",
    password: str = "",
    timeout: float = 30.0,
) -> SevenZipDryRunResult:
    worker_path = get_sevenzip_bridge_worker_path()
    job_id = f"dry-run-{uuid.uuid4().hex}"
    payload = {
        "job_id": job_id,
        "archive_path": str(archive_path),
        "output_dir": "",
        "password": str(password or ""),
        "format_hint": str(format_hint or ""),
        "dry_run": True,
    }
    try:
        completed = subprocess.run(
            [worker_path],
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=max(1.0, float(timeout or 30.0)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _coerce_text(exc.stdout)
        stderr = _coerce_text(exc.stderr)
        return SevenZipDryRunResult(
            ok=False,
            returncode=-101,
            result={
                "type": "result",
                "job_id": job_id,
                "status": "failed",
                "failure_stage": "worker_timeout",
                "failure_kind": "process_timeout",
            },
            stdout=stdout,
            stderr=stderr,
            message="sevenzip_worker dry-run timed out",
        )
    except OSError as exc:
        return SevenZipDryRunResult(
            ok=False,
            returncode=-100,
            result={
                "type": "result",
                "job_id": job_id,
                "status": "failed",
                "failure_stage": "worker_start",
                "failure_kind": "process_start",
            },
            stderr=str(exc),
            message=f"sevenzip_worker dry-run failed to start: {exc}",
        )

    protocol_error = ""
    try:
        events = _parse_worker_json_lines(completed.stdout, job_id)
    except (ValueError, TypeError) as exc:
        events = []
        protocol_error = f"sevenzip_worker dry-run protocol failed: {exc}"
    result = next((item for item in reversed(events) if item.get("type") == "result"), {})
    progress = [item for item in events if item.get("type") == "progress"]
    if not result:
        result = {
            "type": "result",
            "job_id": job_id,
            "status": "failed",
            "failure_stage": "worker_protocol",
            "failure_kind": "process_io",
            "message": protocol_error or "sevenzip_worker dry-run did not emit a result",
        }
    diagnostics = result.get("diagnostics") if isinstance(result.get("diagnostics"), dict) else {}
    ok = completed.returncode == 0 and result.get("status") == "ok"
    message = str(result.get("message") or completed.stderr or ("worker dry-run ok" if ok else "worker dry-run failed"))
    return SevenZipDryRunResult(
        ok=ok,
        returncode=int(completed.returncode),
        result=dict(result),
        diagnostics=dict(diagnostics),
        progress=progress,
        stdout=completed.stdout,
        stderr=completed.stderr,
        message=message,
    )


def _parse_worker_json_lines(stdout: str, job_id: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    accumulator = NativeWorkerResultAccumulator(job_id)
    for line in str(stdout or "").splitlines():
        if not line.strip():
            continue
        parsed = parse_worker_transport_event(line)
        if parsed["type"] == "protocol_error":
            raise ValueError(parsed["message"])
        if not accumulator.accept(parsed):
            events.append(parsed)
    return events


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
