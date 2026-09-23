import json
import subprocess
from copy import deepcopy
from typing import Any

from sunpack_native import NativeWorkerManifest, worker_manifest_from_rows


_STDIO_TAIL_LINES = 40
_STDIO_TAIL_CHARS = 4000


def attach_worker_diagnostics(
    completed: subprocess.CompletedProcess,
    *,
    request_payload: dict[str, Any] | None = None,
    process_failure: dict[str, Any] | None = None,
    result_payload: dict[str, Any] | None = None,
    progress_events: list[dict[str, Any]] | None = None,
) -> subprocess.CompletedProcess:
    completed.worker_diagnostics = build_worker_diagnostics(
        stdout=str(completed.stdout or ""),
        stderr=str(completed.stderr or ""),
        returncode=completed.returncode,
        args=completed.args,
        request_payload=request_payload,
        process_failure=process_failure,
        result_payload=result_payload,
        progress_events=progress_events,
    )
    return completed


def build_worker_diagnostics(
    *,
    stdout: str,
    stderr: str,
    returncode: int | None,
    args: Any = None,
    request_payload: dict[str, Any] | None = None,
    process_failure: dict[str, Any] | None = None,
    result_payload: dict[str, Any] | None = None,
    progress_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if isinstance(result_payload, dict):
        result = result_payload
        _expand_manifest(result)
        parsed_progress_events = list(progress_events or [])
    else:
        events = _json_events(stdout)
        result = next((event for event in reversed(events) if event.get("type") == "result"), {})
        parsed_progress_events = [event for event in events if event.get("type") == "progress"]
    diagnostics: dict[str, Any] = {
        "source": "sevenzip_worker",
        "returncode": returncode,
        "result": result,
        "progress_events": parsed_progress_events,
        "last_progress_event": parsed_progress_events[-1] if parsed_progress_events else {},
        "process": {
            "args": list(args) if isinstance(args, (list, tuple)) else args,
            "stderr_tail": _tail_lines(stderr),
            "stdout_tail": _tail_lines(stdout),
        },
        "repro": {
            "args": list(args) if isinstance(args, (list, tuple)) else args,
            "request": _redact_request(request_payload),
        },
    }
    failure = process_failure or _infer_process_failure(returncode, result, stderr)
    if failure:
        diagnostics["process_failure"] = failure
        diagnostics.setdefault("failure_stage", failure.get("failure_stage", "worker_process"))
        diagnostics.setdefault("failure_kind", failure.get("failure_kind", "process"))
    elif result:
        if result.get("failure_stage"):
            diagnostics["failure_stage"] = result.get("failure_stage")
        if result.get("failure_kind"):
            diagnostics["failure_kind"] = result.get("failure_kind")
    return diagnostics


def worker_result_payload(completed_or_text: Any) -> dict[str, Any]:
    diagnostics = getattr(completed_or_text, "worker_diagnostics", None)
    if isinstance(diagnostics, dict):
        result = diagnostics.get("result")
        if isinstance(result, dict) and result:
            return result
    text = completed_or_text if isinstance(completed_or_text, str) else ""
    if not text and completed_or_text is not None:
        text = f"{getattr(completed_or_text, 'stdout', '')}\n{getattr(completed_or_text, 'stderr', '')}"
    for event in reversed(_json_events(str(text or ""))):
        if event.get("type") == "result":
            return event
    return {}


def compact_success_worker_diagnostics(diagnostics: dict[str, Any]) -> None:
    """Drop transient native worker rows after the output inventory owns them."""
    result = diagnostics.get("result") if isinstance(diagnostics, dict) else None
    if not isinstance(result, dict) or result.get("status") != "ok":
        return
    manifest = result.get("verified_manifest")
    if not isinstance(manifest, dict) or not manifest.get("validated"):
        return
    inventory = manifest.get("inventory")
    if not isinstance(inventory, dict) or not inventory.get("complete"):
        return
    manifest.pop("native_rows", None)
    native = result.get("diagnostics")
    if not isinstance(native, dict):
        return
    output_trace = native.get("output_trace")
    if isinstance(output_trace, dict):
        output_trace.pop("items", None)


def _json_events(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            _expand_manifest(payload)
            events.append(payload)
    return events


def _expand_manifest(payload: dict[str, Any]) -> None:
    manifest = payload.get("verified_manifest")
    if not isinstance(manifest, dict) or int(manifest.get("version", 0) or 0) != 3:
        return
    rows = manifest.get("rows")
    if not isinstance(rows, list):
        rows = []
    inventory = manifest.get("inventory")
    if isinstance(inventory, list) and len(inventory) == 5:
        inventory = {
            "complete": bool(inventory[0]), "file_count": int(inventory[1]),
            "dir_count": int(inventory[2]), "total_size": int(inventory[3]),
            "identity_paths": bool(inventory[4]),
        }
        manifest["inventory"] = inventory
    if not isinstance(inventory, dict):
        inventory = {}
    if rows:
        manifest["native_rows"] = worker_manifest_from_rows(
            rows,
            bool(inventory.get("complete")),
            int(inventory.get("file_count", len(rows)) or 0),
            int(inventory.get("dir_count", 0) or 0),
            int(inventory.get("total_size", 0) or 0),
            bool(inventory.get("identity_paths")),
        )
    manifest.pop("rows", None)


def native_worker_manifest(result: dict[str, Any]) -> NativeWorkerManifest | None:
    manifest = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    value = manifest.get("native_rows")
    return value if isinstance(value, NativeWorkerManifest) else None


def worker_manifest_files(result: dict[str, Any]) -> list[dict[str, Any]]:
    native = native_worker_manifest(result)
    return [dict(item) for item in native.materialize_files()] if native is not None else []


def _tail_lines(text: str, limit: int = _STDIO_TAIL_LINES) -> list[str]:
    # A successful worker result is a single multi-megabyte JSON line.  The
    # structured payload is retained separately, so diagnostics only need a
    # bounded textual tail for malformed output and process failures.
    lines = (text or "")[-_STDIO_TAIL_CHARS:].splitlines()
    return lines[-limit:]


def _infer_process_failure(returncode: int | None, result: dict[str, Any], stderr: str) -> dict[str, Any]:
    if result:
        return {}
    message = (stderr or "").strip()
    if returncode == -100:
        return {
            "failure_stage": "worker_start",
            "failure_kind": "process_start",
            "message": message or "sevenzip_worker failed to start",
        }
    if returncode == -101:
        return {
            "failure_stage": "worker_timeout",
            "failure_kind": "process_timeout",
            "message": message or "sevenzip_worker timed out",
        }
    if returncode == -102:
        return {
            "failure_stage": "worker_no_progress",
            "failure_kind": "process_stall",
            "message": message or "sevenzip_worker made no observable progress",
        }
    if returncode is not None and returncode < 0:
        return {
            "failure_stage": "worker_terminated",
            "failure_kind": "process_signal",
            "message": message or f"sevenzip_worker terminated with code {returncode}",
        }
    if returncode not in (None, 0):
        return {
            "failure_stage": "worker_exit",
            "failure_kind": "process_exit",
            "message": message or f"sevenzip_worker exited with code {returncode}",
        }
    return {}


def _redact_request(request_payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(request_payload, dict):
        return {}
    payload = deepcopy(request_payload)
    if "password" in payload:
        password = payload.get("password")
        payload["password_present"] = bool(password)
        payload["password_length"] = len(str(password)) if password is not None else 0
        payload["password"] = "<redacted>" if password else ""
    if "passwords" in payload:
        passwords = payload.get("passwords")
        payload["password_count"] = len(passwords) if isinstance(passwords, list) else 0
        payload["passwords"] = "<redacted>"
    return payload
