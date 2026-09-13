from __future__ import annotations

import hashlib
import os
import platform
import sys
import threading
import traceback
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


_MAX_SNAPSHOT_ENTRIES = 2048
_FACT_KEYS = (
    "candidate.",
    "file.",
    "relation.",
    "archive.input",
    "archive.state",
    "archive.source",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def jsonable(value: Any, *, _depth: int = 0) -> Any:
    """Convert diagnostic values to bounded JSON-compatible data.

    Diagnostics must never make a failing test fail again.  In particular,
    native result objects can contain Paths, enums, dataclasses and byte
    buffers, none of which should be handed directly to json.dumps.
    """
    if _depth > 12:
        return "<diagnostic-depth-limit>"
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {
            str(key): jsonable(item, _depth=_depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(item, _depth=_depth + 1) for item in value]
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return jsonable(to_dict(), _depth=_depth + 1)
        except Exception as exc:  # pragma: no cover - diagnostic fallback
            return {"repr": repr(value), "to_dict_error": repr(exc)}
    if is_dataclass(value):
        return {
            item.name: jsonable(getattr(value, item.name), _depth=_depth + 1)
            for item in fields(value)
        }
    return repr(value)


def password_summary(passwords: Iterable[str] | None) -> dict[str, Any]:
    values = [str(value) for value in (passwords or [])]
    joined = "\0".join(values).encode("utf-8")
    return {
        "count": len(values),
        "sha256": hashlib.sha256(joined).hexdigest(),
        "lengths": [len(value) for value in values],
    }


def snapshot_path(
    path: Path | str,
    *,
    recursive: bool = True,
    max_entries: int = _MAX_SNAPSHOT_ENTRIES,
) -> dict[str, Any]:
    """Capture filesystem state without embedding file contents in a report."""
    root = Path(path)
    result: dict[str, Any] = {
        "path": str(root),
        "exists": root.exists() or root.is_symlink(),
        "entries": [],
        "truncated": False,
    }
    if not result["exists"]:
        return result

    try:
        root_stat = root.stat()
        result.update({
            "kind": "directory" if root.is_dir() else "file",
            "size": root_stat.st_size,
            "mtime_ns": root_stat.st_mtime_ns,
        })
    except OSError as exc:
        result["stat_error"] = repr(exc)
        return result

    if not root.is_dir():
        try:
            result["sha256"] = _sha256(root)
        except OSError as exc:
            result["read_error"] = repr(exc)
        return result

    candidates = sorted(root.rglob("*"), key=lambda item: str(item).casefold()) if recursive else []
    for child in candidates:
        if len(result["entries"]) >= max_entries:
            result["truncated"] = True
            break
        try:
            stat = child.stat()
            item: dict[str, Any] = {
                "relative_path": child.relative_to(root).as_posix(),
                "kind": "directory" if child.is_dir() else "file",
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
            }
            if child.is_file():
                item["sha256"] = _sha256(child)
        except OSError as exc:
            item = {
                "relative_path": str(child.relative_to(root)),
                "stat_or_read_error": repr(exc),
            }
        result["entries"].append(item)
    result["entry_count"] = len(result["entries"])
    return result


def environment_snapshot() -> dict[str, Any]:
    tools: dict[str, Any] = {}
    try:
        from tests.helpers.tool_config import get_test_tools

        for name, value in get_test_tools().items():
            if value is None:
                tools[name] = {"configured": False}
            else:
                tool_path = Path(value)
                tools[name] = {
                    "configured": True,
                    **snapshot_path(tool_path, recursive=False),
                }
    except Exception as exc:  # pragma: no cover - diagnostic fallback
        tools["lookup_error"] = repr(exc)
    return {
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "thread_count": threading.active_count(),
        "tools": tools,
    }


def record_exception(info: dict[str, Any], phase: str, exc: BaseException) -> None:
    info.setdefault("diagnostics", {}).setdefault("exceptions", []).append({
        "phase": phase,
        "type": type(exc).__name__,
        "message": str(exc),
        "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
    })


def case_snapshot(case: Any) -> dict[str, Any]:
    metadata = getattr(case, "metadata", {})
    password = getattr(case, "password", None)
    return {
        "case_id": getattr(case, "case_id", ""),
        "archive_format": getattr(case, "archive_format", ""),
        "archive_dir": str(getattr(case, "archive_dir", "")),
        "entry_path": str(getattr(case, "entry_path", "")),
        "marker_name": getattr(case, "marker_name", ""),
        "marker_text_length": len(str(getattr(case, "marker_text", ""))),
        "password_present": password is not None,
        "password_sha256": hashlib.sha256(str(password).encode("utf-8")).hexdigest()
        if password is not None
        else None,
        "split": bool(getattr(case, "split", False)),
        "sfx": bool(getattr(case, "sfx", False)),
        "carrier": getattr(case, "carrier", None),
        "disguise_ext": getattr(case, "disguise_ext", None),
        "corruption": getattr(case, "corruption", None),
        "split_issue": getattr(case, "split_issue", None),
        "metadata": jsonable(metadata),
    }


def task_snapshot(task: Any) -> dict[str, Any]:
    fact_bag = getattr(task, "fact_bag", None)
    raw_facts = fact_bag.to_dict() if fact_bag is not None else {}
    selected_facts = {
        key: value
        for key, value in raw_facts.items()
        if key.startswith(_FACT_KEYS)
    }
    split_info = getattr(task, "split_info", None)
    return {
        "main_path": getattr(task, "main_path", ""),
        "all_parts": list(getattr(task, "all_parts", []) or []),
        "cleanup_parts": list(getattr(task, "cleanup_parts", []) or []),
        "carrier_path": getattr(task, "carrier_path", ""),
        "logical_name": getattr(task, "logical_name", ""),
        "key": getattr(task, "key", ""),
        "score": getattr(task, "score", None),
        "decision": getattr(task, "decision", ""),
        "detected_ext": getattr(task, "detected_ext", ""),
        "split_info": jsonable(split_info),
        "facts": jsonable(selected_facts),
    }


def scan_tasks_snapshot(directory: Path | str, *, passwords: list[str] | None = None) -> dict[str, Any]:
    from sunpack.coordinator.task_provider import ArchiveTaskProvider
    from tests.real.plan1_real_archives.plan1_support import plan1_config

    provider = ArchiveTaskProvider(plan1_config(passwords=passwords))
    tasks = provider.scan_targets([str(directory)])
    return {
        "directory": str(directory),
        "task_count": len(tasks),
        "tasks": [task_snapshot(task) for task in tasks],
    }


def failure_snapshot(failure: Any) -> Any:
    return jsonable(failure.to_dict() if hasattr(failure, "to_dict") else failure)


def summary_snapshot(summary: Any) -> dict[str, Any] | None:
    if summary is None:
        return None
    target_results = []
    for result in list(getattr(summary, "target_results", []) or []):
        target_results.append({
            "input_path": getattr(result, "input_path", ""),
            "outcome_kind": jsonable(getattr(result, "outcome_kind", "")),
            "output_dir": getattr(result, "output_dir", ""),
            "verification": jsonable(getattr(result, "verification", {})),
            "error": getattr(result, "error", ""),
            "failure": failure_snapshot(getattr(result, "failure", None)),
        })
    return {
        "success_count": getattr(summary, "success_count", None),
        "partial_success_count": getattr(summary, "partial_success_count", None),
        "failed_tasks": [str(item) for item in (getattr(summary, "failed_tasks", []) or [])],
        "processed_keys": [str(item) for item in (getattr(summary, "processed_keys", []) or [])],
        "failures": [failure_snapshot(item) for item in (getattr(summary, "failures", []) or [])],
        "recovered_outputs": jsonable(getattr(summary, "recovered_outputs", [])),
        "policy_skips": jsonable(getattr(summary, "policy_skips", [])),
        "target_results": target_results,
    }


def pipeline_snapshot(
    info: dict[str, Any],
    *,
    phase: str,
    summary: Any = None,
    roots: Iterable[Path | str] = (),
) -> None:
    diagnostics = info.setdefault("diagnostics", {})
    diagnostics.setdefault("pipeline_snapshots", []).append({
        "phase": phase,
        "summary": summary_snapshot(summary),
        "roots": [snapshot_path(root) for root in roots],
    })


def marker_locations(root: Path | str, marker_name: str, marker_text: str) -> list[dict[str, Any]]:
    root_path = Path(root)
    needle = str(marker_text).encode("utf-8")
    matches: list[dict[str, Any]] = []
    if not root_path.exists():
        return matches
    for path in sorted(root_path.rglob("*"), key=lambda item: str(item).casefold()):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if needle not in data:
            continue
        matches.append({
            "path": str(path),
            "relative_path": str(path.relative_to(root_path)),
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(data).hexdigest(),
            "marker_name": marker_name,
        })
    return matches

