from __future__ import annotations

import threading


_LOCK = threading.Lock()
_ACTIVE = False
_HOST = None


def set_server_runtime_active(active: bool) -> None:
    global _ACTIVE
    with _LOCK:
        _ACTIVE = bool(active)


def server_runtime_active() -> bool:
    with _LOCK:
        return _ACTIVE


def set_runtime_host(host) -> None:
    global _HOST
    with _LOCK:
        _HOST = host


def runtime_host():
    with _LOCK:
        return _HOST


def require_runtime_host():
    host = runtime_host()
    if host is None:
        raise RuntimeError("RuntimeHost is not active")
    return host
